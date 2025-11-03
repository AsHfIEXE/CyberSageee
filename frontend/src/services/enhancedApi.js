import { API_CONFIG } from '../utils/constants';
import { 
  ErrorFactory, 
  ErrorLogger, 
  TimeoutError 
} from '../utils/errors';
import { cacheManager } from '../utils/cache';
import { connectionMonitor } from '../utils/connection';

export class EnhancedApiService {
  constructor() {
    this.baseURL = API_CONFIG.BASE_URL;
    this.headers = {
      'Content-Type': 'application/json',
    };
    this.requestInterceptors = [];
    this.responseInterceptors = [];
    this.requestCount = 0;
    this.inflightRequests = new Map();
  }

  // Add request interceptor
  addRequestInterceptor(interceptor) {
    this.requestInterceptors.push(interceptor);
    return () => {
      const index = this.requestInterceptors.indexOf(interceptor);
      if (index > -1) {
        this.requestInterceptors.splice(index, 1);
      }
    };
  }

  // Add response interceptor
  addResponseInterceptor(interceptor) {
    this.responseInterceptors.push(interceptor);
    return () => {
      const index = this.responseInterceptors.indexOf(interceptor);
      if (index > -1) {
        this.responseInterceptors.splice(index, 1);
      }
    };
  }

  // Enhanced HTTP request with retry logic
  async request(endpoint, options = {}) {
    const requestId = this.generateRequestId();
    const startTime = Date.now();
    
    const config = {
      method: 'GET',
      timeout: API_CONFIG.TIMEOUT.DEFAULT,
      retry: API_CONFIG.RETRY_CONFIG.MAX_ATTEMPTS,
      cache: true,
      ...options
    };

    // Apply request interceptors
    for (const interceptor of this.requestInterceptors) {
      const result = await interceptor(config);
      if (result !== undefined) {
        Object.assign(config, result);
      }
    }

    // Check cache first if enabled
    if (config.method === 'GET' && config.cache && !config.bypassCache) {
      const cacheKey = this.generateCacheKey(endpoint, config.params);
      const cachedData = cacheManager.get(cacheKey);
      if (cachedData) {
        connectionMonitor.recordRequest(true, Date.now() - startTime);
        return cachedData;
      }
    }

    try {
      const result = await this.executeWithRetry(endpoint, config, requestId);
      
      // Apply response interceptors
      for (const interceptor of this.responseInterceptors) {
        const interceptResult = await interceptor(result);
        if (interceptResult !== undefined) {
          Object.assign(result, interceptResult);
        }
      }

      // Cache successful GET requests
      if (config.method === 'GET' && config.cache && !config.bypassCache) {
        const cacheKey = this.generateCacheKey(endpoint, config.params);
        cacheManager.set(cacheKey, result);
      }

      connectionMonitor.recordRequest(true, Date.now() - startTime);
      return result;
    } catch (error) {
      const apiError = ErrorFactory.createFromError(error);
      ErrorLogger.log(apiError, { endpoint, config, requestId });
      connectionMonitor.recordRequest(false, Date.now() - startTime);
      
      throw apiError;
    }
  }

  // Execute request with exponential backoff retry
  async executeWithRetry(endpoint, config, requestId) {
    let lastError;
    
    for (let attempt = 1; attempt <= config.retry; attempt++) {
      try {
        this.inflightRequests.set(requestId, { endpoint, config, attempt });
        
        const result = await this.executeRequest(endpoint, config);
        
        this.inflightRequests.delete(requestId);
        return result;
      } catch (error) {
        this.inflightRequests.delete(requestId);
        lastError = error;
        
        // Don't retry on client errors (4xx) except for 408, 429
        const errorStatus = error.status;
        const shouldRetry = 
          error.isRetryable() && 
          attempt < config.retry &&
          (!error.isClientError() || errorStatus === 408 || errorStatus === 429);

        if (!shouldRetry) {
          break;
        }

        // Calculate delay with exponential backoff and jitter
        const delay = this.calculateRetryDelay(attempt);
        
        if (attempt < config.retry) {
          await this.delay(delay);
        }
      }
    }

    throw lastError;
  }

  // Execute individual request
  async executeRequest(endpoint, config) {
    const url = `${this.baseURL}${endpoint}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.timeout);

    try {
      const fetchConfig = {
        method: config.method,
        headers: {
          ...this.headers,
          ...config.headers,
        },
        signal: controller.signal,
      };

      // Add body for appropriate methods
      if (config.body && ['POST', 'PUT', 'PATCH'].includes(config.method)) {
        if (typeof config.body === 'object') {
          fetchConfig.body = JSON.stringify(config.body);
        } else {
          fetchConfig.body = config.body;
        }
      }

      const response = await fetch(url, fetchConfig);
      clearTimeout(timeoutId);

      if (!response.ok) {
        const error = ErrorFactory.createFromResponse(response, null);
        throw error;
      }

      // Handle different response types
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        return await response.json();
      } else if (contentType && contentType.includes('text/')) {
        return await response.text();
      } else {
        return await response.arrayBuffer();
      }
    } catch (error) {
      clearTimeout(timeoutId);
      
      if (error.name === 'AbortError') {
        throw new TimeoutError(config.timeout);
      }
      
      throw error;
    }
  }

  // Calculate retry delay with exponential backoff and jitter
  calculateRetryDelay(attempt) {
    const { INITIAL_DELAY, MAX_DELAY, BACKOFF_MULTIPLIER, JITTER } = API_CONFIG.RETRY_CONFIG;
    
    const exponentialDelay = INITIAL_DELAY * Math.pow(BACKOFF_MULTIPLIER, attempt - 1);
    const jitter = exponentialDelay * JITTER * (Math.random() - 0.5) * 2;
    
    return Math.min(exponentialDelay + jitter, MAX_DELAY);
  }

  // Delay utility
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Generate cache key
  generateCacheKey(endpoint, params = {}) {
    const queryString = new URLSearchParams(params).toString();
    const paramString = queryString ? `?${queryString}` : '';
    return `${endpoint}${paramString}`;
  }

  // Generate unique request ID
  generateRequestId() {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Cancel specific request
  cancelRequest(requestId) {
    if (this.inflightRequests.has(requestId)) {
      this.inflightRequests.delete(requestId);
      return true;
    }
    return false;
  }

  // Cancel all requests
  cancelAllRequests() {
    this.inflightRequests.clear();
  }

  // GET request with enhanced features
  async get(endpoint, params = {}, options = {}) {
    const queryString = new URLSearchParams(params).toString();
    const url = queryString ? `${endpoint}?${queryString}` : endpoint;
    
    return this.request(url, {
      method: 'GET',
      ...options
    });
  }

  // POST request with enhanced features
  async post(endpoint, data = {}, options = {}) {
    return this.request(endpoint, {
      method: 'POST',
      body: data,
      ...options
    });
  }

  // PUT request with enhanced features
  async put(endpoint, data = {}, options = {}) {
    return this.request(endpoint, {
      method: 'PUT',
      body: data,
      ...options
    });
  }

  // DELETE request with enhanced features
  async delete(endpoint, options = {}) {
    return this.request(endpoint, {
      method: 'DELETE',
      ...options
    });
  }

  // PATCH request with enhanced features
  async patch(endpoint, data = {}, options = {}) {
    return this.request(endpoint, {
      method: 'PATCH',
      body: data,
      ...options
    });
  }

  // Upload file
  async uploadFile(endpoint, file, options = {}) {
    const formData = new FormData();
    formData.append('file', file);

    if (options.additionalData) {
      Object.keys(options.additionalData).forEach(key => {
        formData.append(key, options.additionalData[key]);
      });
    }

    return this.request(endpoint, {
      method: 'POST',
      body: formData,
      headers: {
        // Let browser set Content-Type for FormData
        ...Object.fromEntries(
          Object.entries(this.headers).filter(([key]) => key !== 'Content-Type')
        )
      },
      ...options
    });
  }

  // Download file
  async downloadFile(endpoint, filename, options = {}) {
    const response = await this.request(endpoint, {
      method: 'GET',
      responseType: 'blob',
      ...options
    });

    // Create blob and download
    const blob = new Blob([response]);
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);

    return true;
  }

  // Batch requests
  async batch(requests) {
    const results = await Promise.allSettled(
      requests.map(req => this.request(req.endpoint, req.options))
    );

    return results.map((result, index) => ({
      index,
      status: result.status,
      value: result.status === 'fulfilled' ? result.value : null,
      error: result.status === 'rejected' ? result.reason : null
    }));
  }

  // Get service statistics
  getStats() {
    return {
      inflightRequests: this.inflightRequests.size,
      interceptors: {
        request: this.requestInterceptors.length,
        response: this.responseInterceptors.length
      },
      cache: cacheManager.getStats(),
      connection: connectionMonitor.getStatus()
    };
  }

  // Health check
  async healthCheck() {
    try {
      const result = await this.get('/health', {}, { timeout: 5000, cache: false });
      return { healthy: true, data: result };
    } catch (error) {
      return { healthy: false, error: error.message };
    }
  }

  // Cleanup
  destroy() {
    this.cancelAllRequests();
    this.requestInterceptors = [];
    this.responseInterceptors = [];
  }
}

// Enhanced specialized service classes
export class EnhancedScanService extends EnhancedApiService {
  constructor() {
    super();
    this.endpoint = API_CONFIG.ENDPOINTS.SCAN;
  }

  async startScan(scanConfig, options = {}) {
    return this.post(this.endpoint, scanConfig, {
      timeout: API_CONFIG.TIMEOUT.SCAN,
      ...options
    });
  }

  async stopScan(scanId, options = {}) {
    return this.post(`${this.endpoint}/stop`, { scan_id: scanId }, options);
  }

  async pauseScan(scanId, options = {}) {
    return this.post(`${this.endpoint}/pause`, { scan_id: scanId }, options);
  }

  async resumeScan(scanId, options = {}) {
    return this.post(`${this.endpoint}/resume`, { scan_id: scanId }, options);
  }

  async getScanStatus(scanId, options = {}) {
    return this.get(`${this.endpoint}/status/${scanId}`, {}, {
      cache: true,
      ...options
    });
  }

  async getScanResults(scanId, options = {}) {
    return this.get(`${this.endpoint}/results/${scanId}`, {}, {
      timeout: API_CONFIG.TIMEOUT.SCAN,
      ...options
    });
  }

  async exportResults(scanId, format = 'json', options = {}) {
    return this.downloadFile(
      `${this.endpoint}/export/${scanId}?format=${format}`,
      `scan_results_${scanId}.${format}`,
      {
        timeout: API_CONFIG.TIMEOUT.EXPORT,
        ...options
      }
    );
  }
}

export class EnhancedVulnerabilityService extends EnhancedApiService {
  constructor() {
    super();
    this.endpoint = API_CONFIG.ENDPOINTS.VULNERABILITIES;
  }

  async getVulnerabilities(scanId, options = {}) {
    return this.get(this.endpoint, { scan_id: scanId }, {
      cache: true,
      ...options
    });
  }

  async getVulnerabilityDetails(vulnerabilityId, options = {}) {
    return this.get(`${this.endpoint}/${vulnerabilityId}`, {}, {
      cache: true,
      ...options
    });
  }

  async updateVulnerabilityStatus(vulnerabilityId, status, options = {}) {
    return this.put(`${this.endpoint}/${vulnerabilityId}/status`, { status }, options);
  }

  async getStatistics(scanId, options = {}) {
    return this.get(`${this.endpoint}/statistics`, { scan_id: scanId }, {
      cache: true,
      ...options
    });
  }
}

export class EnhancedHistoryService extends EnhancedApiService {
  constructor() {
    super();
    this.endpoint = API_CONFIG.ENDPOINTS.HISTORY;
  }

  async getScanHistory(page = 1, limit = 20, options = {}) {
    return this.get(this.endpoint, { page, limit }, {
      cache: true,
      ...options
    });
  }

  async getScanDetails(scanId, options = {}) {
    return this.get(`${this.endpoint}/${scanId}`, {}, {
      cache: true,
      ...options
    });
  }

  async deleteScan(scanId, options = {}) {
    return this.delete(`${this.endpoint}/${scanId}`, options);
  }

  async importScan(scanData, options = {}) {
    return this.post(`${this.endpoint}/import`, scanData, {
      timeout: API_CONFIG.TIMEOUT.SCAN,
      ...options
    });
  }
}

export class EnhancedRepeaterService extends EnhancedApiService {
  constructor() {
    super();
    this.endpoint = API_CONFIG.ENDPOINTS.REPEATER;
  }

  async sendRequest(requestConfig, options = {}) {
    return this.post(`${this.endpoint}/send`, requestConfig, {
      timeout: 30000, // 30 seconds for HTTP requests
      ...options
    });
  }

  async getRequestHistory(options = {}) {
    return this.get(`${this.endpoint}/history`, {}, {
      cache: true,
      ...options
    });
  }

  async saveRequest(requestConfig, options = {}) {
    return this.post(`${this.endpoint}/save`, requestConfig, options);
  }

  async deleteRequest(requestId, options = {}) {
    return this.delete(`${this.endpoint}/history/${requestId}`, options);
  }
}

// Create enhanced service instances
export const enhancedScanService = new EnhancedScanService();
export const enhancedVulnerabilityService = new EnhancedVulnerabilityService();
export const enhancedHistoryService = new EnhancedHistoryService();
export const enhancedRepeaterService = new EnhancedRepeaterService();

// Export the main enhanced service
export default EnhancedApiService;
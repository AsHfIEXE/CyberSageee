import { API_CONFIG } from '../utils/constants';

// Base API service class
class ApiService {
  constructor() {
    this.baseURL = API_CONFIG.BASE_URL;
    this.headers = {
      'Content-Type': 'application/json',
    };
  }

  // Generic HTTP request method
  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      headers: this.headers,
      ...options,
    };

    try {
      const response = await fetch(url, config);
      
      if (!response.ok) {
        throw new Error(`HTTP Error: ${response.status} ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('API Request failed:', error);
      throw error;
    }
  }

  // GET request
  async get(endpoint, params = {}) {
    const queryString = new URLSearchParams(params).toString();
    const url = queryString ? `${endpoint}?${queryString}` : endpoint;
    return this.request(url, { method: 'GET' });
  }

  // POST request
  async post(endpoint, data = {}) {
    return this.request(endpoint, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // PUT request
  async put(endpoint, data = {}) {
    return this.request(endpoint, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  // DELETE request
  async delete(endpoint) {
    return this.request(endpoint, { method: 'DELETE' });
  }
}

// Specialized service classes
class ScanService extends ApiService {
  constructor() {
    super();
    this.endpoint = API_CONFIG.ENDPOINTS.SCAN;
  }

  // Start a new scan
  startScan(scanConfig) {
    return this.post(this.endpoint, scanConfig);
  }

  // Stop current scan
  stopScan(scanId) {
    return this.post(`${this.endpoint}/stop`, { scan_id: scanId });
  }

  // Pause scan
  pauseScan(scanId) {
    return this.post(`${this.endpoint}/pause`, { scan_id: scanId });
  }

  // Resume scan
  resumeScan(scanId) {
    return this.post(`${this.endpoint}/resume`, { scan_id: scanId });
  }

  // Get scan status
  getScanStatus(scanId) {
    return this.get(`${this.endpoint}/status/${scanId}`);
  }

  // Get scan results
  getScanResults(scanId) {
    return this.get(`${this.endpoint}/results/${scanId}`);
  }

  // Export scan results
  exportResults(scanId, format = 'json') {
    return this.get(`${this.endpoint}/export/${scanId}`, { format });
  }
}

class VulnerabilityService extends ApiService {
  constructor() {
    super();
    this.endpoint = API_CONFIG.ENDPOINTS.VULNERABILITIES;
  }

  // Get vulnerabilities
  getVulnerabilities(scanId) {
    return this.get(this.endpoint, { scan_id: scanId });
  }

  // Get vulnerability details
  getVulnerabilityDetails(vulnerabilityId) {
    return this.get(`${this.endpoint}/${vulnerabilityId}`);
  }

  // Update vulnerability status
  updateVulnerabilityStatus(vulnerabilityId, status) {
    return this.put(`${this.endpoint}/${vulnerabilityId}/status`, { status });
  }

  // Get vulnerability statistics
  getStatistics(scanId) {
    return this.get(`${this.endpoint}/statistics`, { scan_id: scanId });
  }
}

class HistoryService extends ApiService {
  constructor() {
    super();
    this.endpoint = API_CONFIG.ENDPOINTS.HISTORY;
  }

  // Get scan history
  getScanHistory(page = 1, limit = 20) {
    return this.get(this.endpoint, { page, limit });
  }

  // Get specific scan details
  getScanDetails(scanId) {
    return this.get(`${this.endpoint}/${scanId}`);
  }

  // Delete scan record
  deleteScan(scanId) {
    return this.delete(`${this.endpoint}/${scanId}`);
  }

  // Import scan
  importScan(scanData) {
    return this.post(`${this.endpoint}/import`, scanData);
  }
}

class RepeaterService extends ApiService {
  constructor() {
    super();
    this.endpoint = API_CONFIG.ENDPOINTS.REPEATER;
  }

  // Send HTTP request
  sendRequest(requestConfig) {
    return this.post(`${this.endpoint}/send`, requestConfig);
  }

  // Get request history
  getRequestHistory() {
    return this.get(`${this.endpoint}/history`);
  }

  // Save request to history
  saveRequest(requestConfig) {
    return this.post(`${this.endpoint}/save`, requestConfig);
  }

  // Delete request from history
  deleteRequest(requestId) {
    return this.delete(`${this.endpoint}/history/${requestId}`);
  }
}

// Export service instances
export const scanService = new ScanService();
export const vulnerabilityService = new VulnerabilityService();
export const historyService = new HistoryService();
export const repeaterService = new RepeaterService();

// Export main service class for custom requests
export default ApiService;
import { PERFORMANCE_CONFIG } from '../utils/constants';

export class ConnectionMonitor {
  constructor() {
    this.isOnline = navigator.onLine;
    this.connectionQuality = 'good'; // good, fair, poor
    this.latency = 0;
    this.packetLoss = 0;
    this.lastHealthCheck = null;
    this.healthCheckInterval = null;
    this.listeners = new Map();
    this.metrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageLatency: 0,
      uptime: 0,
      startTime: Date.now()
    };
    this.setupEventListeners();
  }

  // Setup event listeners for network changes
  setupEventListeners() {
    window.addEventListener('online', this.handleOnline.bind(this));
    window.addEventListener('offline', this.handleOffline.bind(this));
    
    // Listen for focus events to check connection
    window.addEventListener('focus', this.checkConnection.bind(this));
    
    // Setup periodic health checks
    this.startHealthChecks();
  }

  // Handle coming online
  handleOnline() {
    this.isOnline = true;
    this.emit('statusChange', { 
      isOnline: true, 
      previousState: this.isOnline ? 'online' : 'offline',
      timestamp: Date.now()
    });
    this.checkConnection();
  }

  // Handle going offline
  handleOffline() {
    this.isOnline = false;
    this.emit('statusChange', { 
      isOnline: false, 
      previousState: this.isOnline ? 'online' : 'offline',
      timestamp: Date.now()
    });
  }

  // Start periodic health checks
  startHealthChecks() {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }

    this.healthCheckInterval = setInterval(async () => {
      if (this.isOnline) {
        await this.performHealthCheck();
      }
    }, PERFORMANCE_CONFIG.HEALTH_CHECK_INTERVAL);
  }

  // Stop health checks
  stopHealthChecks() {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }
  }

  // Perform health check
  async performHealthCheck() {
    const startTime = Date.now();
    
    try {
      const response = await fetch('/health', {
        method: 'GET',
        headers: {
          'Cache-Control': 'no-cache',
          'X-Health-Check': 'true'
        },
        timeout: 10000 // 10 seconds timeout
      });

      const latency = Date.now() - startTime;
      const isHealthy = response.ok;
      
      this.updateMetrics({
        successfulRequests: this.metrics.successfulRequests + (isHealthy ? 1 : 0),
        failedRequests: this.metrics.failedRequests + (isHealthy ? 0 : 1),
        averageLatency: (this.metrics.averageLatency + latency) / 2
      });

      this.lastHealthCheck = {
        timestamp: Date.now(),
        latency,
        status: isHealthy ? 'healthy' : 'unhealthy',
        statusCode: response.status
      };

      // Update connection quality based on latency
      this.updateConnectionQuality(latency, response.status);

      this.emit('healthCheck', this.lastHealthCheck);
      
      return this.lastHealthCheck;
    } catch (error) {
      const latency = Date.now() - startTime;
      
      this.updateMetrics({
        failedRequests: this.metrics.failedRequests + 1,
        averageLatency: (this.metrics.averageLatency + latency) / 2
      });

      this.lastHealthCheck = {
        timestamp: Date.now(),
        latency,
        status: 'error',
        error: error.message
      };

      this.updateConnectionQuality(latency, 0);
      
      this.emit('healthCheck', this.lastHealthCheck);
      
      return this.lastHealthCheck;
    }
  }

  // Check basic connection
  async checkConnection() {
    if (!this.isOnline) {
      this.connectionQuality = 'offline';
      return { online: false, quality: 'offline' };
    }

    try {
      // Try a quick request to check connectivity
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const response = await fetch('/health', {
        method: 'HEAD',
        signal: controller.signal,
        cache: 'no-cache'
      });

      clearTimeout(timeoutId);
      
      this.connectionQuality = response.ok ? 'good' : 'poor';
      return { online: true, quality: this.connectionQuality };
    } catch (error) {
      this.connectionQuality = 'poor';
      return { online: true, quality: 'poor', error: error.message };
    }
  }

  // Update connection quality based on latency and status
  updateConnectionQuality(latency, statusCode) {
    let quality = 'good';
    
    if (statusCode >= 400) {
      quality = 'poor';
    } else if (latency > 2000) {
      quality = 'poor';
    } else if (latency > 1000) {
      quality = 'fair';
    } else if (latency > 500) {
      quality = 'fair';
    }

    if (quality !== this.connectionQuality) {
      this.connectionQuality = quality;
      this.emit('qualityChange', {
        quality,
        latency,
        statusCode,
        timestamp: Date.now()
      });
    }

    this.latency = latency;
  }

  // Update metrics
  updateMetrics(newMetrics) {
    this.metrics = { ...this.metrics, ...newMetrics };
    this.emit('metricsUpdate', this.metrics);
  }

  // Record request metrics
  recordRequest(success, latency) {
    this.metrics.totalRequests++;
    
    if (success) {
      this.metrics.successfulRequests++;
    } else {
      this.metrics.failedRequests++;
    }

    // Update average latency
    this.metrics.averageLatency = 
      (this.metrics.averageLatency * (this.metrics.totalRequests - 1) + latency) / 
      this.metrics.totalRequests;

    this.emit('requestComplete', { success, latency, totalRequests: this.metrics.totalRequests });
  }

  // Get current status
  getStatus() {
    return {
      online: this.isOnline,
      quality: this.connectionQuality,
      latency: this.latency,
      lastHealthCheck: this.lastHealthCheck,
      metrics: { ...this.metrics },
      uptime: Date.now() - this.metrics.startTime
    };
  }

  // Get connection quality description
  getQualityDescription() {
    switch (this.connectionQuality) {
      case 'good':
        return 'Connection is working well';
      case 'fair':
        return 'Connection is slow but functional';
      case 'poor':
        return 'Connection is having issues';
      case 'offline':
        return 'No internet connection';
      default:
        return 'Connection status unknown';
    }
  }

  // Get detailed metrics
  getDetailedMetrics() {
    const successRate = this.metrics.totalRequests > 0 
      ? (this.metrics.successfulRequests / this.metrics.totalRequests * 100).toFixed(1)
      : 0;

    return {
      ...this.metrics,
      successRate: `${successRate}%`,
      uptime: Date.now() - this.metrics.startTime,
      currentLatency: this.latency,
      quality: this.connectionQuality,
      lastHealthCheck: this.lastHealthCheck
    };
  }

  // Event handling
  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event).add(callback);
    
    // Return unsubscribe function
    return () => {
      this.off(event, callback);
    };
  }

  off(event, callback) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).delete(callback);
    }
  }

  emit(event, data) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          console.error('Error in connection monitor listener:', error);
        }
      });
    }
  }

  // Cleanup
  destroy() {
    this.stopHealthChecks();
    this.listeners.clear();
    
    window.removeEventListener('online', this.handleOnline.bind(this));
    window.removeEventListener('offline', this.handleOffline.bind(this));
    window.removeEventListener('focus', this.checkConnection.bind(this));
  }
}

// Create singleton instance
export const connectionMonitor = new ConnectionMonitor();

// Network Information API enhancement
export class NetworkInformation {
  constructor() {
    this.connection = null;
    this.setupConnectionAPI();
  }

  setupConnectionAPI() {
    if ('connection' in navigator) {
      this.connection = navigator.connection;
      this.setupEventListeners();
    }
  }

  setupEventListeners() {
    if (!this.connection) return;

    // Listen for connection changes
    this.connection.addEventListener('change', this.handleConnectionChange.bind(this));
  }

  handleConnectionChange() {
    const connectionData = {
      effectiveType: this.connection.effectiveType,
      downlink: this.connection.downlink,
      rtt: this.connection.rtt,
      saveData: this.connection.saveData
    };

    connectionMonitor.emit('connectionChange', connectionData);
  }

  getConnectionInfo() {
    if (!this.connection) {
      return {
        supported: false,
        effectiveType: 'unknown',
        downlink: null,
        rtt: null,
        saveData: false
      };
    }

    return {
      supported: true,
      effectiveType: this.connection.effectiveType,
      downlink: this.connection.downlink,
      rtt: this.connection.rtt,
      saveData: this.connection.saveData
    };
  }
}

// Create singleton instance
export const networkInfo = new NetworkInformation();
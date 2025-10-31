import { QUEUE_CONFIG } from '../utils/constants';

export class RequestQueue {
  constructor() {
    this.queue = [];
    this.processing = false;
    this.maxSize = QUEUE_CONFIG.MAX_QUEUE_SIZE;
    this.flushInterval = null;
    this.listeners = new Map();
    this.stats = {
      totalQueued: 0,
      totalProcessed: 0,
      totalFailed: 0,
      lastFlush: null
    };
    this.startAutoFlush();
  }

  // Add request to queue
  async queueRequest(requestConfig) {
    if (this.queue.length >= this.maxSize) {
      throw new Error(`Queue is full. Maximum size: ${this.maxSize}`);
    }

    const queueItem = {
      id: this.generateId(),
      timestamp: Date.now(),
      priority: requestConfig.priority || QUEUE_CONFIG.PRIORITY_NORMAL,
      retryCount: 0,
      maxRetries: requestConfig.maxRetries || 3,
      ...requestConfig
    };

    this.queue.push(queueItem);
    this.sortQueue();
    this.stats.totalQueued++;

    this.emit('itemQueued', queueItem);
    this.emit('queueSizeChange', { size: this.queue.length });

    return queueItem.id;
  }

  // Sort queue by priority and timestamp
  sortQueue() {
    const priorityOrder = {
      [QUEUE_CONFIG.PRIORITY_HIGH]: 3,
      [QUEUE_CONFIG.PRIORITY_NORMAL]: 2,
      [QUEUE_CONFIG.PRIORITY_LOW]: 1
    };

    this.queue.sort((a, b) => {
      const priorityDiff = priorityOrder[b.priority] - priorityOrder[a.priority];
      if (priorityDiff !== 0) return priorityDiff;
      return a.timestamp - b.timestamp;
    });
  }

  // Process queue
  async processQueue() {
    if (this.processing || this.queue.length === 0) {
      return;
    }

    this.processing = true;
    this.emit('processingStarted');

    try {
      while (this.queue.length > 0) {
        const item = this.queue.shift();
        
        try {
          await this.processItem(item);
          this.stats.totalProcessed++;
          this.emit('itemProcessed', item);
        } catch (error) {
          this.stats.totalFailed++;
          
          if (item.retryCount < item.maxRetries) {
            // Re-queue with incremented retry count
            item.retryCount++;
            item.timestamp = Date.now(); // Move to end of queue
            this.queue.push(item);
            this.emit('itemRetry', { item, error });
          } else {
            this.emit('itemFailed', { item, error });
          }
        }
      }
    } finally {
      this.processing = false;
      this.stats.lastFlush = Date.now();
      this.emit('processingCompleted');
      this.emit('queueSizeChange', { size: this.queue.length });
    }
  }

  // Process individual queue item
  async processItem(item) {
    const { url, method = 'GET', headers = {}, body, timeout = 30000 } = item.request;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const config = {
        method,
        headers,
        signal: controller.signal
      };

      if (body && ['POST', 'PUT', 'PATCH'].includes(method)) {
        config.body = typeof body === 'string' ? body : JSON.stringify(body);
      }

      const response = await fetch(url, config);
      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json();
      this.emit('itemSuccess', { item, result });
      
      return result;
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }

  // Start automatic flushing
  startAutoFlush() {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
    }

    this.flushInterval = setInterval(() => {
      if (this.queue.length > 0) {
        this.processQueue();
      }
    }, QUEUE_CONFIG.FLUSH_INTERVAL);
  }

  // Stop automatic flushing
  stopAutoFlush() {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
      this.flushInterval = null;
    }
  }

  // Manually flush queue
  async flush() {
    await this.processQueue();
  }

  // Clear queue
  clear() {
    const clearedItems = [...this.queue];
    this.queue = [];
    this.emit('queueCleared', clearedItems);
    this.emit('queueSizeChange', { size: 0 });
  }

  // Remove specific item from queue
  removeItem(id) {
    const index = this.queue.findIndex(item => item.id === id);
    if (index !== -1) {
      const [removedItem] = this.queue.splice(index, 1);
      this.emit('itemRemoved', removedItem);
      this.emit('queueSizeChange', { size: this.queue.length });
      return removedItem;
    }
    return null;
  }

  // Get queue status
  getStatus() {
    const priorityCounts = {
      [QUEUE_CONFIG.PRIORITY_HIGH]: 0,
      [QUEUE_CONFIG.PRIORITY_NORMAL]: 0,
      [QUEUE_CONFIG.PRIORITY_LOW]: 0
    };

    this.queue.forEach(item => {
      priorityCounts[item.priority]++;
    });

    return {
      size: this.queue.length,
      maxSize: this.maxSize,
      processing: this.processing,
      priorityCounts,
      stats: { ...this.stats },
      lastFlush: this.stats.lastFlush
    };
  }

  // Get queue items (for debugging)
  getItems() {
    return this.queue.map(item => ({
      id: item.id,
      priority: item.priority,
      timestamp: item.timestamp,
      retryCount: item.retryCount,
      maxRetries: item.maxRetries,
      method: item.request.method,
      url: item.request.url
    }));
  }

  // Set maximum queue size
  setMaxSize(newMaxSize) {
    if (newMaxSize < this.queue.length) {
      throw new Error(`New max size (${newMaxSize}) is smaller than current queue size (${this.queue.length})`);
    }
    this.maxSize = newMaxSize;
  }

  // Generate unique ID
  generateId() {
    return `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Event handling
  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event).add(callback);
    
    return () => this.off(event, callback);
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
          console.error('Error in queue listener:', error);
        }
      });
    }
  }

  // Cleanup
  destroy() {
    this.stopAutoFlush();
    this.queue = [];
    this.listeners.clear();
  }
}

// Create singleton instance
export const requestQueue = new RequestQueue();

// Queue decorator for API methods
export function queueable(options = {}) {
  return function(target, propertyName, descriptor) {
    const method = descriptor.value;
    
    descriptor.value = async function(...args) {
      const { 
        priority = QUEUE_CONFIG.PRIORITY_NORMAL,
        maxRetries = 3,
        timeout = 30000,
        queueIfOffline = true 
      } = options;

      // Check if we should queue the request
      const isOnline = navigator.onLine;
      
      if (!isOnline && queueIfOffline) {
        const queueId = await requestQueue.queueRequest({
          request: {
            url: this.baseURL + args[0], // Assuming first arg is endpoint
            method: options.method || 'GET',
            headers: options.headers || {},
            body: args[1] || null,
            timeout
          },
          priority,
          maxRetries
        });
        
        return { queued: true, queueId };
      }

      // Process normally if online or not queuing offline
      return await method.apply(this, args);
    };
    
    return descriptor;
  };
}

// Auto-flush on network restore
window.addEventListener('online', () => {
  setTimeout(() => {
    if (requestQueue.queue.length > 0) {
      requestQueue.flush();
    }
  }, 1000); // Wait 1 second for network to stabilize
});
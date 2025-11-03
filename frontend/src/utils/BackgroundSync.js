// IndexedDB utility for service worker background sync
class IndexedDBManager {
  constructor(dbName = 'CyberSageSyncDB', version = 1) {
    this.dbName = dbName;
    this.version = version;
    this.db = null;
  }

  async init() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.version);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        this.db = request.result;
        resolve(this.db);
      };

      request.onupgradeneeded = (event) => {
        const db = event.target.result;

        // Create object stores
        if (!db.objectStoreNames.contains('syncQueue')) {
          const syncStore = db.createObjectStore('syncQueue', { 
            keyPath: 'id', 
            autoIncrement: true 
          });
          syncStore.createIndex('status', 'status', { unique: false });
          syncStore.createIndex('timestamp', 'timestamp', { unique: false });
        }

        if (!db.objectStoreNames.contains('apiCache')) {
          const cacheStore = db.createObjectStore('apiCache', { 
            keyPath: 'url' 
          });
          cacheStore.createIndex('timestamp', 'timestamp', { unique: false });
          cacheStore.createIndex('expiry', 'expiry', { unique: false });
        }

        if (!db.objectStoreNames.contains('performanceMetrics')) {
          const metricsStore = db.createObjectStore('performanceMetrics', { 
            keyPath: 'id', 
            autoIncrement: true 
          });
          metricsStore.createIndex('timestamp', 'timestamp', { unique: false });
          metricsStore.createIndex('type', 'type', { unique: false });
        }
      };
    });
  }

  // Sync Queue Operations
  async addToSyncQueue(requestData) {
    try {
      if (!this.db) await this.init();
      
      const transaction = this.db.transaction(['syncQueue'], 'readwrite');
      const store = transaction.objectStore('syncQueue');
      
      const data = {
        ...requestData,
        status: 'pending',
        timestamp: Date.now(),
        retryCount: 0
      };
      
      await store.add(data);
      return data;
    } catch (error) {
      console.error('Failed to add to sync queue:', error);
      throw error;
    }
  }

  async getPendingSyncRequests() {
    try {
      if (!this.db) await this.init();
      
      const transaction = this.db.transaction(['syncQueue'], 'readonly');
      const store = transaction.objectStore('syncQueue');
      const index = store.index('status');
      
      return new Promise((resolve, reject) => {
        const request = index.getAll('pending');
        request.onsuccess = () => resolve(request.result || []);
        request.onerror = () => reject(request.error);
      });
    } catch (error) {
      console.error('Failed to get pending sync requests:', error);
      return [];
    }
  }

  async updateSyncRequest(id, updates) {
    try {
      if (!this.db) await this.init();
      
      const transaction = this.db.transaction(['syncQueue'], 'readwrite');
      const store = transaction.objectStore('syncQueue');
      
      return new Promise((resolve, reject) => {
        const getRequest = store.get(id);
        getRequest.onsuccess = () => {
          const data = { ...getRequest.result, ...updates };
          const putRequest = store.put(data);
          putRequest.onsuccess = () => resolve(data);
          putRequest.onerror = () => reject(putRequest.error);
        };
        getRequest.onerror = () => reject(getRequest.error);
      });
    } catch (error) {
      console.error('Failed to update sync request:', error);
      throw error;
    }
  }

  async removeSyncRequest(id) {
    try {
      if (!this.db) await this.init();
      
      const transaction = this.db.transaction(['syncQueue'], 'readwrite');
      const store = transaction.objectStore('syncQueue');
      
      return store.delete(id);
    } catch (error) {
      console.error('Failed to remove sync request:', error);
      throw error;
    }
  }

  // API Cache Operations
  async cacheApiResponse(url, data, ttl = 300000) { // 5 minutes default
    try {
      if (!this.db) await this.init();
      
      const transaction = this.db.transaction(['apiCache'], 'readwrite');
      const store = transaction.objectStore('apiCache');
      
      const cacheData = {
        url,
        data,
        timestamp: Date.now(),
        expiry: Date.now() + ttl
      };
      
      await store.put(cacheData);
    } catch (error) {
      console.error('Failed to cache API response:', error);
    }
  }

  async getCachedApiResponse(url) {
    try {
      if (!this.db) await this.init();
      
      const transaction = this.db.transaction(['apiCache'], 'readonly');
      const store = transaction.objectStore('apiCache');
      
      return new Promise((resolve, reject) => {
        const request = store.get(url);
        request.onsuccess = () => {
          const result = request.result;
          if (result && result.expiry > Date.now()) {
            resolve(result.data);
          } else {
            resolve(null);
          }
        };
        request.onerror = () => reject(request.error);
      });
    } catch (error) {
      console.error('Failed to get cached API response:', error);
      return null;
    }
  }

  async cleanupExpiredCache() {
    try {
      if (!this.db) await this.init();
      
      const transaction = this.db.transaction(['apiCache'], 'readwrite');
      const store = transaction.objectStore('apiCache');
      const index = store.index('expiry');
      
      return new Promise((resolve, reject) => {
        const now = Date.now();
        const range = IDBKeyRange.upperBound(now);
        const request = index.openCursor(range);
        
        let deletedCount = 0;
        request.onsuccess = (event) => {
          const cursor = event.target.result;
          if (cursor) {
            store.delete(cursor.primaryKey);
            deletedCount++;
            cursor.continue();
          } else {
            resolve(deletedCount);
          }
        };
        request.onerror = () => reject(request.error);
      });
    } catch (error) {
      console.error('Failed to cleanup expired cache:', error);
      return 0;
    }
  }

  // Performance Metrics
  async recordPerformanceMetric(type, data) {
    try {
      if (!this.db) await this.init();
      
      const transaction = this.db.transaction(['performanceMetrics'], 'readwrite');
      const store = transaction.objectStore('performanceMetrics');
      
      const metric = {
        type,
        data,
        timestamp: Date.now()
      };
      
      await store.add(metric);
    } catch (error) {
      console.error('Failed to record performance metric:', error);
    }
  }

  async getPerformanceMetrics(type, limit = 100) {
    try {
      if (!this.db) await this.init();
      
      const transaction = this.db.transaction(['performanceMetrics'], 'readonly');
      const store = transaction.objectStore('performanceMetrics');
      const index = store.index('type');
      
      return new Promise((resolve, reject) => {
        const request = index.getAll(type, limit);
        request.onsuccess = () => resolve(request.result || []);
        request.onerror = () => reject(request.error);
      });
    } catch (error) {
      console.error('Failed to get performance metrics:', error);
      return [];
    }
  }

  // Database management
  async clearAllData() {
    try {
      if (!this.db) await this.init();
      
      const storeNames = ['syncQueue', 'apiCache', 'performanceMetrics'];
      const promises = storeNames.map(storeName => {
        const transaction = this.db.transaction([storeName], 'readwrite');
        return transaction.objectStore(storeName).clear();
      });
      
      await Promise.all(promises);
      console.log('All IndexedDB data cleared');
    } catch (error) {
      console.error('Failed to clear IndexedDB data:', error);
      throw error;
    }
  }

  async getDatabaseStats() {
    try {
      if (!this.db) await this.init();
      
      const storeNames = ['syncQueue', 'apiCache', 'performanceMetrics'];
      const stats = {};
      
      for (const storeName of storeNames) {
        const transaction = this.db.transaction([storeName], 'readonly');
        const store = transaction.objectStore(storeName);
        
        stats[storeName] = await new Promise((resolve, reject) => {
          const countRequest = store.count();
          countRequest.onsuccess = () => resolve(countRequest.result);
          countRequest.onerror = () => reject(countRequest.error);
        });
      }
      
      return stats;
    } catch (error) {
      console.error('Failed to get database stats:', error);
      return {};
    }
  }
}

// Background Sync Manager
class BackgroundSyncManager {
  constructor() {
    this.idbManager = new IndexedDBManager();
    this.isOnline = navigator.onLine;
    this.setupEventListeners();
  }

  setupEventListeners() {
    window.addEventListener('online', () => {
      this.isOnline = true;
      this.handleConnectivityChange(true);
    });

    window.addEventListener('offline', () => {
      this.isOnline = false;
      this.handleConnectivityChange(false);
    });
  }

  async handleConnectivityChange(isOnline) {
    if (isOnline) {
      console.log('BackgroundSyncManager: Back online, processing queued requests');
      await this.processSyncQueue();
    }
  }

  async queueApiRequest(url, options = {}) {
    try {
      const requestData = {
        url,
        method: options.method || 'GET',
        headers: options.headers || {},
        body: options.body || null,
        metadata: options.metadata || {}
      };

      await this.idbManager.addToSyncQueue(requestData);
      console.log('BackgroundSyncManager: Request queued for background sync:', requestData.url);

      // If online, try to sync immediately
      if (this.isOnline) {
        await this.processSyncQueue();
      }

      return { queued: true, offline: !this.isOnline };
    } catch (error) {
      console.error('BackgroundSyncManager: Failed to queue request:', error);
      return { queued: false, error: error.message };
    }
  }

  async processSyncQueue() {
    try {
      const pendingRequests = await this.idbManager.getPendingSyncRequests();
      
      if (pendingRequests.length === 0) {
        console.log('BackgroundSyncManager: No pending requests to sync');
        return;
      }

      console.log(`BackgroundSyncManager: Processing ${pendingRequests.length} queued requests`);

      for (const request of pendingRequests) {
        try {
          await this.processSingleRequest(request);
        } catch (error) {
          console.error('BackgroundSyncManager: Failed to process request:', error);
          
          // Update retry count
          const retryCount = (request.retryCount || 0) + 1;
          const maxRetries = 3;
          
          if (retryCount >= maxRetries) {
            console.log('BackgroundSyncManager: Max retries reached, marking as failed');
            await this.idbManager.updateSyncRequest(request.id, { 
              status: 'failed', 
              error: error.message,
              failedAt: Date.now()
            });
          } else {
            console.log(`BackgroundSyncManager: Retrying request (${retryCount}/${maxRetries})`);
            await this.idbManager.updateSyncRequest(request.id, { 
              status: 'pending',
              retryCount,
              lastError: error.message,
              nextRetry: Date.now() + (60000 * retryCount) // Exponential backoff
            });
          }
        }
      }

      // Clean up old cache entries
      await this.idbManager.cleanupExpiredCache();
    } catch (error) {
      console.error('BackgroundSyncManager: Failed to process sync queue:', error);
    }
  }

  async processSingleRequest(request) {
    const { url, method, headers, body } = request;

    // Check if we should retry based on exponential backoff
    if (request.nextRetry && Date.now() < request.nextRetry) {
      return; // Skip for now
    }

    const fetchOptions = {
      method,
      headers,
      ...(body && { body })
    };

    const response = await fetch(url, fetchOptions);
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    // Mark as completed
    await this.idbManager.updateSyncRequest(request.id, { 
      status: 'completed',
      completedAt: Date.now(),
      response: {
        status: response.status,
        statusText: response.statusText
      }
    });

    console.log(`BackgroundSyncManager: Successfully synced request: ${url}`);
    
    // Notify main thread of successful sync
    if (window.postMessage) {
      window.postMessage({
        type: 'BACKGROUND_SYNC_SUCCESS',
        requestId: request.id,
        url: request.url
      });
    }
  }

  async registerBackgroundSync(tag = 'background-sync') {
    if ('serviceWorker' in navigator && 'sync' in window.ServiceWorkerRegistration.prototype) {
      try {
        const registration = await navigator.serviceWorker.ready;
        await registration.sync.register(tag);
        console.log('BackgroundSyncManager: Background sync registered');
      } catch (error) {
        console.error('BackgroundSyncManager: Failed to register background sync:', error);
      }
    }
  }

  async getSyncStatus() {
    try {
      const stats = await this.idbManager.getDatabaseStats();
      return {
        isOnline: this.isOnline,
        pendingRequests: stats.syncQueue || 0,
        cachedResponses: stats.apiCache || 0,
        performanceMetrics: stats.performanceMetrics || 0
      };
    } catch (error) {
      console.error('BackgroundSyncManager: Failed to get sync status:', error);
      return { isOnline: this.isOnline, error: error.message };
    }
  }
}

// Singleton instances
export const idbManager = new IndexedDBManager();
export const backgroundSyncManager = new BackgroundSyncManager();

// React hook for background sync
export const useBackgroundSync = () => {
  const [syncStatus, setSyncStatus] = React.useState({
    isOnline: navigator.onLine,
    pendingRequests: 0
  });

  React.useEffect(() => {
    const updateStatus = async () => {
      const status = await backgroundSyncManager.getSyncStatus();
      setSyncStatus(status);
    };

    updateStatus();

    // Listen for background sync events
    const handleMessage = (event) => {
      if (event.data.type === 'BACKGROUND_SYNC_SUCCESS') {
        updateStatus();
      }
    };

    window.addEventListener('message', handleMessage);
    
    // Periodic status updates
    const interval = setInterval(updateStatus, 30000); // Every 30 seconds

    return () => {
      window.removeEventListener('message', handleMessage);
      clearInterval(interval);
    };
  }, []);

  const queueRequest = React.useCallback(async (url, options) => {
    return await backgroundSyncManager.queueApiRequest(url, options);
  }, []);

  const processQueue = React.useCallback(async () => {
    await backgroundSyncManager.processSyncQueue();
  }, []);

  const registerSync = React.useCallback(async (tag) => {
    await backgroundSyncManager.registerBackgroundSync(tag);
  }, []);

  return {
    syncStatus,
    queueRequest,
    processQueue,
    registerSync
  };
};

export default backgroundSyncManager;
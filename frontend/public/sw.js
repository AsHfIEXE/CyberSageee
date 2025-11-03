// Service Worker for offline caching and performance optimization
const CACHE_NAME = 'cybersage-v2-v2';
const STATIC_CACHE = 'cybersage-static-v2';
const DYNAMIC_CACHE = 'cybersage-dynamic-v2';

// Assets to cache immediately
const STATIC_ASSETS = [
  '/',
  '/static/js/bundle.js',
  '/static/css/main.css',
  '/manifest.json',
  '/favicon.ico'
];

// API endpoints to cache
const API_CACHE_PATTERNS = [
  /^\/api\/vulnerabilities/,
  /^\/api\/scans/,
  /^\/api\/stats/
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  console.log('Service Worker: Installing...');
  
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => {
        console.log('Service Worker: Caching static assets');
        return cache.addAll(STATIC_ASSETS);
      })
      .then(() => {
        console.log('Service Worker: Static assets cached');
        return self.skipWaiting();
      })
      .catch((error) => {
        console.error('Service Worker: Failed to cache static assets:', error);
      })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  console.log('Service Worker: Activating...');
  
  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames.map((cacheName) => {
            if (cacheName !== STATIC_CACHE && cacheName !== DYNAMIC_CACHE) {
              console.log('Service Worker: Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            }
          })
        );
      })
      .then(() => {
        console.log('Service Worker: Activated');
        return self.clients.claim();
      })
  );
});

// Fetch event - serve from cache with network fallback
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);
  
  // Handle API requests differently
  if (isApiRequest(url)) {
    event.respondWith(handleApiRequest(request));
    return;
  }
  
  // Handle static assets
  if (isStaticAsset(url)) {
    event.respondWith(handleStaticAsset(request));
    return;
  }
  
  // Handle navigation requests
  if (request.mode === 'navigate') {
    event.respondWith(handleNavigation(request));
    return;
  }
  
  // Default fetch strategy
  event.respondWith(
    caches.match(request)
      .then((cachedResponse) => {
        if (cachedResponse) {
          return cachedResponse;
        }
        
        return fetch(request)
          .then((response) => {
            // Don't cache non-successful responses
            if (!response || response.status !== 200 || response.type !== 'basic') {
              return response;
            }
            
            // Clone the response for caching
            const responseToCache = response.clone();
            
            caches.open(DYNAMIC_CACHE)
              .then((cache) => {
                cache.put(request, responseToCache);
              });
            
            return response;
          });
      })
  );
});

// API request handler with stale-while-revalidate strategy
async function handleApiRequest(request) {
  const cache = await caches.open(DYNAMIC_CACHE);
  const cachedResponse = await cache.match(request);
  
  const fetchPromise = fetch(request)
    .then((networkResponse) => {
      // Cache successful API responses
      if (networkResponse.status === 200) {
        cache.put(request, networkResponse.clone());
      }
      return networkResponse;
    })
    .catch((error) => {
      console.log('Service Worker: Network request failed:', error);
      
      // Return cached response if available
      if (cachedResponse) {
        return cachedResponse;
      }
      
      // Return offline response
      return new Response(
        JSON.stringify({
          error: 'Network unavailable',
          offline: true,
          message: 'This data is not available offline'
        }),
        {
          status: 503,
          statusText: 'Service Unavailable',
          headers: { 'Content-Type': 'application/json' }
        }
      );
    });
  
  // Return cached response immediately if available, update in background
  if (cachedResponse) {
    fetchPromise; // Trigger background update
    return cachedResponse;
  }
  
  return fetchPromise;
}

// Static asset handler with cache-first strategy
async function handleStaticAsset(request) {
  return caches.match(request)
    .then((cachedResponse) => {
      if (cachedResponse) {
        return cachedResponse;
      }
      
      return fetch(request)
        .then((response) => {
          if (response.status === 200) {
            const responseToCache = response.clone();
            caches.open(STATIC_CACHE)
              .then((cache) => {
                cache.put(request, responseToCache);
              });
          }
          return response;
        });
    });
}

// Navigation handler for SPA routing
async function handleNavigation(request) {
  return caches.match('/')
    .then((cachedResponse) => {
      const fetchPromise = fetch(request)
        .then((networkResponse) => {
          return networkResponse;
        })
        .catch(() => {
          // Return cached app shell if network fails
          return cachedResponse || new Response('Offline', { status: 503 });
        });
      
      // Return cached version immediately if available
      return cachedResponse || fetchPromise;
    });
}

// Background sync for when connectivity is restored
self.addEventListener('sync', (event) => {
  if (event.tag === 'background-sync') {
    console.log('Service Worker: Background sync triggered');
    event.waitUntil(performBackgroundSync());
  }
});

// Background sync function with IndexedDB integration
async function performBackgroundSync() {
  try {
    // Initialize IndexedDB
    const db = await openIndexedDB();
    
    // Get pending sync requests from IndexedDB
    const queuedRequests = await getQueuedRequestsFromIDB(db);
    
    console.log(`Service Worker: Processing ${queuedRequests.length} queued requests`);
    
    for (const requestData of queuedRequests) {
      try {
        const fetchOptions = {
          method: requestData.method,
          headers: requestData.headers,
          ...(requestData.body && { body: requestData.body })
        };
        
        const response = await fetch(requestData.url, fetchOptions);
        
        if (response.ok) {
          // Remove from queue after successful sync
          await removeFromQueueInIDB(db, requestData.id);
          console.log(`Service Worker: Successfully synced ${requestData.url}`);
        } else {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
      } catch (error) {
        console.error('Service Worker: Failed to sync request:', error);
        
        // Update retry count in IndexedDB
        const retryCount = (requestData.retryCount || 0) + 1;
        const maxRetries = 3;
        
        if (retryCount >= maxRetries) {
          await markRequestAsFailed(db, requestData.id, error.message);
        } else {
          await updateRetryCount(db, requestData.id, retryCount);
        }
      }
    }
    
    // Clean up old cache entries
    await cleanupExpiredCache(db);
    
  } catch (error) {
    console.error('Service Worker: Background sync failed:', error);
  }
}

// IndexedDB operations
function openIndexedDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('CyberSageSyncDB', 1);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function getQueuedRequestsFromIDB(db) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(['syncQueue'], 'readonly');
    const store = transaction.objectStore('syncQueue');
    const index = store.index('status');
    const request = index.getAll('pending');
    
    request.onsuccess = () => resolve(request.result || []);
    request.onerror = () => reject(request.error);
  });
}

async function removeFromQueueInIDB(db, id) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(['syncQueue'], 'readwrite');
    const store = transaction.objectStore('syncQueue');
    const request = store.delete(id);
    
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

async function markRequestAsFailed(db, id, error) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(['syncQueue'], 'readwrite');
    const store = transaction.objectStore('syncQueue');
    
    const getRequest = store.get(id);
    getRequest.onsuccess = () => {
      const data = getRequest.result;
      if (data) {
        data.status = 'failed';
        data.error = error;
        data.failedAt = Date.now();
        
        const putRequest = store.put(data);
        putRequest.onsuccess = () => resolve();
        putRequest.onerror = () => reject(putRequest.error);
      } else {
        resolve();
      }
    };
    getRequest.onerror = () => reject(getRequest.error);
  });
}

async function updateRetryCount(db, id, retryCount) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(['syncQueue'], 'readwrite');
    const store = transaction.objectStore('syncQueue');
    
    const getRequest = store.get(id);
    getRequest.onsuccess = () => {
      const data = getRequest.result;
      if (data) {
        data.retryCount = retryCount;
        data.lastError = 'Network error';
        data.nextRetry = Date.now() + (60000 * retryCount); // Exponential backoff
        
        const putRequest = store.put(data);
        putRequest.onsuccess = () => resolve();
        putRequest.onerror = () => reject(putRequest.error);
      } else {
        resolve();
      }
    };
    getRequest.onerror = () => reject(getRequest.error);
  });
}

async function cleanupExpiredCache(db) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(['apiCache'], 'readwrite');
    const store = transaction.objectStore('apiCache');
    const index = store.index('expiry');
    
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
        console.log(`Service Worker: Cleaned up ${deletedCount} expired cache entries`);
        resolve(deletedCount);
      }
    };
    request.onerror = () => reject(request.error);
  });
}

// Message handler for communication with main thread
self.addEventListener('message', (event) => {
  const { type, payload } = event.data;
  
  switch (type) {
    case 'SKIP_WAITING':
      self.skipWaiting();
      break;
      
    case 'GET_VERSION':
      event.ports[0].postMessage({ version: CACHE_NAME });
      break;
      
    case 'CLEAR_CACHE':
      clearAllCaches()
        .then(() => {
          event.ports[0].postMessage({ success: true });
        })
        .catch((error) => {
          event.ports[0].postMessage({ success: false, error: error.message });
        });
      break;
      
    case 'QUEUE_REQUEST':
      queueRequest(payload)
        .then(() => {
          event.ports[0].postMessage({ success: true });
        })
        .catch((error) => {
          event.ports[0].postMessage({ success: false, error: error.message });
        });
      break;
      
    default:
      console.log('Service Worker: Unknown message type:', type);
  }
});

// Utility functions
function isApiRequest(url) {
  return API_CACHE_PATTERNS.some(pattern => pattern.test(url.pathname));
}

function isStaticAsset(url) {
  return url.pathname.startsWith('/static/') || 
         url.pathname.endsWith('.js') || 
         url.pathname.endsWith('.css') ||
         url.pathname.endsWith('.png') ||
         url.pathname.endsWith('.jpg') ||
         url.pathname.endsWith('.svg') ||
         url.pathname.endsWith('.ico');
}

// Legacy compatibility functions (deprecated - use BackgroundSync class instead)
async function getQueuedRequests() {
  console.warn('Service Worker: getQueuedRequests is deprecated, use BackgroundSync class');
  return [];
}

async function removeFromQueue(requestId) {
  console.warn('Service Worker: removeFromQueue is deprecated, use BackgroundSync class');
}

async function queueRequest(requestData) {
  console.warn('Service Worker: queueRequest is deprecated, use BackgroundSync class');
  try {
    const db = await openIndexedDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(['syncQueue'], 'readwrite');
      const store = transaction.objectStore('syncQueue');
      
      const data = {
        ...requestData,
        status: 'pending',
        timestamp: Date.now(),
        retryCount: 0
      };
      
      const request = store.add(data);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  } catch (error) {
    console.error('Service Worker: Failed to queue request:', error);
    throw error;
  }
}

async function clearAllCaches() {
  const cacheNames = await caches.keys();
  return Promise.all(
    cacheNames.map(cacheName => caches.delete(cacheName))
  );
}

// Push notification handler
self.addEventListener('push', (event) => {
  const options = {
    body: event.data ? event.data.text() : 'New scan result available',
    icon: '/icon-192x192.png',
    badge: '/icon-72x72.png',
    vibrate: [100, 50, 100],
    data: {
      dateOfArrival: Date.now(),
      primaryKey: 1
    },
    actions: [
      {
        action: 'view',
        title: 'View Results',
        icon: '/icon-view.png'
      },
      {
        action: 'close',
        title: 'Close',
        icon: '/icon-close.png'
      }
    ]
  };
  
  event.waitUntil(
    self.registration.showNotification('CyberSage 2.0', options)
  );
});

// Notification click handler
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  
  if (event.action === 'view') {
    event.waitUntil(
      clients.openWindow('/')
    );
  }
});

console.log('Service Worker: Registered successfully');
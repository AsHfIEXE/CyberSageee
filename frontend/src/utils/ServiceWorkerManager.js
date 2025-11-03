import React from 'react';
// Service Worker registration and management
export class ServiceWorkerManager {
  constructor() {
    this.registration = null;
    this.isSupported = 'serviceWorker' in navigator;
    this.updateAvailable = false;
  }

  async register() {
    if (!this.isSupported) {
      console.log('Service Worker not supported');
      return false;
    }

    try {
      this.registration = await navigator.serviceWorker.register('/sw.js', {
        scope: '/'
      });

      console.log('Service Worker registered successfully:', this.registration.scope);

      // Handle updates
      this.registration.addEventListener('updatefound', () => {
        const newWorker = this.registration.installing;
        
        newWorker.addEventListener('statechange', () => {
          if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
            this.updateAvailable = true;
            this.notifyUpdateAvailable();
          }
        });
      });

      // Handle messages from service worker
      navigator.serviceWorker.addEventListener('message', (event) => {
        this.handleMessage(event.data);
      });

      return true;
    } catch (error) {
      console.error('Service Worker registration failed:', error);
      return false;
    }
  }

  async unregister() {
    if (this.registration) {
      const result = await this.registration.unregister();
      console.log('Service Worker unregistered:', result);
      return result;
    }
    return false;
  }

  async update() {
    if (this.registration) {
      await this.registration.update();
    }
  }

  async getVersion() {
    if (this.registration) {
      return new Promise((resolve) => {
        const messageChannel = new MessageChannel();
        messageChannel.port1.onmessage = (event) => {
          resolve(event.data.version);
        };
        this.registration.active?.postMessage(
          { type: 'GET_VERSION' },
          [messageChannel.port2]
        );
      });
    }
    return null;
  }

  notifyUpdateAvailable() {
    // Emit custom event for update notification
    window.dispatchEvent(new CustomEvent('serviceWorkerUpdateAvailable'));
  }

  handleMessage(data) {
    switch (data.type) {
      case 'UPDATE_AVAILABLE':
        this.updateAvailable = true;
        this.notifyUpdateAvailable();
        break;
        
      case 'CACHE_UPDATED':
        console.log('Cache updated:', data.cacheName);
        break;
        
      case 'OFFLINE_STATUS':
        console.log('Offline status changed:', data.isOffline);
        window.dispatchEvent(new CustomEvent('offlineStatusChanged', {
          detail: { isOffline: data.isOffline }
        }));
        break;
    }
  }

  // Request background sync
  async requestBackgroundSync(tag) {
    if (this.registration && 'sync' in this.registration) {
      try {
        await this.registration.sync.register(tag);
        console.log('Background sync registered:', tag);
      } catch (error) {
        console.error('Background sync registration failed:', error);
      }
    }
  }

  // Show notification
  async showNotification(title, options) {
    if (this.registration && 'showNotification' in this.registration) {
      try {
        await this.registration.showNotification(title, options);
      } catch (error) {
        console.error('Notification show failed:', error);
      }
    }
  }

  // Clear all caches
  async clearCaches() {
    if (this.registration) {
      return new Promise((resolve) => {
        const messageChannel = new MessageChannel();
        messageChannel.port1.onmessage = (event) => {
          resolve(event.data);
        };
        this.registration.active?.postMessage(
          { type: 'CLEAR_CACHE' },
          [messageChannel.port2]
        );
      });
    }
  }
}

// Singleton instance
export const serviceWorkerManager = new ServiceWorkerManager();

// React hook for service worker
export const useServiceWorker = () => {
  const [isRegistered, setIsRegistered] = React.useState(false);
  const [updateAvailable, setUpdateAvailable] = React.useState(false);
  const [isOffline, setIsOffline] = React.useState(!navigator.onLine);

  React.useEffect(() => {
    // Register service worker
    serviceWorkerManager.register().then(setIsRegistered);

    // Listen for update available
    const handleUpdateAvailable = () => setUpdateAvailable(true);
    window.addEventListener('serviceWorkerUpdateAvailable', handleUpdateAvailable);

    // Listen for offline status changes
    const handleOfflineChange = (event) => setIsOffline(event.detail.isOffline);
    window.addEventListener('offlineStatusChanged', handleOfflineChange);

    // Monitor online/offline status
    const handleOnline = () => setIsOffline(false);
    const handleOffline = () => setIsOffline(true);
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('serviceWorkerUpdateAvailable', handleUpdateAvailable);
      window.removeEventListener('offlineStatusChanged', handleOfflineChange);
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  const updateServiceWorker = React.useCallback(async () => {
    await serviceWorkerManager.update();
    window.location.reload();
  }, []);

  return {
    isRegistered,
    updateAvailable,
    isOffline,
    updateServiceWorker,
    serviceWorkerManager
  };
};

// Performance-optimized bundle loader
export const loadBundle = (bundleName) => {
  return React.lazy(() => import(`../pages/${bundleName}`));
};

// Lazy-loaded pages for code splitting
export const LazyEnhancedDashboardPage = loadBundle('EnhancedDashboardPage');
export const LazyEnhancedVulnerabilitiesPage = loadBundle('EnhancedVulnerabilitiesPage');
export const LazyEnhancedScannerPage = loadBundle('EnhancedScannerPage');
export const LazyEnhancedHistoryPage = loadBundle('EnhancedHistoryPage');
export const LazyEnhancedToolsPage = loadBundle('EnhancedToolsPage');
export const LazyEnhancedChainsPage = loadBundle('EnhancedChainsPage');
export const LazyEnhancedStatisticsPage = loadBundle('EnhancedStatisticsPage');
export const LazyEnhancedBlueprintPage = loadBundle('EnhancedBlueprintPage');
export const LazyEnhancedRepeaterPage = loadBundle('EnhancedRepeaterPage');

// Optimized loading component
export const LazyLoadingFallback = ({ message = 'Loading...' }) => (
  <div className="flex items-center justify-center min-h-screen">
    <div className="text-center">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
      <p className="text-gray-600 dark:text-gray-400">{message}</p>
    </div>
  </div>
);

// Error boundary for lazy loading
export class LazyLoadErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Lazy loading error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex items-center justify-center min-h-screen">
          <div className="text-center">
            <div className="w-12 h-12 mx-auto mb-4 text-red-500">
              <svg fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
            </div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
              Loading Error
            </h2>
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              There was an error loading this component. Please try refreshing the page.
            </p>
            <button
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary/90 transition-colors"
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// Preload critical components
export const preloadComponent = (componentName) => {
  const components = {
    EnhancedDashboardPage: () => import('../pages/EnhancedDashboardPage'),
    EnhancedVulnerabilitiesPage: () => import('../pages/EnhancedVulnerabilitiesPage'),
    EnhancedScannerPage: () => import('../pages/EnhancedScannerPage')
  };

  if (components[componentName]) {
    components[componentName]();
  }
};

// Router with code splitting
export const createOptimizedRouter = () => {
  return {
    routes: {
      dashboard: LazyEnhancedDashboardPage,
      vulnerabilities: LazyEnhancedVulnerabilitiesPage,
      scanner: LazyEnhancedScannerPage,
      history: LazyEnhancedHistoryPage,
      tools: LazyEnhancedToolsPage,
      chains: LazyEnhancedChainsPage,
      statistics: LazyEnhancedStatisticsPage,
      blueprint: LazyEnhancedBlueprintPage,
      repeater: LazyEnhancedRepeaterPage
    },

    getComponent: (routeName) => {
      const Component = LazyLoadErrorBoundary(
        { children: React.createElement(LazyLoadingFallback, { message: `Loading ${routeName}...` }) }
      );

      const LazyComponent = React.lazy(() => 
        import(`../pages/Enhanced${routeName.charAt(0).toUpperCase() + routeName.slice(1)}Page`)
      );

      return (props) => (
        <LazyLoadErrorBoundary>
          <React.Suspense fallback={<LazyLoadingFallback message={`Loading ${routeName}...`} />}>
            <LazyComponent {...props} />
          </React.Suspense>
        </LazyLoadErrorBoundary>
      );
    }
  };
};

export default serviceWorkerManager;
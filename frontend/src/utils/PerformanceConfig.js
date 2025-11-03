// Performance optimization configuration
export const PERFORMANCE_CONFIG = {
  // Virtual list settings
  virtualList: {
    itemHeight: 80,
    overscanCount: 5,
    enableInfiniteScroll: true,
    maxItems: 10000
  },

  // Debounce settings
  debounce: {
    search: 300,
    filter: 500,
    scroll: 16
  },

  // Memory management
  memory: {
    maxVulnerabilities: 5000,
    maxScanHistory: 1000,
    cleanupInterval: 60000 // 1 minute
  },

  // Cache settings
  cache: {
    apiCacheTimeout: 300000, // 5 minutes
    staticCacheTimeout: 86400000, // 24 hours
    maxCacheSize: 50 * 1024 * 1024 // 50MB
  },

  // Performance monitoring thresholds
  thresholds: {
    renderTime: 16, // 60fps
    memoryUsage: 50 * 1024 * 1024, // 50MB
    bundleSize: 150 * 1024, // 150KB
    loadTime: 2000 // 2 seconds
  },

  // Feature flags
  features: {
    virtualScrolling: true,
    serviceWorker: true,
    performanceMonitoring: true,
    codeSplitting: true,
    lazyLoading: true,
    offlineSupport: true
  }
};

// Bundle analyzer configuration
export const BUNDLE_CONFIG = {
  // Code splitting strategy
  codeSplitting: {
    pages: [
      'EnhancedDashboardPage',
      'EnhancedVulnerabilitiesPage',
      'EnhancedScannerPage',
      'EnhancedHistoryPage',
      'EnhancedToolsPage',
      'EnhancedChainsPage',
      'EnhancedStatisticsPage',
      'EnhancedBlueprintPage',
      'EnhancedRepeaterPage'
    ],
    components: [
      'VirtualizedLists',
      'OptimizedComponents',
      'EnhancedModal'
    ],
    libraries: [
      'recharts',
      'react-window',
      'web-vitals'
    ]
  },

  // Tree shaking optimization
  treeShaking: {
    enabled: true,
    removeDebugCode: true,
    minifyClassNames: true
  },

  // Compression settings
  compression: {
    gzip: true,
    brotli: true,
    level: 6
  }
};

// Performance targets
export const PERFORMANCE_TARGETS = {
  // Bundle size targets (gzipped)
  bundle: {
    initial: '100kb', // Target for initial bundle
    total: '150kb',   // Target for total bundle size
    components: '20kb' // Target for individual component bundles
  },

  // Performance metrics
  metrics: {
    FCP: 1800,    // First Contentful Paint (ms)
    LCP: 2500,    // Largest Contentful Paint (ms)
    FID: 100,     // First Input Delay (ms)
    CLS: 0.1,     // Cumulative Layout Shift
    TTI: 3000     // Time to Interactive (ms)
  },

  // Runtime performance
  runtime: {
    renderTime: 16,      // 60fps target
    memoryUsage: 50,     // MB
    scrollPerformance: 60, // FPS
    responseTime: 200    // ms for API calls
  }
};

// Optimization strategies
export const OPTIMIZATION_STRATEGIES = {
  // React optimizations
  react: {
    useMemo: true,
    useCallback: true,
    React.memo: true,
    useLayoutEffect: true,
    useDeferredValue: true
  },

  // Bundle optimizations
  bundle: {
    dynamicImports: true,
    lazyLoading: true,
    treeShaking: true,
    deadCodeElimination: true
  },

  // Network optimizations
  network: {
    serviceWorker: true,
    caching: true,
    compression: true,
    preloading: true
  },

  // Rendering optimizations
  rendering: {
    virtualScrolling: true,
    offscreenRendering: true,
    hardwareAcceleration: true,
    willChange: true
  }
};

// Development vs Production settings
export const getPerformanceConfig = () => {
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  return {
    ...PERFORMANCE_CONFIG,
    debug: isDevelopment,
    monitoring: {
      enabled: true,
      interval: isDevelopment ? 1000 : 60000,
      retention: isDevelopment ? 1000 : 10000
    }
  };
};

export default PERFORMANCE_CONFIG;
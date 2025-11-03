// Performance monitoring and optimization utilities
import React from 'react';
import { getCLS, getFID, getFCP, getLCP, getTTFB } from 'web-vitals';

class PerformanceMonitor {
  constructor() {
    this.metrics = {};
    this.observers = new Map();
    this.isInitialized = false;
  }

  init() {
    if (this.isInitialized) return;
    this.isInitialized = true;

    // Core Web Vitals
    getCLS(this.onMetric.bind(this));
    getFID(this.onMetric.bind(this));
    getFCP(this.onMetric.bind(this));
    getLCP(this.onMetric.bind(this));
    getTTFB(this.onMetric.bind(this));

    // Performance Observer for additional metrics
    if ('PerformanceObserver' in window) {
      this.initPerformanceObserver();
    }

    // Custom performance marks
    this.setupPerformanceMarks();
  }

  initPerformanceObserver() {
    // Navigation Timing
    if ('PerformanceObserver' in window) {
      const navObserver = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        entries.forEach((entry) => {
          if (entry.entryType === 'navigation') {
            this.recordMetric('navigation', {
              domContentLoaded: entry.domContentLoadedEventEnd - entry.domContentLoadedEventStart,
              loadComplete: entry.loadEventEnd - entry.loadEventStart,
              timeToInteractive: entry.domInteractive - entry.navigationStart,
              firstByte: entry.responseStart - entry.requestStart,
            });
          }
        });
      });
      navObserver.observe({ entryTypes: ['navigation'] });
      this.observers.set('navigation', navObserver);
    }

    // Resource Timing
    if ('PerformanceObserver' in window) {
      const resourceObserver = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        const resources = entries.reduce((acc, entry) => {
          const duration = entry.responseEnd - entry.startTime;
          const resourceType = entry.initiatorType || 'unknown';
          
          if (!acc[resourceType]) {
            acc[resourceType] = { count: 0, totalDuration: 0, avgDuration: 0 };
          }
          
          acc[resourceType].count++;
          acc[resourceType].totalDuration += duration;
          acc[resourceType].avgDuration = acc[resourceType].totalDuration / acc[resourceType].count;
          
          return acc;
        }, {});

        this.recordMetric('resources', resources);
      });
      resourceObserver.observe({ entryTypes: ['resource'] });
      this.observers.set('resources', resourceObserver);
    }
  }

  setupPerformanceMarks() {
    // React rendering performance
    if (window.performance && window.performance.mark) {
      window.performance.mark('app-start');
    }
  }

  onMetric({ name, value, delta, id }) {
    this.recordMetric(name, { value, delta, id, timestamp: Date.now() });
    
    // Log significant performance issues
    if (this.shouldAlert(name, value)) {
      console.warn(`Performance issue detected: ${name} = ${value}ms`);
    }
  }

  shouldAlert(metric, value) {
    const thresholds = {
      'CLS': 0.1,      // Cumulative Layout Shift
      'FID': 100,      // First Input Delay
      'FCP': 1800,     // First Contentful Paint
      'LCP': 2500,     // Largest Contentful Paint
      'TTFB': 800,     // Time to First Byte
    };

    return value > (thresholds[metric] || Infinity);
  }

  recordMetric(name, data) {
    this.metrics[name] = {
      ...this.metrics[name],
      ...data,
      lastUpdated: Date.now(),
    };
  }

  // Performance marks for custom measurements
  markStart(label) {
    if (window.performance && window.performance.mark) {
      window.performance.mark(`${label}-start`);
    }
  }

  markEnd(label) {
    if (window.performance && window.performance.mark) {
      window.performance.mark(`${label}-end`);
      window.performance.measure(label, `${label}-start`, `${label}-end`);
    }
  }

  // Get performance data
  getMetrics() {
    return { ...this.metrics };
  }

  getMetric(name) {
    return this.metrics[name];
  }

  // Clean up observers
  destroy() {
    this.observers.forEach((observer) => observer.disconnect());
    this.observers.clear();
  }
}

// Singleton instance
export const performanceMonitor = new PerformanceMonitor();

// React hooks for performance monitoring
export const usePerformanceMonitor = (componentName) => {
  React.useEffect(() => {
    performanceMonitor.init();
    performanceMonitor.markStart(`component-${componentName}`);

    return () => {
      performanceMonitor.markEnd(`component-${componentName}`);
    };
  }, [componentName]);

  return {
    markStart: performanceMonitor.markStart.bind(performanceMonitor),
    markEnd: performanceMonitor.markEnd.bind(performanceMonitor),
    getMetrics: performanceMonitor.getMetrics.bind(performanceMonitor),
  };
};

// High-order component for performance tracking
export const withPerformanceTracking = (WrappedComponent, componentName) => {
  const TrackedComponent = (props) => {
    const { markStart, markEnd } = usePerformanceMonitor(componentName);

    React.useEffect(() => {
      markStart('render');
      markEnd('render');
    }, [markStart, markEnd]);

    return <WrappedComponent {...props} />;
  };

  TrackedComponent.displayName = `withPerformanceTracking(${componentName})`;
  return React.memo(TrackedComponent);
};

// Performance optimization utilities
export const debounce = (func, delay) => {
  let timeoutId;
  return (...args) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => func.apply(null, args), delay);
  };
};

export const throttle = (func, delay) => {
  let lastCall = 0;
  return (...args) => {
    const now = new Date().getTime();
    if (now - lastCall < delay) {
      return;
    }
    lastCall = now;
    return func(...args);
  };
};

// Memory usage monitoring
export const getMemoryUsage = () => {
  if ('memory' in performance) {
    return {
      used: performance.memory.usedJSHeapSize,
      total: performance.memory.totalJSHeapSize,
      limit: performance.memory.jsHeapSizeLimit,
    };
  }
  return null;
};

// Bundle size monitoring
export const analyzeBundleSize = () => {
  const scripts = Array.from(document.querySelectorAll('script[src]'));
  const stylesheets = Array.from(document.querySelectorAll('link[rel="stylesheet"]'));
  
  return {
    scripts: scripts.length,
    stylesheets: stylesheets.length,
    totalAssets: scripts.length + stylesheets.length,
  };
};

export default performanceMonitor;
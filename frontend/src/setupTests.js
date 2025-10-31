import '@testing-library/jest-dom';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React from 'react';
import { BrowserRouter } from 'react-router-dom';

// Mock Intersection Observer
global.IntersectionObserver = class IntersectionObserver {
  constructor() {}
  observe() { return null; }
  disconnect() { return null; }
  unobserve() { return null; }
};

// Mock Resize Observer
global.ResizeObserver = class ResizeObserver {
  constructor() {}
  observe() { return null; }
  disconnect() { return null; }
  unobserve() { return null; }
};

// Mock performance observer
global.PerformanceObserver = class PerformanceObserver {
  constructor() {}
  observe() { return null; }
  disconnect() { return null; }
};

// Mock WebSocket
global.WebSocket = class WebSocket {
  constructor() {
    this.readyState = 0;
    this.onopen = null;
    this.onmessage = null;
    this.onerror = null;
    this.onclose = null;
    this.send = jest.fn();
    this.close = jest.fn();
  }
};

// Mock navigator
global.navigator = {
  ...global.navigator,
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
  onLine: true,
  doNotTrack: false,
  cookieEnabled: true,
  serviceWorker: {
    getRegistrations: jest.fn().mockResolvedValue([]),
    register: jest.fn().mockResolvedValue({ scope: '/' })
  }
};

// Mock window.matchMedia
global.matchMedia = jest.fn().mockImplementation(query => ({
  matches: false,
  media: query,
  onchange: null,
  addListener: jest.fn(), // deprecated
  removeListener: jest.fn(), // deprecated
  addEventListener: jest.fn(),
  removeEventListener: jest.fn(),
  dispatchEvent: jest.fn(),
}));

// Mock localStorage
const localStorageMock = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
};
global.localStorage = localStorageMock;

// Mock sessionStorage
const sessionStorageMock = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
};
global.sessionStorage = sessionStorageMock;

// Mock fetch
global.fetch = jest.fn();

// Mock console methods to reduce noise in tests
global.console = {
  ...console,
  warn: jest.fn(),
  error: jest.fn(),
  log: jest.fn(),
};

// Setup and teardown helpers
export const renderWithRouter = (component) => {
  return render(
    <BrowserRouter>
      {component}
    </BrowserRouter>
  );
};

export const renderWithProviders = (component, options = {}) => {
  const { initialEntries = ['/'] } = options;
  
  return render(
    <BrowserRouter initialEntries={initialEntries}>
      {component}
    </BrowserRouter>
  );
};

// Mock data for tests
export const mockVulnerability = {
  id: 1,
  title: 'Test Vulnerability',
  severity: 'critical',
  description: 'A test vulnerability for testing purposes',
  cve_id: 'CVE-2024-TEST',
  cvss_score: 9.8,
  timestamp: '2025-10-31T10:00:00Z'
};

export const mockVulnerabilityList = Array.from({ length: 10 }, (_, i) => ({
  ...mockVulnerability,
  id: i + 1,
  title: `Test Vulnerability ${i + 1}`,
  severity: ['critical', 'high', 'medium', 'low'][i % 4]
}));

export const mockStats = {
  critical: 2,
  high: 3,
  medium: 4,
  low: 1,
  total: 10
};

// Async utilities
export const waitForLoadingToComplete = async () => {
  await waitFor(() => {
    const loadingElements = screen.queryAllByText(/loading|spinner/i);
    expect(loadingElements).toHaveLength(0);
  });
};

// Accessibility testing utilities
export const testA11y = (component, options = {}) => {
  const { includeDequeue = true } = options;
  const { axe, toHaveNoViolations } = require('jest-axe');
  expect.extend(toHaveNoViolations);
  
  return axe(component, {
    includeDequeue,
    ...options
  });
};

// Form testing utilities
export const fillForm = async (form, fields) => {
  const user = userEvent.setup();
  
  for (const [field, value] of Object.entries(fields)) {
    const element = form.querySelector(`[name="${field}"], #${field}`);
    if (element) {
      if (element.tagName === 'SELECT') {
        await user.selectOptions(element, value);
      } else if (element.type === 'checkbox' || element.type === 'radio') {
        if (value) {
          await user.click(element);
        }
      } else {
        await user.type(element, value);
      }
    }
  }
};

// Button testing utilities
export const clickButton = async (button) => {
  const user = userEvent.setup();
  await user.click(button);
};

export const doubleClickButton = async (button) => {
  const user = userEvent.setup();
  await user.dblClick(button);
};

// Modal testing utilities
export const testModal = async (modalElement, actions = []) => {
  expect(modalElement).toBeInTheDocument();
  
  // Test focus management
  const firstFocusable = modalElement.querySelector('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
  if (firstFocusable) {
    expect(firstFocusable).toHaveFocus();
  }
  
  // Test ESC key to close
  fireEvent.keyDown(modalElement, { key: 'Escape', code: 'Escape' });
  expect(modalElement).not.toBeInTheDocument();
  
  // Test overlay click to close
  fireEvent.click(modalElement);
  expect(modalElement).toBeInTheDocument();
  
  // Test specific actions
  for (const action of actions) {
    const button = modalElement.querySelector(`[data-testid="${action}"], button:contains("${action}")`);
    if (button) {
      await clickButton(button);
    }
  }
};

// Responsive testing utilities
export const testResponsiveBehavior = (Component, viewports = [
  { width: 320, height: 568, name: 'mobile' },
  { width: 768, height: 1024, name: 'tablet' },
  { width: 1280, height: 720, name: 'desktop' }
]) => {
  viewports.forEach(({ width, height, name }) => {
    test(`renders correctly on ${name} (${width}x${height})`, () => {
      global.innerWidth = width;
      global.innerHeight = height;
      
      const { container } = render(<Component />);
      expect(container.firstChild).toBeInTheDocument();
    });
  });
};

// Theme testing utilities
export const testThemeToggle = async (themeToggle) => {
  const user = userEvent.setup();
  
  // Test initial state
  expect(themeToggle).toBeInTheDocument();
  
  // Test toggle functionality
  await user.click(themeToggle);
  
  // Verify theme change
  const htmlElement = document.documentElement;
  expect(htmlElement.className).toContain('dark').or.toContain('light');
  
  // Test toggle back
  await user.click(themeToggle);
  expect(htmlElement.className).toBeTruthy();
};

// WebSocket testing utilities
export const mockWebSocketConnection = (status = 'connected') => {
  const mockWs = {
    readyState: status === 'connected' ? 1 : 3,
    onopen: jest.fn(),
    onmessage: jest.fn(),
    onerror: jest.fn(),
    onclose: jest.fn(),
    send: jest.fn(),
    close: jest.fn()
  };
  
  global.WebSocket = jest.fn(() => mockWs);
  return mockWs;
};

// API testing utilities
export const mockApiResponse = (endpoint, data, delay = 0) => {
  global.fetch = jest.fn(() =>
    new Promise(resolve => {
      setTimeout(() => {
        resolve({
          ok: true,
          json: () => Promise.resolve(data)
        });
      }, delay);
    })
  );
};

export const mockApiError = (endpoint, error = 'Network Error', status = 500) => {
  global.fetch = jest.fn(() =>
    Promise.resolve({
      ok: false,
      status,
      json: () => Promise.resolve({ error })
    })
  );
};

// Error boundary testing utilities
export const testErrorBoundary = (Component, error) => {
  const ThrowError = () => {
    throw error;
  };
  
  const { container } = render(
    <ErrorBoundary>
      <Component />
      <ThrowError />
    </ErrorBoundary>
  );
  
  expect(container.querySelector('.error-boundary')).toBeInTheDocument();
};

// Performance testing utilities
export const measureRenderPerformance = (Component) => {
  const start = performance.now();
  render(<Component />);
  const end = performance.now();
  
  const renderTime = end - start;
  expect(renderTime).toBeLessThan(16); // Should render in less than 1 frame
  
  return renderTime;
};

// Memory leak testing utilities
export const testMemoryLeaks = (Component) => {
  const { unmount } = render(<Component />);
  const beforeMemory = performance.memory ? performance.memory.usedJSHeapSize : 0;
  
  unmount();
  
  // Force garbage collection if available
  if (global.gc) {
    global.gc();
  }
  
  const afterMemory = performance.memory ? performance.memory.usedJSHeapSize : 0;
  const memoryDiff = afterMemory - beforeMemory;
  
  // Memory should not increase significantly
  expect(Math.abs(memoryDiff)).toBeLessThan(1024 * 1024); // 1MB threshold
};

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithRouter, mockVulnerability, testA11y } from '../../setupTests';
import { useScan } from '../../context/EnhancedScanContext';
import { SCAN_STATUS } from '../../utils/constants';

// Mock the context
jest.mock('../../context/EnhancedScanContext', () => ({
  useScan: jest.fn()
}));

// Mock the constants
jest.mock('../../utils/constants', () => ({
  SCAN_STATUS: {
    IDLE: 'idle',
    RUNNING: 'running',
    COMPLETED: 'completed',
    ERROR: 'error'
  }
}));

// Mock performance utilities
jest.mock('../../utils/PerformanceMonitor', () => ({
  usePerformanceMonitor: jest.fn(() => ({
    trackMetric: jest.fn()
  })),
  debounce: jest.fn((fn) => fn)
}));

// Import component to test
const EnhancedDashboardPage = React.lazy(() => import('../../pages/EnhancedDashboardPage'));

describe('EnhancedDashboardPage', () => {
  const mockUseScan = {
    vulnerabilities: [
      {
        id: 1,
        title: 'Test Vulnerability',
        severity: 'critical',
        description: 'Test description'
      }
    ],
    stats: {
      critical: 2,
      high: 3,
      medium: 4,
      low: 1,
      total: 10
    },
    scanStatus: SCAN_STATUS.COMPLETED,
    progress: 0,
    connected: true,
    scanHistory: [],
    toolActivity: [],
    aiInsights: [],
    chains: []
  };

  beforeEach(() => {
    useScan.mockReturnValue(mockUseScan);
    jest.clearAllMocks();
  });

  test('renders dashboard components', () => {
    renderWithRouter(<EnhancedDashboardPage />);

    expect(screen.getByText('Security Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Real-Time Monitoring')).toBeInTheDocument();
  });

  test('displays vulnerability statistics', () => {
    renderWithRouter(<EnhancedDashboardPage />);

    expect(screen.getByTestId('stats-card')).toBeInTheDocument();
    expect(screen.getByTestId('chart')).toBeInTheDocument();
  });

  test('shows connection status', () => {
    renderWithRouter(<EnhancedDashboardPage />);

    expect(screen.getByTestId('connection-status')).toBeInTheDocument();
  });

  test('handles theme toggle', () => {
    renderWithRouter(<EnhancedDashboardPage />);

    const themeToggle = screen.getByTestId('theme-toggle');
    fireEvent.click(themeToggle);

    expect(document.documentElement.className).toContain('dark');
  });

  test('displays real-time updates', () => {
    useScan.mockReturnValue({
      ...mockUseScan,
      connected: true
    });

    renderWithRouter(<EnhancedDashboardPage />);

    expect(screen.getByText(/connected/i)).toBeInTheDocument();
  });

  test('shows offline indicator when disconnected', () => {
    useScan.mockReturnValue({
      ...mockUseScan,
      connected: false
    });

    renderWithRouter(<EnhancedDashboardPage />);

    expect(screen.getByText(/disconnected/i)).toBeInTheDocument();
  });
});

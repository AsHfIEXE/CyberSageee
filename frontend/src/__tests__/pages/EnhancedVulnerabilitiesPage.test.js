import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithRouter, mockVulnerability, mockStats } from '../../setupTests';
import { setupUserEvent } from '../userEvent-compat';
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

// Mock components
jest.mock('../../components/VirtualizedLists', () => ({
  VirtualizedVulnerabilityList: ({ vulnerabilities, onItemClick }) => (
    <div data-testid="virtualized-list">
      {vulnerabilities?.map(vuln => (
        <div key={vuln.id} data-testid="vulnerability-item" onClick={() => onItemClick?.(vuln)}>
          {vuln.title}
        </div>
      ))}
    </div>
  )
}));

jest.mock('../../components/OptimizedComponents', () => ({
  OptimizedSearchInput: ({ onChange }) => (
    <input 
      data-testid="search-input" 
      placeholder="Search vulnerabilities..."
      onChange={(e) => onChange?.(e.target.value)}
    />
  ),
  OptimizedStatsCard: ({ title, value }) => (
    <div data-testid="stats-card">
      <span>{title}</span>
      <span data-testid="stats-value">{value}</span>
    </div>
  ),
  OptimizedChart: () => (
    <div data-testid="chart">
      <canvas />
    </div>
  )
}));

// Mock theme components
jest.mock('../../components/ThemeComponents', () => ({
  Card: ({ children, className }) => (
    <div data-testid="card" className={className}>
      {children}
    </div>
  ),
  Badge: ({ children, variant }) => (
    <span data-testid="badge" data-variant={variant}>
      {children}
    </span>
  ),
  Button: ({ children, onClick, variant, size }) => (
    <button 
      data-testid="button" 
      data-variant={variant} 
      data-size={size}
      onClick={onClick}
    >
      {children}
    </button>
  ),
  PageTransition: ({ children }) => (
    <div data-testid="page-transition">
      {children}
    </div>
  ),
  DetailModal: ({ isOpen, onClose, title, data }) => {
    if (!isOpen) return null;
    return (
      <div data-testid="detail-modal" role="dialog" aria-labelledby="modal-title">
        <h2 id="modal-title">{title}</h2>
        <div data-testid="modal-content">{JSON.stringify(data)}</div>
        <button data-testid="close-modal" onClick={onClose}>Close</button>
      </div>
    );
  }
}));

// Mock loading skeletons
jest.mock('../../components/EnhancedLoadingSkeletons', () => ({
  VulnerabilitiesSkeleton: () => (
    <div data-testid="vulnerabilities-skeleton">
      <div className="animate-pulse bg-gray-300 h-4 rounded w-3/4 mb-4"></div>
      <div className="animate-pulse bg-gray-300 h-4 rounded w-1/2 mb-4"></div>
    </div>
  ),
  SectionLoading: () => (
    <div data-testid="section-loading" className="animate-pulse">
      Loading...
    </div>
  )
}));

// Mock performance monitor
jest.mock('../../utils/PerformanceMonitor', () => ({
  usePerformanceMonitor: jest.fn(() => ({
    trackMetric: jest.fn()
  }))
}));

// Mock chart library
jest.mock('recharts', () => ({
  BarChart: ({ children }) => <div data-testid="bar-chart">{children}</div>,
  Bar: () => <div data-testid="bar" />,
  XAxis: () => <div data-testid="x-axis" />,
  YAxis: () => <div data-testid="y-axis" />,
  CartesianGrid: () => <div data-testid="cartesian-grid" />,
  Tooltip: () => <div data-testid="tooltip" />,
  ResponsiveContainer: ({ children }) => <div data-testid="responsive-container">{children}</div>,
  PieChart: ({ children }) => <div data-testid="pie-chart">{children}</div>,
  Pie: () => <div data-testid="pie" />,
  Cell: () => <div data-testid="cell" />,
  LineChart: ({ children }) => <div data-testid="line-chart">{children}</div>,
  Line: () => <div data-testid="line" />,
  AreaChart: ({ children }) => <div data-testid="area-chart">{children}</div>,
  Area: () => <div data-testid="area" />
}));

// Import the component to test
const EnhancedVulnerabilitiesPage = React.lazy(() => import('../../pages/EnhancedVulnerabilitiesPage'));

describe('EnhancedVulnerabilitiesPage', () => {
  const mockUseScan = {
    vulnerabilities: [],
    stats: mockStats,
    scanStatus: SCAN_STATUS.IDLE,
    progress: 0,
    connected: true
  };

  beforeEach(() => {
    useScan.mockReturnValue(mockUseScan);
    jest.clearAllMocks();
  });

  test('renders loading state when no vulnerabilities and idle', () => {
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities: [],
      scanStatus: SCAN_STATUS.IDLE
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);
    
    expect(screen.getByTestId('vulnerabilities-skeleton')).toBeInTheDocument();
  });

  test('renders vulnerabilities when data is available', async () => {
    const vulnerabilities = [mockVulnerability];
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities,
      scanStatus: SCAN_STATUS.COMPLETED
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    await waitFor(() => {
      expect(screen.getByTestId('vulnerabilities-skeleton')).not.toBeInTheDocument();
    });

    expect(screen.getByText('Vulnerability Analysis')).toBeInTheDocument();
    expect(screen.getByText('Found Vulnerabilities')).toBeInTheDocument();
  });

  test('displays vulnerability statistics', () => {
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities: [mockVulnerability],
      stats: mockStats
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    expect(screen.getByText('Critical')).toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument();
    expect(screen.getByText('Medium')).toBeInTheDocument();
    expect(screen.getByText('Low')).toBeInTheDocument();
  });

  test('handles vulnerability filtering', () => {
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities: [mockVulnerability]
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    const filterButton = screen.getByRole('button', { name: /critical/i });
    fireEvent.click(filterButton);

    // Verify filtering behavior
    expect(filterButton).toHaveAttribute('data-variant', 'primary');
  });

  test('handles sorting functionality', () => {
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities: [mockVulnerability]
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    const sortSelect = screen.getByRole('combobox', { name: /sort/i });
    expect(sortSelect).toBeInTheDocument();

    fireEvent.change(sortSelect, { target: { value: 'timestamp' } });
  });

  test('toggles between grid and list view modes', () => {
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities: [mockVulnerability]
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    const gridButton = screen.getByTestId('button'); // First button (grid view)
    const listButton = screen.getAllByTestId('button')[1]; // Second button (list view)

    // Initially grid view
    expect(gridButton).toHaveAttribute('data-variant', 'primary');

    // Switch to list view
    fireEvent.click(listButton);
    expect(listButton).toHaveAttribute('data-variant', 'primary');

    // Switch back to grid view
    fireEvent.click(gridButton);
  });

  test('opens vulnerability detail modal on item click', async () => {
    const user = setupUserEvent();
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities: [mockVulnerability]
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    await waitFor(() => {
      expect(screen.getByTestId('vulnerability-item')).toBeInTheDocument();
    });

    await user.click(screen.getByTestId('vulnerability-item'));

    await waitFor(() => {
      expect(screen.getByTestId('detail-modal')).toBeInTheDocument();
    });

    expect(screen.getByText('Vulnerability Details')).toBeInTheDocument();
  });

  test('closes modal when close button is clicked', async () => {
    const user = setupUserEvent();
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities: [mockVulnerability]
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    await user.click(screen.getByTestId('vulnerability-item'));
    await waitFor(() => {
      expect(screen.getByTestId('detail-modal')).toBeInTheDocument();
    });

    await user.click(screen.getByTestId('close-modal'));

    await waitFor(() => {
      expect(screen.queryByTestId('detail-modal')).not.toBeInTheDocument();
    });
  });

  test('displays search input and handles search', async () => {
    const user = setupUserEvent();
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities: [mockVulnerability]
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    const searchInput = screen.getByTestId('search-input');
    expect(searchInput).toBeInTheDocument();

    await user.type(searchInput, 'SQL Injection');
  });

  test('displays charts when data is available', () => {
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities: [mockVulnerability],
      stats: mockStats
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    expect(screen.getByTestId('bar-chart')).toBeInTheDocument();
    expect(screen.getByTestId('pie-chart')).toBeInTheDocument();
    expect(screen.getByTestId('line-chart')).toBeInTheDocument();
  });

  test('handles WebSocket disconnection state', () => {
    useScan.mockReturnValue({
      ...mockUseScan,
      connected: false
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    // Should still render, but might show offline indicator
    expect(screen.getByText('Vulnerability Analysis')).toBeInTheDocument();
  });

  test('handles scan progress display', () => {
    useScan.mockReturnValue({
      ...mockUseScan,
      scanStatus: SCAN_STATUS.RUNNING,
      progress: 50
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    expect(screen.getByTestId('section-loading')).toBeInTheDocument();
  });

  test('displays no vulnerabilities found state', () => {
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities: [],
      scanStatus: SCAN_STATUS.COMPLETED
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    expect(screen.getByText('No Vulnerabilities Found')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /run new scan/i })).toBeInTheDocument();
  });

  test('handles "Run New Scan" button click', async () => {
    const user = setupUserEvent();
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities: [],
      scanStatus: SCAN_STATUS.COMPLETED
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    const runNewScanButton = screen.getByRole('button', { name: /run new scan/i });
    await user.click(runNewScanButton);

    // Should trigger page reload or scan restart
    expect(window.location.reload).toHaveBeenCalled();
  });

  test('applies responsive design classes', () => {
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities: [mockVulnerability]
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    const card = screen.getByTestId('card');
    expect(card).toHaveClass('hover-glow');
  });

  test('displays vulnerability count', () => {
    const vulnerabilities = [mockVulnerability, { ...mockVulnerability, id: 2 }];
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    expect(screen.getByText('(2 items)')).toBeInTheDocument();
  });

  test('maintains accessibility standards', async () => {
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities: [mockVulnerability]
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    // Check for proper heading structure
    const headings = screen.getAllByRole('heading');
    expect(headings.length).toBeGreaterThan(0);

    // Check for ARIA labels
    const searchInput = screen.getByTestId('search-input');
    expect(searchInput).toHaveAttribute('placeholder');

    // Check for proper button labels
    const buttons = screen.getAllByTestId('button');
    buttons.forEach(button => {
      expect(button).toHaveTextContent();
    });
  });

  test('handles keyboard navigation', async () => {
    const user = setupUserEvent();
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities: [mockVulnerability]
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    // Tab navigation should work
    await user.tab();
    expect(screen.getByTestId('search-input')).toHaveFocus();

    // Enter key on search
    await user.type(screen.getByTestId('search-input'), 'test{enter}');
  });

  test('renders page transition animations', () => {
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities: [mockVulnerability]
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    expect(screen.getByTestId('page-transition')).toBeInTheDocument();
  });

  test('handles export functionality', () => {
    const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
    useScan.mockReturnValue({
      ...mockUseScan,
      vulnerabilities: [mockVulnerability]
    });

    renderWithRouter(<EnhancedVulnerabilitiesPage />);

    const exportButton = screen.getByRole('button', { name: /export/i });
    fireEvent.click(exportButton);

    expect(consoleSpy).toHaveBeenCalledWith('Exporting vulnerability report...');
    
    consoleSpy.mockRestore();
  });
});

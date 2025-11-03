import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithRouter, testA11y } from '../../setupTests';

// Mock Chart.js
jest.mock('react-chartjs-2', () => ({
  Bar: () => <div data-testid="bar-chart" />,
  Doughnut: () => <div data-testid="doughnut-chart" />,
  Line: () => <div data-testid="line-chart" />
}));

jest.mock('chart.js', () => ({
  Chart: {
    register: jest.fn()
  }
}));

// Import component to test
import { OptimizedStatsCard } from '../../components/OptimizedComponents';

describe('OptimizedStatsCard', () => {
  const defaultProps = {
    title: 'Test Stat',
    value: 42,
    icon: 'TestIcon',
    change: 5,
    changeType: 'positive'
  };

  test('renders with basic props', () => {
    render(<OptimizedStatsCard {...defaultProps} />);

    expect(screen.getByText('Test Stat')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
  });

  test('displays change indicator', () => {
    render(<OptimizedStatsCard {...defaultProps} />);

    expect(screen.getByText('+5%')).toBeInTheDocument();
  });

  test('handles negative change', () => {
    const negativeProps = {
      ...defaultProps,
      change: -3,
      changeType: 'negative'
    };

    render(<OptimizedStatsCard {...negativeProps} />);

    expect(screen.getByText('-3%')).toBeInTheDocument();
  });

  test('shows loading state', () => {
    render(<OptimizedStatsCard {...defaultProps} loading />);

    expect(screen.getByTestId('loading-skeleton')).toBeInTheDocument();
  });

  test('has proper accessibility attributes', () => {
    render(<OptimizedStatsCard {...defaultProps} />);

    const card = screen.getByTestId('stats-card');
    expect(card).toHaveAttribute('role');
    expect(card).toHaveAttribute('aria-label');
  });

  test('handles click events', () => {
    const onClick = jest.fn();
    render(<OptimizedStatsCard {...defaultProps} onClick={onClick} />);

    fireEvent.click(screen.getByTestId('stats-card'));
    expect(onClick).toHaveBeenCalled();
  });
});

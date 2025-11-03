// Optimized components with React.memo and performance enhancements
import React, { memo, useMemo, useCallback } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import { usePerformanceMonitor, debounce } from '../utils/PerformanceMonitor';

// Optimized Stats Card with React.memo
export const OptimizedStatsCard = memo(({ 
  title, 
  value, 
  change, 
  trend, 
  icon: Icon, 
  color = 'blue',
  loading = false 
}) => {
  const { markStart, markEnd } = usePerformanceMonitor('StatsCard');

  React.useEffect(() => {
    markStart('render');
    markEnd('render');
  });

  const colorClasses = useMemo(() => ({
    blue: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    green: 'bg-green-500/20 text-green-400 border-green-500/30',
    red: 'bg-red-500/20 text-red-400 border-red-500/30',
    yellow: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    purple: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
    indigo: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30'
  }), []);

  const trendIcon = useMemo(() => {
    if (!change) return null;
    return change > 0 ? '↗' : change < 0 ? '↘' : '→';
  }, [change]);

  const trendColor = useMemo(() => {
    if (!change) return 'text-gray-500';
    return change > 0 ? 'text-green-500' : change < 0 ? 'text-red-500' : 'text-gray-500';
  }, [change]);

  if (loading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6 animate-pulse">
        <div className="flex items-center justify-between mb-4">
          <div className="w-8 h-8 bg-gray-300 dark:bg-gray-600 rounded-lg"></div>
          <div className="w-16 h-6 bg-gray-300 dark:bg-gray-600 rounded"></div>
        </div>
        <div className="space-y-2">
          <div className="w-24 h-8 bg-gray-300 dark:bg-gray-600 rounded"></div>
          <div className="w-20 h-4 bg-gray-300 dark:bg-gray-600 rounded"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm hover:shadow-lg transition-all duration-300 hover:-translate-y-1 border border-gray-200 dark:border-gray-700">
      <div className="p-6">
        <div className="flex items-center justify-between mb-4">
          <div className={`p-2 rounded-lg ${colorClasses[color]}`}>
            {Icon && <Icon className="w-5 h-5" />}
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold text-gray-900 dark:text-white">
              {value}
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400">
              {title}
            </div>
          </div>
        </div>
        
        {change !== undefined && (
          <div className="flex items-center gap-2">
            <span className={`text-sm font-medium ${trendColor}`}>
              {trendIcon} {Math.abs(change)}%
            </span>
            <span className="text-xs text-gray-500 dark:text-gray-400">
              {trend}
            </span>
          </div>
        )}
      </div>
    </div>
  );
});

OptimizedStatsCard.displayName = 'OptimizedStatsCard';

// Optimized Chart Component with performance improvements
export const OptimizedChart = memo(({ 
  data, 
  type = 'line', 
  height = 300, 
  color = '#3B82F6',
  loading = false,
  animate = true
}) => {
  const { markStart, markEnd } = usePerformanceMonitor('Chart');

  React.useEffect(() => {
    markStart('render');
    markEnd('render');
  }, [markStart, markEnd]);

  const chartColors = useMemo(() => [color, '#10B981', '#F59E0B', '#EF4444', '#8B5CF6'], [color]);

  const formatTooltip = useCallback((value, name) => {
    return [value, name];
  }, []);

  if (loading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6" style={{ height }}>
        <div className="animate-pulse">
          <div className="w-32 h-6 bg-gray-300 dark:bg-gray-600 rounded mb-4"></div>
          <div className="w-full h-64 bg-gray-300 dark:bg-gray-600 rounded"></div>
        </div>
      </div>
    );
  }

  if (!data || data.length === 0) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6 flex items-center justify-center" style={{ height }}>
        <div className="text-center text-gray-500 dark:text-gray-400">
          <div className="w-12 h-12 mx-auto mb-2 text-gray-300 dark:text-gray-600">
            <svg fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M3 3a1 1 0 000 2v8a2 2 0 002 2h2.586l-1.293 1.293a1 1 0 101.414 1.414L10 15.414l2.293 2.293a1 1 0 001.414-1.414L12.414 15H15a2 2 0 002-2V5a1 1 0 100-2H3zm11.707 4.707a1 1 0 00-1.414-1.414L10 9.586 8.707 8.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
          </div>
          <p>No data available</p>
        </div>
      </div>
    );
  }

  const renderChart = () => {
    switch (type) {
      case 'bar':
        return (
          <BarChart data={data} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
            <XAxis 
              dataKey="name" 
              stroke="#9CA3AF"
              fontSize={12}
            />
            <YAxis 
              stroke="#9CA3AF"
              fontSize={12}
            />
            <Tooltip 
              formatter={formatTooltip}
              contentStyle={{
                backgroundColor: 'rgba(17, 24, 39, 0.95)',
                border: '1px solid #374151',
                borderRadius: '8px',
                color: '#F9FAFB'
              }}
            />
            <Bar 
              dataKey="value" 
              fill={color}
              radius={[4, 4, 0, 0]}
              animationDuration={animate ? 800 : 0}
            />
          </BarChart>
        );
      
      case 'pie':
        return (
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              outerRadius={80}
              dataKey="value"
              animationDuration={animate ? 800 : 0}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={chartColors[index % chartColors.length]} />
              ))}
            </Pie>
            <Tooltip formatter={formatTooltip} />
          </PieChart>
        );
      
      default: // line chart
        return (
          <LineChart data={data} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
            <XAxis 
              dataKey="name" 
              stroke="#9CA3AF"
              fontSize={12}
            />
            <YAxis 
              stroke="#9CA3AF"
              fontSize={12}
            />
            <Tooltip 
              formatter={formatTooltip}
              contentStyle={{
                backgroundColor: 'rgba(17, 24, 39, 0.95)',
                border: '1px solid #374151',
                borderRadius: '8px',
                color: '#F9FAFB'
              }}
            />
            <Line 
              type="monotone" 
              dataKey="value" 
              stroke={color}
              strokeWidth={2}
              dot={{ fill: color, strokeWidth: 2, r: 4 }}
              activeDot={{ r: 6, stroke: color, strokeWidth: 2 }}
              animationDuration={animate ? 800 : 0}
            />
          </LineChart>
        );
    }
  };

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        {renderChart()}
      </ResponsiveContainer>
    </div>
  );
});

OptimizedChart.displayName = 'OptimizedChart';

// Optimized Modal with performance improvements
export const OptimizedModal = memo(({ 
  isOpen, 
  onClose, 
  title, 
  children, 
  size = 'lg',
  loading = false
}) => {
  const { markStart, markEnd } = usePerformanceMonitor('Modal');

  React.useEffect(() => {
    markStart('render');
    markEnd('render');
  }, [isOpen, markStart, markEnd]);

  React.useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }

    return () => {
      document.body.style.overflow = 'unset';
    };
  }, [isOpen]);

  const sizeClasses = {
    sm: 'max-w-md',
    md: 'max-w-lg',
    lg: 'max-w-2xl',
    xl: 'max-w-4xl',
    '2xl': 'max-w-6xl'
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 animate-fade-in">
      <div 
        className={`bg-white dark:bg-gray-800 rounded-2xl shadow-2xl border border-gray-200 dark:border-gray-700 w-full transform transition-all duration-300 scale-100 translate-y-0 opacity-100 ${sizeClasses[size]}`}
        onClick={(e) => {
          if (e.target === e.currentTarget) {
            onClose();
          }
        }}
      >
        <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-xl font-semibold text-gray-900 dark:text-white">
            {title}
          </h3>
          <button
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors duration-200"
          >
            ×
          </button>
        </div>
        
        <div className="p-6">
          {loading ? (
            <div className="flex items-center justify-center h-32">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
          ) : (
            children
          )}
        </div>
      </div>
    </div>
  );
});

OptimizedModal.displayName = 'OptimizedModal';

// Optimized Search Input with debounced performance
export const OptimizedSearchInput = memo(({ 
  placeholder = 'Search...', 
  onSearch,
  debounceMs = 300,
  className = '',
  ...props
}) => {
  const [searchTerm, setSearchTerm] = React.useState('');

  const debouncedSearch = useMemo(
    () => debounce((term) => onSearch?.(term), debounceMs),
    [onSearch, debounceMs]
  );

  const handleInputChange = useCallback((e) => {
    const value = e.target.value;
    setSearchTerm(value);
    debouncedSearch(value);
  }, [debouncedSearch]);

  return (
    <div className={`relative ${className}`}>
      <svg 
        className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" 
        fill="none" 
        stroke="currentColor" 
        viewBox="0 0 24 24"
      >
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
      </svg>
      <input
        type="text"
        value={searchTerm}
        onChange={handleInputChange}
        placeholder={placeholder}
        className="w-full pl-10 pr-4 py-2 bg-gray-50 dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent transition-all duration-200"
        {...props}
      />
    </div>
  );
});

OptimizedSearchInput.displayName = 'OptimizedSearchInput';

export default {
  OptimizedStatsCard,
  OptimizedChart,
  OptimizedModal,
  OptimizedSearchInput
};
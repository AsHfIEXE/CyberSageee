// Virtualized list components for optimal performance with large datasets
import React, { memo, useMemo, useCallback, useState } from 'react';
import { FixedSizeList as List } from 'react-window';
import AutoSizer from 'react-virtualized-auto-sizer';
import { debounce } from '../utils/PerformanceMonitor';

// Virtualized Vulnerability List
export const VirtualizedVulnerabilityList = memo(({ 
  vulnerabilities = [],
  onItemClick,
  onSelect,
  selectedItems = new Set(),
  filter = '',
  sortBy = 'severity',
  sortOrder = 'desc'
}) => {
  const [scrollTop, setScrollTop] = useState(0);

  // Filter and sort vulnerabilities
  const filteredAndSortedVulnerabilities = useMemo(() => {
    let filtered = vulnerabilities;
    
    // Apply filter
    if (filter) {
      const filterLower = filter.toLowerCase();
      filtered = vulnerabilities.filter(vuln => 
        vuln.title?.toLowerCase().includes(filterLower) ||
        vuln.description?.toLowerCase().includes(filterLower) ||
        vuln.severity?.toLowerCase().includes(filterLower)
      );
    }

    // Apply sorting
    return filtered.sort((a, b) => {
      let aValue = a[sortBy];
      let bValue = b[sortBy];
      
      if (sortBy === 'severity') {
        const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        aValue = severityOrder[a.severity] || 0;
        bValue = severityOrder[b.severity] || 0;
      }
      
      if (sortOrder === 'asc') {
        return aValue > bValue ? 1 : -1;
      }
      return aValue < bValue ? 1 : -1;
    });
  }, [vulnerabilities, filter, sortBy, sortOrder]);

  // Debounced scroll handler
  const debouncedScrollHandler = useCallback(
    debounce((scrollTop) => {
      setScrollTop(scrollTop);
    }, 16),
    []
  );

  // Render individual vulnerability item
  const VulnerabilityItem = memo(({ index, style }) => {
    const vulnerability = filteredAndSortedVulnerabilities[index];
    if (!vulnerability) return null;

    const isSelected = selectedItems.has(vulnerability.id);
    const severityColor = {
      critical: 'bg-red-500/20 text-red-400 border-red-500/30',
      high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      low: 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    }[vulnerability.severity] || 'bg-gray-500/20 text-gray-400 border-gray-500/30';

    return (
      <div 
        style={style}
        className={`
          px-4 py-3 border-b border-gray-200 dark:border-gray-700
          hover:bg-gray-50 dark:hover:bg-gray-800/50
          transition-colors duration-150 cursor-pointer
          ${isSelected ? 'bg-blue-50 dark:bg-blue-900/20' : ''}
        `}
        onClick={() => onItemClick?.(vulnerability)}
      >
        <div className="flex items-start justify-between">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white truncate">
                {vulnerability.title || 'Untitled Vulnerability'}
              </h3>
              <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${severityColor}`}>
                {vulnerability.severity}
              </span>
            </div>
            
            {vulnerability.description && (
              <p className="text-xs text-gray-600 dark:text-gray-400 line-clamp-2 mb-1">
                {vulnerability.description}
              </p>
            )}
            
            <div className="flex items-center gap-4 text-xs text-gray-500 dark:text-gray-400">
              {vulnerability.cve && (
                <span className="font-mono">CVE: {vulnerability.cve}</span>
              )}
              {vulnerability.cvss && (
                <span>CVSS: {vulnerability.cvss}</span>
              )}
              {vulnerability.status && (
                <span className={`px-2 py-0.5 rounded text-xs ${
                  vulnerability.status === 'fixed' 
                    ? 'bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-400'
                    : 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300'
                }`}>
                  {vulnerability.status}
                </span>
              )}
            </div>
          </div>
          
          {onSelect && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                onSelect(vulnerability);
              }}
              className={`
                ml-2 p-1.5 rounded-lg transition-colors duration-150
                ${isSelected 
                  ? 'bg-primary text-white' 
                  : 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400 hover:bg-gray-300 dark:hover:bg-gray-600'
                }
              `}
            >
              <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
              </svg>
            </button>
          )}
        </div>
      </div>
    );
  });

  VulnerabilityItem.displayName = 'VulnerabilityItem';

  if (filteredAndSortedVulnerabilities.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-500 dark:text-gray-400">
        <div className="text-center">
          <div className="w-12 h-12 mx-auto mb-4 text-gray-300 dark:text-gray-600">
            <svg fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
            </svg>
          </div>
          <p>No vulnerabilities found</p>
          <p className="text-sm mt-1">Try adjusting your filters</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full">
      <AutoSizer>
        {({ height, width }) => (
          <List
            height={height}
            width={width}
            itemCount={filteredAndSortedVulnerabilities.length}
            itemSize={80}
            onScroll={({ scrollOffset }) => debouncedScrollHandler(scrollOffset)}
            overscanCount={5}
          >
            {VulnerabilityItem}
          </List>
        )}
      </AutoSizer>
    </div>
  );
});

VirtualizedVulnerabilityList.displayName = 'VirtualizedVulnerabilityList';

// Virtualized Scan History List
export const VirtualizedScanHistoryList = memo(({ 
  scans = [],
  onItemClick,
  onSelect,
  selectedItems = new Set()
}) => {
  const [scrollTop, setScrollTop] = useState(0);

  // Debounced scroll handler
  const debouncedScrollHandler = useCallback(
    debounce((scrollTop) => {
      setScrollTop(scrollTop);
    }, 16),
    []
  );

  // Render individual scan item
  const ScanItem = memo(({ index, style }) => {
    const scan = scans[index];
    if (!scan) return null;

    const isSelected = selectedItems.has(scan.id);
    const statusColors = {
      completed: 'bg-green-500/20 text-green-400 border-green-500/30',
      running: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
      failed: 'bg-red-500/20 text-red-400 border-red-500/30',
      pending: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    };

    return (
      <div 
        style={style}
        className={`
          px-4 py-3 border-b border-gray-200 dark:border-gray-700
          hover:bg-gray-50 dark:hover:bg-gray-800/50
          transition-colors duration-150 cursor-pointer
          ${isSelected ? 'bg-blue-50 dark:bg-blue-900/20' : ''}
        `}
        onClick={() => onItemClick?.(scan)}
      >
        <div className="flex items-start justify-between">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white truncate">
                {scan.name || 'Unnamed Scan'}
              </h3>
              <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${
                statusColors[scan.status] || 'bg-gray-500/20 text-gray-400 border-gray-500/30'
              }`}>
                {scan.status}
              </span>
            </div>
            
            <div className="text-xs text-gray-600 dark:text-gray-400 mb-1">
              Target: {scan.target}
            </div>
            
            <div className="flex items-center gap-4 text-xs text-gray-500 dark:text-gray-400">
              {scan.startTime && (
                <span>{new Date(scan.startTime).toLocaleString()}</span>
              )}
              {scan.vulnerabilities > 0 && (
                <span className="text-red-500">{scan.vulnerabilities} issues</span>
              )}
              {scan.scanId && (
                <span className="font-mono">{scan.scanId}</span>
              )}
            </div>
          </div>
          
          {onSelect && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                onSelect(scan);
              }}
              className={`
                ml-2 p-1.5 rounded-lg transition-colors duration-150
                ${isSelected 
                  ? 'bg-primary text-white' 
                  : 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400 hover:bg-gray-300 dark:hover:bg-gray-600'
                }
              `}
            >
              <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
              </svg>
            </button>
          )}
        </div>
      </div>
    );
  });

  ScanItem.displayName = 'ScanItem';

  if (scans.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-500 dark:text-gray-400">
        <div className="text-center">
          <div className="w-12 h-12 mx-auto mb-4 text-gray-300 dark:text-gray-600">
            <svg fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M3 3a1 1 0 000 2v8a2 2 0 002 2h2.586l-1.293 1.293a1 1 0 101.414 1.414L10 15.414l2.293 2.293a1 1 0 001.414-1.414L12.414 15H15a2 2 0 002-2V5a1 1 0 100-2H3zm11.707 4.707a1 1 0 00-1.414-1.414L10 9.586 8.707 8.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
          </div>
          <p>No scans found</p>
          <p className="text-sm mt-1">Start a scan to see results here</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full">
      <AutoSizer>
        {({ height, width }) => (
          <List
            height={height}
            width={width}
            itemCount={scans.length}
            itemSize={80}
            onScroll={({ scrollOffset }) => debouncedScrollHandler(scrollOffset)}
            overscanCount={5}
          >
            {ScanItem}
          </List>
        )}
      </AutoSizer>
    </div>
  );
});

VirtualizedScanHistoryList.displayName = 'VirtualizedScanHistoryList';

// Virtualized Tool Activity List
export const VirtualizedToolActivityList = memo(({ 
  activities = [],
  onItemClick
}) => {
  const [scrollTop, setScrollTop] = useState(0);

  // Debounced scroll handler
  const debouncedScrollHandler = useCallback(
    debounce((scrollTop) => {
      setScrollTop(scrollTop);
    }, 16),
    []
  );

  // Render individual activity item
  const ActivityItem = memo(({ index, style }) => {
    const activity = activities[index];
    if (!activity) return null;

    const statusColors = {
      completed: 'text-green-400',
      running: 'text-blue-400',
      failed: 'text-red-400',
      pending: 'text-yellow-400'
    };

    const statusBgColors = {
      completed: 'bg-green-500/20',
      running: 'bg-blue-500/20',
      failed: 'bg-red-500/20',
      pending: 'bg-yellow-500/20'
    };

    return (
      <div 
        style={style}
        className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors duration-150"
        onClick={() => onItemClick?.(activity)}
      >
        <div className="flex items-start gap-3">
          <div className={`w-2 h-2 rounded-full mt-2 ${statusBgColors[activity.status]} ${statusColors[activity.status]}`} />
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between mb-1">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                {activity.name || 'Tool Activity'}
              </h3>
              <span className="text-xs text-gray-500 dark:text-gray-400">
                {activity.duration ? `${activity.duration}s` : 'In progress'}
              </span>
            </div>
            
            <div className="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-400">
              <span>{activity.status}</span>
              {activity.timestamp && (
                <>
                  <span>•</span>
                  <span>{new Date(activity.timestamp).toLocaleTimeString()}</span>
                </>
              )}
            </div>
            
            {activity.result && (
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1 line-clamp-2">
                {activity.result}
              </p>
            )}
          </div>
        </div>
      </div>
    );
  });

  ActivityItem.displayName = 'ActivityItem';

  if (activities.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-500 dark:text-gray-400">
        <div className="text-center">
          <div className="w-12 h-12 mx-auto mb-4 text-gray-300 dark:text-gray-600">
            <svg fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-8.707l-3-3a1 1 0 00-1.414 1.414L10.586 9H7a1 1 0 100 2h3.586l-1.293 1.293a1 1 0 101.414 1.414l3-3a1 1 0 000-1.414z" clipRule="evenodd" />
            </svg>
          </div>
          <p>No tool activity</p>
          <p className="text-sm mt-1">Tool activities will appear here</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full">
      <AutoSizer>
        {({ height, width }) => (
          <List
            height={height}
            width={width}
            itemCount={activities.length}
            itemSize={70}
            onScroll={({ scrollOffset }) => debouncedScrollHandler(scrollOffset)}
            overscanCount={5}
          >
            {ActivityItem}
          </List>
        )}
      </AutoSizer>
    </div>
  );
});

VirtualizedToolActivityList.displayName = 'VirtualizedToolActivityList';

export default {
  VirtualizedVulnerabilityList,
  VirtualizedScanHistoryList,
  VirtualizedToolActivityList
};
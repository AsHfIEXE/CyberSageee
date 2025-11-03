// Enhanced Vulnerabilities Page with Virtualized Lists and Performance Optimizations
import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useScan } from '../context/EnhancedScanContext';
import { SCAN_STATUS } from '../utils/constants';
import { usePerformanceMonitor } from '../utils/PerformanceMonitor';
import { VirtualizedVulnerabilityList } from '../components/VirtualizedLists';
import { OptimizedSearchInput, OptimizedStatsCard, OptimizedChart } from '../components/OptimizedComponents';
import { 
  Card, 
  Badge, 
  Button, 
  StatusIndicator,
  PageTransition
} from '../components/ThemeComponents';
import { 
  VulnerabilitiesSkeleton,
  SectionLoading
} from '../components/EnhancedLoadingSkeletons';
import { DetailModal } from '../components/ThemeComponents';

import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  Area,
  AreaChart
} from 'recharts';

const EnhancedVulnerabilitiesPage = () => {
  const { 
    vulnerabilities, 
    stats, 
    scanStatus,
    progress,
    connected 
  } = useScan();

  const [loading, setLoading] = useState(false);
  const [selectedVulnerability, setSelectedVulnerability] = useState(null);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [filter, setFilter] = useState('all');
  const [sortBy, setSortBy] = useState('severity');
  const [viewMode, setViewMode] = useState('grid');

  // Simulate loading state
  useEffect(() => {
    if (vulnerabilities.length === 0 && scanStatus === SCAN_STATUS.IDLE) {
      setLoading(true);
      const timer = setTimeout(() => setLoading(false), 2000);
      return () => clearTimeout(timer);
    }
  }, [vulnerabilities.length, scanStatus]);

  // Filter and sort vulnerabilities
  const filteredVulnerabilities = useMemo(() => {
    let filtered = vulnerabilities;
    
    if (filter !== 'all') {
      filtered = filtered.filter(vuln => vuln.severity === filter);
    }
    
    return filtered.sort((a, b) => {
      if (sortBy === 'severity') {
        const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        return severityOrder[b.severity] - severityOrder[a.severity];
      }
      if (sortBy === 'timestamp') {
        return new Date(b.timestamp) - new Date(a.timestamp);
      }
      if (sortBy === 'title') {
        return a.title.localeCompare(b.title);
      }
      return 0;
    });
  }, [vulnerabilities, filter, sortBy]);

  // Chart data preparation
  const severityDistribution = useMemo(() => {
    return [
      { name: 'Critical', value: stats.critical, color: '#ef4444' },
      { name: 'High', value: stats.high, color: '#f97316' },
      { name: 'Medium', value: stats.medium, color: '#eab308' },
      { name: 'Low', value: stats.low, color: '#3b82f6' }
    ];
  }, [stats]);

  const vulnerabilityTrend = useMemo(() => {
    // Mock trend data - in real app this would come from historical data
    return [
      { date: '2024-01', critical: 12, high: 25, medium: 45, low: 78 },
      { date: '2024-02', critical: 8, high: 20, medium: 38, low: 65 },
      { date: '2024-03', critical: 15, high: 32, medium: 52, low: 82 },
      { date: '2024-04', critical: 5, high: 18, medium: 28, low: 45 },
      { date: '2024-05', critical: 3, high: 12, medium: 22, low: 38 },
      { date: '2024-06', critical: 7, high: 15, medium: 35, low: 52 }
    ];
  }, []);

  // Handle vulnerability actions
  const handleVulnerabilityClick = (vulnerability) => {
    setSelectedVulnerability(vulnerability);
    setShowDetailModal(true);
  };

  const handleExportReport = () => {
    // Mock export functionality
    console.log('Exporting vulnerability report...');
  };

  if (loading) {
    return <VulnerabilitiesSkeleton />;
  }

  const vulnerabilityDetailFields = [
    { label: 'Title', key: 'title' },
    { label: 'Severity', key: 'severity', type: 'badge' },
    { label: 'Description', key: 'description' },
    { label: 'CVE ID', key: 'cve_id' },
    { label: 'CVSS Score', key: 'cvss_score' },
    { label: 'Solution', key: 'solution' },
    { label: 'References', key: 'references', type: 'array' }
  ];

  const severityColors = {
    critical: 'text-red-400 bg-red-500/20 border-red-500/30',
    high: 'text-orange-400 bg-orange-500/20 border-orange-500/30',
    medium: 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30',
    low: 'text-blue-400 bg-blue-500/20 border-blue-500/30'
  };

  return (
    <PageTransition>
      <div className="space-y-8">
        {/* Enhanced Header */}
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 animate-fade-in-down">
          <div>
            <h1 className="text-4xl font-bold text-gradient mb-2">
              Vulnerability Analysis
            </h1>
            <p className="text-gray-400">
              Comprehensive security vulnerability assessment and management
            </p>
          </div>
          
          <div className="flex items-center gap-4">
            {/* Connection Status */}
            <StatusIndicator 
              status={connected ? 'online' : 'offline'} 
              showText={true}
            />
            
            {/* Export Button */}
            <Button 
              variant="primary" 
              icon={
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              }
              onClick={handleExportReport}
            >
              Export Report
            </Button>
          </div>
        </div>

        {/* Vulnerability Overview Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Severity Distribution Pie Chart */}
          <Card className="hover-glow" padding="xl">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-bold text-white">Severity Distribution</h3>
              <Badge variant="primary" size="sm">
                {vulnerabilities.length} Total
              </Badge>
            </div>
            
            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityDistribution}
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    dataKey="value"
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {severityDistribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{
                      background: '#1f2937',
                      border: '1px solid #374151',
                      borderRadius: '8px',
                      color: '#f9fafb'
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </Card>

          {/* Vulnerability Trend Line Chart */}
          <Card className="hover-glow" padding="xl">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-bold text-white">Vulnerability Trends</h3>
              <Badge variant="success" size="sm">
                6 Months
              </Badge>
            </div>
            
            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={vulnerabilityTrend}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="date" stroke="#9ca3af" />
                  <YAxis stroke="#9ca3af" />
                  <Tooltip 
                    contentStyle={{
                      background: '#1f2937',
                      border: '1px solid #374151',
                      borderRadius: '8px',
                      color: '#f9fafb'
                    }}
                  />
                  <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.3} />
                  <Area type="monotone" dataKey="high" stackId="1" stroke="#f97316" fill="#f97316" fillOpacity={0.3} />
                  <Area type="monotone" dataKey="medium" stackId="1" stroke="#eab308" fill="#eab308" fillOpacity={0.3} />
                  <Area type="monotone" dataKey="low" stackId="1" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.3} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </div>

        {/* Filter and Sort Controls */}
        <Card className="hover-glow">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            <div className="flex items-center gap-4">
              {/* Filter Buttons */}
              <div className="flex gap-2">
                {['all', 'critical', 'high', 'medium', 'low'].map((filterOption) => (
                  <Button
                    key={filterOption}
                    variant={filter === filterOption ? 'primary' : 'ghost'}
                    size="sm"
                    onClick={() => setFilter(filterOption)}
                  >
                    {filterOption === 'all' ? 'All' : filterOption.charAt(0).toUpperCase() + filterOption.slice(1)}
                    {filterOption !== 'all' && (
                      <Badge variant={filterOption} size="sm" className="ml-2">
                        {stats[filterOption]}
                      </Badge>
                    )}
                  </Button>
                ))}
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              {/* Sort Dropdown */}
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="input py-2 px-3 bg-gray-800 border-gray-600 text-white rounded-lg text-sm"
              >
                <option value="severity">Sort by Severity</option>
                <option value="timestamp">Sort by Date</option>
                <option value="title">Sort by Title</option>
              </select>
              
              {/* View Mode Toggle */}
              <div className="flex bg-gray-800 rounded-lg p-1">
                <Button
                  variant={viewMode === 'grid' ? 'primary' : 'ghost'}
                  size="sm"
                  onClick={() => setViewMode('grid')}
                  className="px-3"
                >
                  <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M5 3a2 2 0 00-2 2v2a2 2 0 002 2h2a2 2 0 002-2V5a2 2 0 00-2-2H5zM5 11a2 2 0 00-2 2v2a2 2 0 002 2h2a2 2 0 002-2v-2a2 2 0 00-2-2H5zM11 5a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V5zM11 13a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
                  </svg>
                </Button>
                <Button
                  variant={viewMode === 'list' ? 'primary' : 'ghost'}
                  size="sm"
                  onClick={() => setViewMode('list')}
                  className="px-3"
                >
                  <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clipRule="evenodd" />
                  </svg>
                </Button>
              </div>
            </div>
          </div>
        </Card>

        {/* Vulnerabilities List */}
        <Card className="hover-glow">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-xl font-bold text-white">
              Found Vulnerabilities
              <span className="ml-2 text-sm font-normal text-gray-400">
                ({filteredVulnerabilities.length} items)
              </span>
            </h3>
          </div>
          
          {filteredVulnerabilities.length > 0 ? (
            viewMode === 'grid' ? (
              // Virtualized Grid View
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {filteredVulnerabilities.map((vulnerability, index) => (
                  <div 
                    key={index}
                    className="group cursor-pointer transition-all duration-200 hover:scale-[1.02] p-6 bg-gray-800/50 border border-gray-700 rounded-xl hover:border-purple-500/50"
                    onClick={() => handleVulnerabilityClick(vulnerability)}
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center gap-2">
                        <Badge variant={vulnerability.severity} size="sm">
                          {vulnerability.severity}
                        </Badge>
                        {vulnerability.cve_id && (
                          <span className="text-xs text-gray-400 font-mono">
                            {vulnerability.cve_id}
                          </span>
                        )}
                      </div>
                      <div className={`w-3 h-3 rounded-full ${
                        vulnerability.severity === 'critical' ? 'bg-red-500 animate-pulse' :
                        vulnerability.severity === 'high' ? 'bg-orange-500' :
                        vulnerability.severity === 'medium' ? 'bg-yellow-500' :
                        'bg-blue-500'
                      }`} />
                    </div>
                    
                    <h4 className="font-semibold text-white group-hover:text-purple-400 transition-colors mb-2">
                      {vulnerability.title}
                    </h4>
                    <p className="text-sm text-gray-400 mb-3 line-clamp-2">
                      {vulnerability.description}
                    </p>
                    
                    <div className="flex items-center justify-between">
                      <div className="text-xs text-gray-500">
                        {new Date(vulnerability.timestamp).toLocaleDateString()}
                      </div>
                      {vulnerability.cvss_score && (
                        <Badge variant="info" size="sm">
                          CVSS: {vulnerability.cvss_score}
                        </Badge>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              // Virtualized List View
              <div className="h-[600px]">
                <VirtualizedVulnerabilityList
                  vulnerabilities={filteredVulnerabilities}
                  onItemClick={handleVulnerabilityClick}
                  filter={filter}
                  sortBy={sortBy}
                  selectedItems={new Set()}
                />
              </div>
            )
          ) : (
            <div className="text-center py-16">
              <div className="w-20 h-20 mx-auto mb-6 p-5 bg-gray-800 rounded-full">
                <svg className="w-10 h-10 text-gray-400 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <h3 className="text-xl font-semibold text-gray-300 mb-2">No Vulnerabilities Found</h3>
              <p className="text-gray-400 mb-6">Your security scan has not identified any vulnerabilities.</p>
              <Button variant="primary" onClick={() => window.location.reload()}>
                Run New Scan
              </Button>
            </div>
          )}
        </Card>

        {/* Vulnerability Detail Modal */}
        <DetailModal
          isOpen={showDetailModal}
          onClose={() => setShowDetailModal(false)}
          title="Vulnerability Details"
          data={selectedVulnerability}
          fields={vulnerabilityDetailFields}
        />
      </div>
    </PageTransition>
  );
};

export default EnhancedVulnerabilitiesPage;

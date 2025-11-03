// Enhanced Statistics Page with Interactive Charts
import React, { useState, useEffect, useMemo } from 'react';
import { useScan } from '../context/EnhancedScanContext';
import { SCAN_STATUS } from '../utils/constants';
import { 
  Card, 
  Badge, 
  Button, 
  ProgressBar,
  StatusIndicator,
  PageTransition,
  StaggeredList,
  SkeletonCard,
  EnhancedModal,
  DetailModal
} from '../components/ThemeComponents';
import { 
  SectionLoading
} from '../components/EnhancedLoadingSkeletons';
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
  AreaChart,
  RadialBarChart,
  RadialBar,
  Legend
} from 'recharts';

const EnhancedStatisticsPage = () => {
  const { 
    stats, 
    vulnerabilities, 
    chains, 
    scanStatus,
    toolActivity,
    connected,
    progress,
    currentPhase 
  } = useScan();

  const [loading, setLoading] = useState(false);
  const [timeRange, setTimeRange] = useState('6months');
  const [selectedMetric, setSelectedMetric] = useState('vulnerabilities');

  // Simulate loading state
  useEffect(() => {
    if (stats.critical === 0 && scanStatus === SCAN_STATUS.IDLE) {
      setLoading(true);
      const timer = setTimeout(() => setLoading(false), 1500);
      return () => clearTimeout(timer);
    }
  }, [stats.critical, scanStatus]);

  // Generate mock historical data for charts
  const historicalData = useMemo(() => {
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'];
    return months.map(month => ({
      month,
      critical: Math.floor(Math.random() * 20) + 5,
      high: Math.floor(Math.random() * 40) + 10,
      medium: Math.floor(Math.random() * 60) + 20,
      low: Math.floor(Math.random() * 80) + 30,
      scans: Math.floor(Math.random() * 50) + 10,
      tools: Math.floor(Math.random() * 25) + 5
    }));
  }, []);

  // Tool activity data
  const toolActivityData = useMemo(() => {
    return toolActivity.slice(0, 8).map(tool => ({
      name: tool.tool,
      value: tool.findings_count || Math.floor(Math.random() * 100),
      status: tool.status
    }));
  }, [toolActivity]);

  // Security metrics over time
  const securityTrends = useMemo(() => {
    return [
      { period: 'Week 1', securityScore: 65, threats: 45, resolution: 78 },
      { period: 'Week 2', securityScore: 72, threats: 38, resolution: 82 },
      { period: 'Week 3', securityScore: 68, threats: 42, resolution: 75 },
      { period: 'Week 4', securityScore: 78, threats: 32, resolution: 88 },
      { period: 'Week 5', securityScore: 85, threats: 25, resolution: 92 },
      { period: 'Week 6', securityScore: 88, threats: 22, resolution: 95 }
    ];
  }, []);

  // Severity distribution for pie chart
  const severityDistribution = [
    { name: 'Critical', value: stats.critical, color: '#ef4444' },
    { name: 'High', value: stats.high, color: '#f97316' },
    { name: 'Medium', value: stats.medium, color: '#eab308' },
    { name: 'Low', value: stats.low, color: '#3b82f6' }
  ];

  // Calculate security metrics
  const totalVulnerabilities = stats.critical + stats.high + stats.medium + stats.low;
  const securityScore = Math.max(0, 100 - (stats.critical * 10 + stats.high * 5 + stats.medium * 2));
  const resolutionRate = vulnerabilities.length > 0 ? 85 : 0;

  if (loading) {
    return (
      <div className="space-y-6 animate-fade-in">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {Array.from({ length: 4 }).map((_, i) => (
            <SkeletonCard key={i} />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <SkeletonCard className="h-96" />
          <SkeletonCard className="h-96" />
        </div>
        <SkeletonCard className="h-64" />
      </div>
    );
  }

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-gray-800 p-3 rounded-lg border border-gray-700">
          <p className="text-white font-medium">{label}</p>
          {payload.map((entry, index) => (
            <p key={index} className="text-sm" style={{ color: entry.color }}>
              {entry.name}: {entry.value}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <PageTransition>
      <div className="space-y-8">
        {/* Enhanced Header */}
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 animate-fade-in-down">
          <div>
            <h1 className="text-4xl font-bold text-gradient mb-2">
              Security Analytics
            </h1>
            <p className="text-gray-400">
              Comprehensive security metrics and performance insights
            </p>
          </div>
          
          <div className="flex items-center gap-4">
            {/* Connection Status */}
            <StatusIndicator 
              status={connected ? 'online' : 'offline'} 
              showText={true}
            />
            
            {/* Time Range Selector */}
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="input py-2 px-3 bg-gray-800 border-gray-600 text-white rounded-lg text-sm"
            >
              <option value="1month">Last Month</option>
              <option value="3months">Last 3 Months</option>
              <option value="6months">Last 6 Months</option>
              <option value="1year">Last Year</option>
            </select>
            
            {/* Export Button */}
            <Button 
              variant="primary"
              icon={
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              }
            >
              Export Analytics
            </Button>
          </div>
        </div>

        {/* Security Score Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <StaggeredList>
            <Card className="text-center hover-glow">
              <div className="space-y-4">
                <div className="w-16 h-16 mx-auto bg-gradient-to-r from-green-500 to-emerald-500 rounded-full flex items-center justify-center">
                  <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <div>
                  <p className="text-3xl font-bold text-green-400">{securityScore}%</p>
                  <p className="text-sm text-gray-400">Security Score</p>
                </div>
                <ProgressBar 
                  value={securityScore} 
                  max={100}
                  size="sm"
                  color="success"
                />
              </div>
            </Card>

            <Card className="text-center hover-glow">
              <div className="space-y-4">
                <div className="w-16 h-16 mx-auto bg-gradient-to-r from-red-500 to-pink-500 rounded-full flex items-center justify-center">
                  <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                  </svg>
                </div>
                <div>
                  <p className="text-3xl font-bold text-red-400">{totalVulnerabilities}</p>
                  <p className="text-sm text-gray-400">Total Vulnerabilities</p>
                </div>
                <Badge variant="error" size="sm">
                  Active Threats
                </Badge>
              </div>
            </Card>

            <Card className="text-center hover-glow">
              <div className="space-y-4">
                <div className="w-16 h-16 mx-auto bg-gradient-to-r from-blue-500 to-cyan-500 rounded-full flex items-center justify-center">
                  <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                </div>
                <div>
                  <p className="text-3xl font-bold text-blue-400">{chains.length}</p>
                  <p className="text-sm text-gray-400">Attack Chains</p>
                </div>
                <Badge variant="warning" size="sm">
                  Detected
                </Badge>
              </div>
            </Card>

            <Card className="text-center hover-glow">
              <div className="space-y-4">
                <div className="w-16 h-16 mx-auto bg-gradient-to-r from-purple-500 to-pink-500 rounded-full flex items-center justify-center">
                  <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                  </svg>
                </div>
                <div>
                  <p className="text-3xl font-bold text-purple-400">{resolutionRate}%</p>
                  <p className="text-sm text-gray-400">Resolution Rate</p>
                </div>
                <ProgressBar 
                  value={resolutionRate} 
                  max={100}
                  size="sm"
                  color="primary"
                />
              </div>
            </Card>
          </StaggeredList>
        </div>

        {/* Main Charts Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Vulnerability Trends */}
          <Card className="hover-glow" padding="xl">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-bold text-white">Vulnerability Trends</h3>
              <Badge variant="primary" size="sm">
                6 Months
              </Badge>
            </div>
            
            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={historicalData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="month" stroke="#9ca3af" />
                  <YAxis stroke="#9ca3af" />
                  <Tooltip content={<CustomTooltip />} />
                  <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.6} />
                  <Area type="monotone" dataKey="high" stackId="1" stroke="#f97316" fill="#f97316" fillOpacity={0.6} />
                  <Area type="monotone" dataKey="medium" stackId="1" stroke="#eab308" fill="#eab308" fillOpacity={0.6} />
                  <Area type="monotone" dataKey="low" stackId="1" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.6} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>

          {/* Security Performance */}
          <Card className="hover-glow" padding="xl">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-bold text-white">Security Performance</h3>
              <Badge variant="success" size="sm">
                Weekly
              </Badge>
            </div>
            
            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={securityTrends}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="period" stroke="#9ca3af" />
                  <YAxis stroke="#9ca3af" />
                  <Tooltip content={<CustomTooltip />} />
                  <Line type="monotone" dataKey="securityScore" stroke="#10b981" strokeWidth={3} dot={{ fill: '#10b981', strokeWidth: 2, r: 6 }} />
                  <Line type="monotone" dataKey="resolution" stroke="#8b5cf6" strokeWidth={3} dot={{ fill: '#8b5cf6', strokeWidth: 2, r: 6 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </div>

        {/* Additional Analytics */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Severity Distribution */}
          <Card className="hover-glow" padding="xl">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-bold text-white">Distribution</h3>
            </div>
            
            <div className="h-64">
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
                  <Tooltip content={<CustomTooltip />} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </Card>

          {/* Tool Activity */}
          <Card className="hover-glow" padding="xl">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-bold text-white">Tool Activity</h3>
              <Badge variant="info" size="sm">
                {toolActivity.length} Active
              </Badge>
            </div>
            
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={toolActivityData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="name" stroke="#9ca3af" angle={-45} textAnchor="end" height={80} />
                  <YAxis stroke="#9ca3af" />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar dataKey="value" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>

          {/* Security Metrics */}
          <Card className="hover-glow" padding="xl">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-bold text-white">Key Metrics</h3>
            </div>
            
            <div className="space-y-6">
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-400">Security Score</span>
                  <span className="text-green-400 font-medium">{securityScore}%</span>
                </div>
                <ProgressBar value={securityScore} max={100} size="sm" color="success" />
              </div>
              
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-400">Resolution Rate</span>
                  <span className="text-blue-400 font-medium">{resolutionRate}%</span>
                </div>
                <ProgressBar value={resolutionRate} max={100} size="sm" color="primary" />
              </div>
              
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-400">Active Threats</span>
                  <span className="text-red-400 font-medium">{totalVulnerabilities}</span>
                </div>
                <ProgressBar value={Math.min(totalVulnerabilities * 2, 100)} max={100} size="sm" color="error" />
              </div>
              
              <div className="grid grid-cols-2 gap-4 pt-4">
                <div className="text-center">
                  <p className="text-2xl font-bold text-white">{chains.length}</p>
                  <p className="text-xs text-gray-400">Attack Chains</p>
                </div>
                <div className="text-center">
                  <p className="text-2xl font-bold text-white">{toolActivity.length}</p>
                  <p className="text-xs text-gray-400">Active Tools</p>
                </div>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </PageTransition>
  );
};

export default EnhancedStatisticsPage;

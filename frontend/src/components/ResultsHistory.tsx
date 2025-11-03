import React, { useState, useEffect } from 'react';
import { 
  History, 
  Download, 
  Upload, 
  Filter, 
  Search, 
  Eye,
  Trash2,
  Share,
  Star,
  Calendar,
  Clock,
  Target,
  Shield,
  AlertTriangle,
  CheckCircle,
  FileText,
  BarChart3,
  TrendingUp,
  SortAsc,
  SortDesc,
  Zap
} from 'lucide-react';

// Types
interface TestResult {
  id: string;
  name: string;
  type: 'vulnerability-scan' | 'security-test' | 'repeater-test' | 'payload-test';
  target: string;
  status: 'completed' | 'failed' | 'running' | 'pending';
  startTime: Date;
  endTime?: Date;
  duration?: number;
  summary: {
    totalRequests: number;
    vulnerabilitiesFound: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    successRate: number;
  };
  findings: Finding[];
  metadata: {
    userAgent: string;
    scanConfig: any;
    payloadCount: number;
    encoderUsed: string[];
  };
  tags: string[];
  isFavorite: boolean;
  notes?: string;
}

interface Finding {
  id: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  url: string;
  evidence: string;
  confidence: number;
  cvss: number;
  cwe: string;
  owasp: string;
  remediation: string;
}

type SortField = 'name' | 'target' | 'startTime' | 'duration' | 'vulnerabilitiesFound';
type SortOrder = 'asc' | 'desc';

const ResultsHistory: React.FC = () => {
  const [isDarkMode] = useState(true);
  const [results, setResults] = useState<TestResult[]>([]);
  const [filteredResults, setFilteredResults] = useState<TestResult[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState('all');
  const [selectedStatus, setSelectedStatus] = useState('all');
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [sortField, setSortField] = useState<SortField>('startTime');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [selectedResults, setSelectedResults] = useState<string[]>([]);
  const [viewMode, setViewMode] = useState<'list' | 'grid'>('list');
  const [showDetails, setShowDetails] = useState<string | null>(null);

  // Mock data for demonstration
  const mockResults: TestResult[] = [
    {
      id: '1',
      name: 'Web Application Security Scan',
      type: 'vulnerability-scan',
      target: 'https://example.com',
      status: 'completed',
      startTime: new Date('2024-01-15T10:30:00'),
      endTime: new Date('2024-01-15T11:45:00'),
      duration: 4500000,
      summary: {
        totalRequests: 1247,
        vulnerabilitiesFound: 23,
        critical: 3,
        high: 7,
        medium: 8,
        low: 5,
        successRate: 94.2
      },
      findings: [
        {
          id: 'f1',
          type: 'SQL Injection',
          severity: 'critical',
          title: 'SQL Injection in User Login',
          description: 'The application is vulnerable to SQL injection attacks in the login form.',
          url: 'https://example.com/login',
          evidence: 'SQL syntax error detected in response',
          confidence: 95,
          cvss: 9.8,
          cwe: 'CWE-89',
          owasp: 'A03:2021',
          remediation: 'Use parameterized queries and input validation'
        }
      ],
      metadata: {
        userAgent: 'CyberSage Scanner v2.0',
        scanConfig: {
          scanType: 'comprehensive',
          ports: '1-65535',
          intensity: 'high'
        },
        payloadCount: 156,
        encoderUsed: ['url', 'base64', 'html']
      },
      tags: ['web-app', 'authentication', 'production'],
      isFavorite: true,
      notes: 'Found critical SQL injection vulnerability. Immediate patch required.'
    },
    {
      id: '2',
      name: 'API Security Testing',
      type: 'security-test',
      target: 'https://api.example.com/v1',
      status: 'completed',
      startTime: new Date('2024-01-14T14:20:00'),
      endTime: new Date('2024-01-14T15:10:00'),
      duration: 3000000,
      summary: {
        totalRequests: 856,
        vulnerabilitiesFound: 12,
        critical: 1,
        high: 4,
        medium: 5,
        low: 2,
        successRate: 88.7
      },
      findings: [
        {
          id: 'f2',
          type: 'XSS',
          severity: 'high',
          title: 'Reflected XSS in Search',
          description: 'Cross-site scripting vulnerability in search functionality.',
          url: 'https://api.example.com/v1/search',
          evidence: 'Script tags executed in response',
          confidence: 88,
          cvss: 7.2,
          cwe: 'CWE-79',
          owasp: 'A03:2021',
          remediation: 'Implement Content Security Policy and input sanitization'
        }
      ],
      metadata: {
        userAgent: 'CyberSage API Tester',
        scanConfig: {
          testTypes: ['xss', 'sqli', 'command-injection'],
          payloadSet: 'standard'
        },
        payloadCount: 89,
        encoderUsed: ['url', 'double-url']
      },
      tags: ['api', 'xss', 'testing'],
      isFavorite: false
    },
    {
      id: '3',
      name: 'Custom Payload Test',
      type: 'payload-test',
      target: 'https://test-app.local',
      status: 'completed',
      startTime: new Date('2024-01-13T09:15:00'),
      endTime: new Date('2024-01-13T09:45:00'),
      duration: 1800000,
      summary: {
        totalRequests: 324,
        vulnerabilitiesFound: 8,
        critical: 2,
        high: 3,
        medium: 2,
        low: 1,
        successRate: 92.1
      },
      findings: [],
      metadata: {
        userAgent: 'CyberSage Payload Tester',
        scanConfig: {
          customPayloads: true,
          encodingTypes: ['raw', 'url', 'base64']
        },
        payloadCount: 45,
        encoderUsed: ['raw', 'url', 'base64']
      },
      tags: ['payloads', 'custom', 'encoding'],
      isFavorite: false
    }
  ];

  // Load results from localStorage or use mock data
  useEffect(() => {
    const savedResults = localStorage.getItem('resultsHistory_results');
    if (savedResults) {
      try {
        const parsed = JSON.parse(savedResults);
        const resultsWithDates = parsed.map((r: any) => ({
          ...r,
          startTime: new Date(r.startTime),
          endTime: r.endTime ? new Date(r.endTime) : undefined
        }));
        setResults(resultsWithDates);
      } catch (e) {
        console.error('Failed to load saved results:', e);
        setResults(mockResults);
      }
    } else {
      setResults(mockResults);
    }
  }, []);

  // Save results to localStorage
  useEffect(() => {
    localStorage.setItem('resultsHistory_results', JSON.stringify(results));
  }, [results]);

  // Filter and sort results
  useEffect(() => {
    let filtered = results.filter(result => {
      const matchesSearch = result.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           result.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           result.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()));
      const matchesType = selectedType === 'all' || result.type === selectedType;
      const matchesStatus = selectedStatus === 'all' || result.status === selectedStatus;
      const matchesSeverity = selectedSeverity === 'all' || 
                             (selectedSeverity === 'critical' && result.summary.critical > 0) ||
                             (selectedSeverity === 'high' && result.summary.high > 0) ||
                             (selectedSeverity === 'medium' && result.summary.medium > 0) ||
                             (selectedSeverity === 'low' && result.summary.low > 0);
      
      return matchesSearch && matchesType && matchesStatus && matchesSeverity;
    });

    // Sort results
    filtered.sort((a, b) => {
      let aVal: any, bVal: any;
      
      switch (sortField) {
        case 'name':
          aVal = a.name.toLowerCase();
          bVal = b.name.toLowerCase();
          break;
        case 'target':
          aVal = a.target.toLowerCase();
          bVal = b.target.toLowerCase();
          break;
        case 'startTime':
          aVal = a.startTime.getTime();
          bVal = b.startTime.getTime();
          break;
        case 'duration':
          aVal = a.duration || 0;
          bVal = b.duration || 0;
          break;
        case 'vulnerabilitiesFound':
          aVal = a.summary.vulnerabilitiesFound;
          bVal = b.summary.vulnerabilitiesFound;
          break;
        default:
          return 0;
      }
      
      if (sortOrder === 'asc') {
        return aVal > bVal ? 1 : -1;
      } else {
        return aVal < bVal ? 1 : -1;
      }
    });

    setFilteredResults(filtered);
  }, [results, searchTerm, selectedType, selectedStatus, selectedSeverity, sortField, sortOrder]);

  // Toggle favorite
  const toggleFavorite = (id: string) => {
    setResults(prev => prev.map(r => r.id === id ? { ...r, isFavorite: !r.isFavorite } : r));
  };

  // Delete result
  const deleteResult = (id: string) => {
    setResults(prev => prev.filter(r => r.id !== id));
    setSelectedResults(prev => prev.filter(rid => rid !== id));
  };

  // Bulk operations
  const deleteSelected = () => {
    setResults(prev => prev.filter(r => !selectedResults.includes(r.id)));
    setSelectedResults([]);
  };

  const exportSelected = (format: 'json' | 'csv' | 'pdf') => {
    const selected = results.filter(r => selectedResults.includes(r.id));
    
    if (format === 'json') {
      const dataStr = JSON.stringify(selected, null, 2);
      const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
      const exportFileDefaultName = 'security_test_results.json';
      const linkElement = document.createElement('a');
      linkElement.setAttribute('href', dataUri);
      linkElement.setAttribute('download', exportFileDefaultName);
      linkElement.click();
    } else if (format === 'csv') {
      // Convert to CSV format
      const headers = ['Name', 'Target', 'Type', 'Status', 'Start Time', 'Duration', 'Total Requests', 'Vulnerabilities', 'Critical', 'High', 'Medium', 'Low'];
      const csvContent = [
        headers.join(','),
        ...selected.map(r => [
          `"${r.name}"`,
          `"${r.target}"`,
          r.type,
          r.status,
          r.startTime.toISOString(),
          r.duration || '',
          r.summary.totalRequests,
          r.summary.vulnerabilitiesFound,
          r.summary.critical,
          r.summary.high,
          r.summary.medium,
          r.summary.low
        ].join(','))
      ].join('\n');
      
      const dataUri = 'data:text/csv;charset=utf-8,'+ encodeURIComponent(csvContent);
      const exportFileDefaultName = 'security_test_results.csv';
      const linkElement = document.createElement('a');
      linkElement.setAttribute('href', dataUri);
      linkElement.setAttribute('download', exportFileDefaultName);
      linkElement.click();
    }
  };

  // Get status icon and color
  const getStatusInfo = (status: string) => {
    switch (status) {
      case 'completed':
        return { icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-500/20' };
      case 'running':
        return { icon: Clock, color: 'text-yellow-400', bg: 'bg-yellow-500/20' };
      case 'failed':
        return { icon: AlertTriangle, color: 'text-red-400', bg: 'bg-red-500/20' };
      default:
        return { icon: Clock, color: 'text-gray-400', bg: 'bg-gray-500/20' };
    }
  };

  // Get type icon
  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'vulnerability-scan': return Shield;
      case 'security-test': return AlertTriangle;
      case 'repeater-test': return Target;
      case 'payload-test': return Zap;
      default: return FileText;
    }
  };

  const formatDuration = (ms?: number) => {
    if (!ms) return '-';
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `${hours}h ${minutes % 60}m`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  };

  return (
    <div className={`min-h-screen ${isDarkMode ? 'bg-gray-950' : 'bg-gray-50'}`}>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className={`text-3xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-2`}>
              Results History
            </h1>
            <p className={`${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
              View, analyze, and export security testing results and reports
            </p>
          </div>
          <div className="flex items-center space-x-3">
            {selectedResults.length > 0 && (
              <>
                <div className="relative group">
                  <button className="px-4 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg flex items-center space-x-2">
                    <Download className="w-4 h-4" />
                    <span>Export ({selectedResults.length})</span>
                  </button>
                  <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg opacity-0 group-hover:opacity-100 transition-opacity z-10">
                    <button
                      onClick={() => exportSelected('json')}
                      className="w-full text-left px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-900 dark:text-gray-100"
                    >
                      Export as JSON
                    </button>
                    <button
                      onClick={() => exportSelected('csv')}
                      className="w-full text-left px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-900 dark:text-gray-100"
                    >
                      Export as CSV
                    </button>
                    <button
                      onClick={() => exportSelected('pdf')}
                      className="w-full text-left px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-900 dark:text-gray-100"
                    >
                      Export as PDF Report
                    </button>
                  </div>
                </div>
                <button
                  onClick={deleteSelected}
                  className="px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg flex items-center space-x-2"
                >
                  <Trash2 className="w-4 h-4" />
                  <span>Delete ({selectedResults.length})</span>
                </button>
              </>
            )}
            <button className={`px-4 py-2 rounded-lg border ${
              isDarkMode 
                ? 'border-gray-600 hover:bg-gray-800 text-gray-300' 
                : 'border-gray-300 hover:bg-gray-50 text-gray-700'
            } flex items-center space-x-2`}>
              <Upload className="w-4 h-4" />
              <span>Import</span>
            </button>
          </div>
        </div>

        {/* Filters and Search */}
        <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-xl p-6`}>
          <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
            {/* Search */}
            <div className="md:col-span-2">
              <div className="relative">
                <Search className={`absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 ${
                  isDarkMode ? 'text-gray-400' : 'text-gray-500'
                }`} />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search results..."
                  className={`w-full pl-10 pr-4 py-2 rounded-lg border ${
                    isDarkMode
                      ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400'
                      : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'
                  }`}
                />
              </div>
            </div>

            {/* Type Filter */}
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className={`px-3 py-2 rounded-lg border ${
                isDarkMode
                  ? 'bg-gray-700 border-gray-600 text-white'
                  : 'bg-white border-gray-300 text-gray-900'
              }`}
            >
              <option value="all">All Types</option>
              <option value="vulnerability-scan">Vulnerability Scan</option>
              <option value="security-test">Security Test</option>
              <option value="repeater-test">Repeater Test</option>
              <option value="payload-test">Payload Test</option>
            </select>

            {/* Status Filter */}
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className={`px-3 py-2 rounded-lg border ${
                isDarkMode
                  ? 'bg-gray-700 border-gray-600 text-white'
                  : 'bg-white border-gray-300 text-gray-900'
              }`}
            >
              <option value="all">All Status</option>
              <option value="completed">Completed</option>
              <option value="running">Running</option>
              <option value="failed">Failed</option>
              <option value="pending">Pending</option>
            </select>

            {/* Severity Filter */}
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className={`px-3 py-2 rounded-lg border ${
                isDarkMode
                  ? 'bg-gray-700 border-gray-600 text-white'
                  : 'bg-white border-gray-300 text-gray-900'
              }`}
            >
              <option value="all">All Severities</option>
              <option value="critical">Has Critical</option>
              <option value="high">Has High</option>
              <option value="medium">Has Medium</option>
              <option value="low">Has Low</option>
            </select>

            {/* Sort Controls */}
            <div className="flex space-x-2">
              <select
                value={sortField}
                onChange={(e) => setSortField(e.target.value as SortField)}
                className={`flex-1 px-3 py-2 rounded-lg border ${
                  isDarkMode
                    ? 'bg-gray-700 border-gray-600 text-white'
                    : 'bg-white border-gray-300 text-gray-900'
                }`}
              >
                <option value="startTime">Start Time</option>
                <option value="name">Name</option>
                <option value="target">Target</option>
                <option value="duration">Duration</option>
                <option value="vulnerabilitiesFound">Vulnerabilities</option>
              </select>
              <button
                onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
                className={`px-3 py-2 rounded-lg border ${
                  isDarkMode
                    ? 'bg-gray-700 border-gray-600 text-white hover:bg-gray-600'
                    : 'bg-white border-gray-300 text-gray-900 hover:bg-gray-50'
                }`}
              >
                {sortOrder === 'asc' ? <SortAsc className="w-4 h-4" /> : <SortDesc className="w-4 h-4" />}
              </button>
            </div>
          </div>
        </div>

        {/* Results Summary */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-lg p-4`}>
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-2xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                  {results.length}
                </p>
                <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                  Total Tests
                </p>
              </div>
              <BarChart3 className="w-8 h-8 text-blue-400" />
            </div>
          </div>
          <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-lg p-4`}>
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-2xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                  {results.reduce((sum, r) => sum + r.summary.totalRequests, 0)}
                </p>
                <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                  Total Requests
                </p>
              </div>
              <Target className="w-8 h-8 text-green-400" />
            </div>
          </div>
          <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-lg p-4`}>
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-2xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                  {results.reduce((sum, r) => sum + r.summary.vulnerabilitiesFound, 0)}
                </p>
                <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                  Total Findings
                </p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-400" />
            </div>
          </div>
          <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-lg p-4`}>
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-2xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                  {results.filter(r => r.isFavorite).length}
                </p>
                <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                  Favorites
                </p>
              </div>
              <Star className="w-8 h-8 text-yellow-400" />
            </div>
          </div>
          <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-lg p-4`}>
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-2xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                  {results.filter(r => r.status === 'completed').length}
                </p>
                <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                  Completed
                </p>
              </div>
              <CheckCircle className="w-8 h-8 text-green-400" />
            </div>
          </div>
        </div>

        {/* Results List */}
        <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-xl overflow-hidden`}>
          <div className={`p-4 border-b ${isDarkMode ? 'border-gray-700' : 'border-gray-200'}`}>
            <div className="flex items-center justify-between">
              <h2 className={`text-xl font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                Test Results ({filteredResults.length})
              </h2>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setSelectedResults(results.map(r => r.id))}
                  className={`px-3 py-1 rounded text-sm ${
                    isDarkMode
                      ? 'bg-gray-600 hover:bg-gray-500 text-gray-300'
                      : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
                  }`}
                >
                  Select All
                </button>
                <button
                  onClick={() => setSelectedResults([])}
                  className={`px-3 py-1 rounded text-sm ${
                    isDarkMode
                      ? 'bg-gray-600 hover:bg-gray-500 text-gray-300'
                      : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
                  }`}
                >
                  Clear
                </button>
              </div>
            </div>
          </div>

          <div className="divide-y divide-gray-700">
            {filteredResults.map((result) => {
              const statusInfo = getStatusInfo(result.status);
              const TypeIcon = getTypeIcon(result.type);
              const isExpanded = showDetails === result.id;
              
              return (
                <div key={result.id} className={`p-4 hover:bg-opacity-50 transition-colors ${
                  isDarkMode ? 'hover:bg-gray-750' : 'hover:bg-gray-50'
                }`}>
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-4 flex-1">
                      {/* Selection Checkbox */}
                      <input
                        type="checkbox"
                        checked={selectedResults.includes(result.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedResults(prev => [...prev, result.id]);
                          } else {
                            setSelectedResults(prev => prev.filter(id => id !== result.id));
                          }
                        }}
                        className="mt-1"
                      />

                      {/* Result Info */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center space-x-2 mb-2">
                          <TypeIcon className="w-5 h-5 text-gray-400" />
                          <h3 className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                            {result.name}
                          </h3>
                          {result.isFavorite && (
                            <Star className="w-4 h-4 text-yellow-400 fill-current" />
                          )}
                          <div className={`flex items-center space-x-1 px-2 py-1 rounded text-xs ${statusInfo.bg}`}>
                            <statusInfo.icon className={`w-3 h-3 ${statusInfo.color}`} />
                            <span className={statusInfo.color}>
                              {result.status.toUpperCase()}
                            </span>
                          </div>
                        </div>
                        
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-3">
                          <div>
                            <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                              Target
                            </p>
                            <p className={`text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                              {result.target}
                            </p>
                          </div>
                          <div>
                            <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                              Start Time
                            </p>
                            <p className={`text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                              {result.startTime.toLocaleString()}
                            </p>
                          </div>
                          <div>
                            <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                              Duration
                            </p>
                            <p className={`text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                              {formatDuration(result.duration)}
                            </p>
                          </div>
                        </div>

                        {/* Summary Stats */}
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-3">
                          <div className={`text-center p-2 rounded ${
                            isDarkMode ? 'bg-gray-700' : 'bg-gray-100'
                          }`}>
                            <p className={`text-lg font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                              {result.summary.totalRequests}
                            </p>
                            <p className={`text-xs ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                              Requests
                            </p>
                          </div>
                          <div className="text-center p-2 rounded bg-red-500/20">
                            <p className="text-lg font-bold text-red-400">
                              {result.summary.vulnerabilitiesFound}
                            </p>
                            <p className="text-xs text-red-400">
                              Findings
                            </p>
                          </div>
                          <div className="text-center p-2 rounded bg-orange-500/20">
                            <p className="text-lg font-bold text-orange-400">
                              {result.summary.high + result.summary.critical}
                            </p>
                            <p className="text-xs text-orange-400">
                              High/Critical
                            </p>
                          </div>
                          <div className="text-center p-2 rounded bg-green-500/20">
                            <p className="text-lg font-bold text-green-400">
                              {result.summary.successRate.toFixed(1)}%
                            </p>
                            <p className="text-xs text-green-400">
                              Success Rate
                            </p>
                          </div>
                        </div>

                        {/* Vulnerability Breakdown */}
                        <div className="flex items-center space-x-4 mb-3">
                          {result.summary.critical > 0 && (
                            <span className="px-2 py-1 bg-red-500/20 text-red-400 rounded text-xs font-medium">
                              {result.summary.critical} Critical
                            </span>
                          )}
                          {result.summary.high > 0 && (
                            <span className="px-2 py-1 bg-orange-500/20 text-orange-400 rounded text-xs font-medium">
                              {result.summary.high} High
                            </span>
                          )}
                          {result.summary.medium > 0 && (
                            <span className="px-2 py-1 bg-yellow-500/20 text-yellow-400 rounded text-xs font-medium">
                              {result.summary.medium} Medium
                            </span>
                          )}
                          {result.summary.low > 0 && (
                            <span className="px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-xs font-medium">
                              {result.summary.low} Low
                            </span>
                          )}
                        </div>

                        {/* Tags */}
                        <div className="flex flex-wrap gap-1 mb-3">
                          {result.tags.map((tag) => (
                            <span
                              key={tag}
                              className={`px-2 py-1 rounded text-xs ${
                                isDarkMode ? 'bg-gray-600 text-gray-300' : 'bg-gray-100 text-gray-600'
                              }`}
                            >
                              #{tag}
                            </span>
                          ))}
                        </div>

                        {/* Expandable Details */}
                        {isExpanded && (
                          <div className={`mt-4 p-4 rounded-lg ${
                            isDarkMode ? 'bg-gray-700' : 'bg-gray-50'
                          }`}>
                            <h4 className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-2`}>
                              Detailed Findings
                            </h4>
                            {result.findings.length > 0 ? (
                              <div className="space-y-2">
                                {result.findings.map((finding) => (
                                  <div key={finding.id} className={`p-3 rounded border ${
                                    isDarkMode ? 'bg-gray-600 border-gray-500' : 'bg-white border-gray-200'
                                  }`}>
                                    <div className="flex items-center justify-between mb-2">
                                      <h5 className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                                        {finding.title}
                                      </h5>
                                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                                        finding.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                                        finding.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                                        finding.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                                        'bg-blue-500/20 text-blue-400'
                                      }`}>
                                        {finding.severity.toUpperCase()}
                                      </span>
                                    </div>
                                    <p className={`text-sm ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-2`}>
                                      {finding.description}
                                    </p>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                                      <div>
                                        <span className={`${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                          Evidence:
                                        </span>
                                        <p className={`${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                          {finding.evidence}
                                        </p>
                                      </div>
                                      <div>
                                        <span className={`${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                          CVSS Score:
                                        </span>
                                        <span className={`ml-1 font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                          {finding.cvss.toFixed(1)}
                                        </span>
                                      </div>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                No specific findings detailed in this result.
                              </p>
                            )}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center space-x-2 ml-4">
                      <button
                        onClick={() => toggleFavorite(result.id)}
                        className={`p-2 rounded transition-colors ${
                          result.isFavorite
                            ? 'text-yellow-400 hover:text-yellow-300'
                            : isDarkMode
                            ? 'text-gray-400 hover:text-yellow-400'
                            : 'text-gray-600 hover:text-yellow-600'
                        }`}
                      >
                        <Star className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => setShowDetails(isExpanded ? null : result.id)}
                        className={`p-2 rounded transition-colors ${
                          isDarkMode
                            ? 'text-gray-400 hover:text-white hover:bg-gray-700'
                            : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                        }`}
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => {/* Share logic */}}
                        className={`p-2 rounded transition-colors ${
                          isDarkMode
                            ? 'text-gray-400 hover:text-white hover:bg-gray-700'
                            : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                        }`}
                      >
                        <Share className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => deleteResult(result.id)}
                        className="p-2 rounded text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}

            {filteredResults.length === 0 && (
              <div className="text-center py-12">
                <div className="w-16 h-16 mx-auto mb-4 p-4 bg-gray-500/20 rounded-full">
                  <History className="w-8 h-8 text-gray-400 mx-auto" />
                </div>
                <p className="text-gray-400">No test results found</p>
                <p className="text-sm text-gray-500 mt-2">
                  Try adjusting your search criteria or run some security tests
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ResultsHistory;
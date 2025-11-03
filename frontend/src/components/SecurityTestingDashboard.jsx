import React, { useState, useEffect } from 'react';
import { 
  Shield, Zap, Target, Bug, Network, Eye, Search, AlertTriangle,
  CheckCircle, TrendingUp, Database, Server, Lock, Key, Globe,
  Play, Pause, RotateCcw, Download, Settings, Activity, Cpu,
  Code, Terminal, Layers, ArrowRight, BarChart3, PieChart
} from 'lucide-react';

const SecurityTestingDashboard = () => {
  const [activeTab, setActiveTab] = useState('overview');
  const [dashboardData, setDashboardData] = useState({
    totalTests: 0,
    vulnerabilitiesFound: 0,
    testsInProgress: 0,
    securityScore: 0,
    recentActivity: [],
    criticalIssues: 0,
    highIssues: 0,
    mediumIssues: 0,
    lowIssues: 0
  });

  const [testSuites] = useState([
    {
      id: 'repeater',
      name: 'HTTP Request Repeater',
      description: 'Manual request testing and modification',
      icon: Target,
      color: 'bg-blue-500',
      status: 'ready',
      features: ['Parameter injection', 'Response manipulation', 'Session management']
    },
    {
      id: 'hetty',
      name: 'HETTY HTTP/2 Testing',
      description: 'HTTP/2 proxy and vulnerability testing',
      icon: Network,
      color: 'bg-green-500',
      status: 'ready',
      features: ['Traffic interception', 'HTTP/2 analysis', 'Vulnerability scanning']
    },
    {
      id: 'scanner',
      name: 'Automated Vulnerability Scanner',
      description: 'Comprehensive security scanning',
      icon: Search,
      color: 'bg-purple-500',
      status: 'ready',
      features: ['OWASP Top 10', 'Custom payloads', 'AI analysis']
    },
    {
      id: 'proxy',
      name: 'Proxy & Interception',
      description: 'Network proxy and traffic analysis',
      icon: Eye,
      color: 'bg-orange-500',
      status: 'ready',
      features: ['SSL/TLS inspection', 'Request modification', 'Real-time analysis']
    }
  ]);

  const [vulnerabilityTrends, setVulnerabilityTrends] = useState([
    { type: 'SQL Injection', count: 15, trend: 'up' },
    { type: 'XSS', count: 12, trend: 'down' },
    { type: 'CSRF', count: 8, trend: 'up' },
    { type: 'Authentication', count: 6, trend: 'stable' },
    { type: 'Authorization', count: 10, trend: 'down' },
    { type: 'SSRF', count: 4, trend: 'up' }
  ]);

  const [testResults, setTestResults] = useState([]);
  const [isRunningTest, setIsRunningTest] = useState(false);

  // Initialize dashboard data
  useEffect(() => {
    initializeDashboardData();
  }, []);

  const initializeDashboardData = () => {
    setDashboardData({
      totalTests: 847,
      vulnerabilitiesFound: 23,
      testsInProgress: 2,
      securityScore: 78,
      recentActivity: [
        { time: '2 min ago', action: 'SQL Injection test completed', result: 'Vulnerability found', severity: 'high' },
        { time: '5 min ago', action: 'XSS payload test', result: 'No vulnerability', severity: 'low' },
        { time: '8 min ago', action: 'Authentication bypass test', result: 'Vulnerability found', severity: 'critical' },
        { time: '12 min ago', action: 'CSRF token validation', result: 'Passed', severity: 'info' },
        { time: '15 min ago', action: 'Directory enumeration', result: '3 paths discovered', severity: 'medium' }
      ],
      criticalIssues: 3,
      highIssues: 7,
      mediumIssues: 9,
      lowIssues: 4
    });
  };

  // Run comprehensive test suite
  const runComprehensiveTest = async () => {
    setIsRunningTest(true);
    
    const testTypes = [
      'SQL Injection', 'XSS', 'CSRF', 'Authentication', 'Authorization',
      'File Inclusion', 'Command Injection', 'SSRF', 'XXE', 'Deserialization'
    ];
    
    const results = [];
    
    for (let i = 0; i < testTypes.length; i++) {
      const testType = testTypes[i];
      
      // Simulate test execution
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const hasVulnerability = Math.random() > 0.7; // 30% chance of finding vulnerability
      const severity = hasVulnerability 
        ? ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)]
        : null;
      
      results.push({
        id: Date.now() + i,
        type: testType,
        status: 'completed',
        hasVulnerability,
        severity,
        timestamp: new Date().toISOString(),
        details: hasVulnerability 
          ? `Vulnerability detected: ${testType.toLowerCase()} weakness found`
          : `Test completed: No ${testType.toLowerCase()} vulnerabilities detected`
      });
      
      setTestResults(prev => [results[i], ...prev]);
    }
    
    setIsRunningTest(false);
    
    // Update dashboard stats
    const newVulnerabilities = results.filter(r => r.hasVulnerability).length;
    setDashboardData(prev => ({
      ...prev,
      vulnerabilitiesFound: prev.vulnerabilitiesFound + newVulnerabilities,
      totalTests: prev.totalTests + testTypes.length
    }));
  };

  // Export test results
  const exportResults = () => {
    const exportData = {
      timestamp: new Date().toISOString(),
      dashboard: dashboardData,
      testResults,
      vulnerabilityTrends,
      testSuites
    };
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-test-results-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-900';
      case 'high': return 'text-orange-400 bg-orange-900';
      case 'medium': return 'text-yellow-400 bg-yellow-900';
      case 'low': return 'text-blue-400 bg-blue-900';
      default: return 'text-gray-400 bg-gray-900';
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical': return <AlertTriangle className="w-4 h-4" />;
      case 'high': return <Shield className="w-4 h-4" />;
      case 'medium': return <Target className="w-4 h-4" />;
      case 'low': return <CheckCircle className="w-4 h-4" />;
      default: return <Activity className="w-4 h-4" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-bold bg-gradient-to-r from-red-400 to-purple-500 bg-clip-text text-transparent">
            Security Testing Center
          </h2>
          <p className="text-sm text-gray-400 mt-1">
            Comprehensive security testing platform with Burp Suite + HETTY functionality
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={exportResults}
            className="inline-flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-all duration-200"
          >
            <Download className="w-4 h-4 mr-2" />
            Export Results
          </button>
          <button
            onClick={runComprehensiveTest}
            disabled={isRunningTest}
            className="inline-flex items-center px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 text-white rounded-lg transition-all duration-200"
          >
            {isRunningTest ? (
              <Pause className="w-4 h-4 mr-2" />
            ) : (
              <Play className="w-4 h-4 mr-2" />
            )}
            {isRunningTest ? 'Running Tests...' : 'Run Comprehensive Test'}
          </button>
        </div>
      </div>

      {/* Dashboard Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Security Score</p>
              <p className="text-2xl font-bold text-green-400">{dashboardData.securityScore}</p>
            </div>
            <Shield className="w-8 h-8 text-green-400" />
          </div>
          <div className="mt-4">
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div 
                className="bg-gradient-to-r from-green-500 to-green-600 h-2 rounded-full"
                style={{ width: `${dashboardData.securityScore}%` }}
              ></div>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Total Tests</p>
              <p className="text-2xl font-bold text-blue-400">{dashboardData.totalTests}</p>
            </div>
            <BarChart3 className="w-8 h-8 text-blue-400" />
          </div>
          <p className="text-sm text-gray-500 mt-2">+{testResults.length} new tests</p>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Vulnerabilities</p>
              <p className="text-2xl font-bold text-red-400">{dashboardData.vulnerabilitiesFound}</p>
            </div>
            <Bug className="w-8 h-8 text-red-400" />
          </div>
          <p className="text-sm text-gray-500 mt-2">{dashboardData.criticalIssues} critical</p>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Active Tests</p>
              <p className="text-2xl font-bold text-purple-400">{dashboardData.testsInProgress}</p>
            </div>
            <Activity className="w-8 h-8 text-purple-400" />
          </div>
          <p className="text-sm text-gray-500 mt-2">Running now</p>
        </div>
      </div>

      {/* Main Content Tabs */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
        <div className="border-b border-gray-200 dark:border-gray-700">
          <nav className="flex space-x-8 px-6">
            {[
              { id: 'overview', label: 'Overview', icon: TrendingUp },
              { id: 'tools', label: 'Testing Tools', icon: Shield },
              { id: 'results', label: 'Test Results', icon: Database },
              { id: 'trends', label: 'Trends', icon: PieChart },
              { id: 'activity', label: 'Recent Activity', icon: Activity }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors duration-200 ${
                  activeTab === tab.id
                    ? 'border-red-500 text-red-500'
                    : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        <div className="p-6">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Test Suites */}
              <div>
                <h3 className="text-lg font-bold mb-4">Available Testing Suites</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {testSuites.map((suite) => (
                    <div key={suite.id} className="bg-gray-50 dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex items-center space-x-3">
                          <div className={`p-2 rounded-lg ${suite.color}`}>
                            <suite.icon className="w-6 h-6 text-white" />
                          </div>
                          <div>
                            <h4 className="font-bold text-lg">{suite.name}</h4>
                            <p className="text-sm text-gray-600 dark:text-gray-400">{suite.description}</p>
                          </div>
                        </div>
                        <div className={`px-2 py-1 rounded text-xs font-medium ${
                          suite.status === 'ready' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'
                        }`}>
                          {suite.status}
                        </div>
                      </div>
                      <div className="space-y-2">
                        <h5 className="font-medium text-sm">Features:</h5>
                        <ul className="text-sm text-gray-600 dark:text-gray-400 space-y-1">
                          {suite.features.map((feature, index) => (
                            <li key={index} className="flex items-center space-x-2">
                              <CheckCircle className="w-3 h-3 text-green-500" />
                              <span>{feature}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                      <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                        <button className="w-full px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors duration-200 flex items-center justify-center space-x-2">
                          <Play className="w-4 h-4" />
                          <span>Launch Tool</span>
                          <ArrowRight className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Vulnerability Summary */}
              <div>
                <h3 className="text-lg font-bold mb-4">Vulnerability Summary</h3>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-red-600 dark:text-red-400">Critical</p>
                        <p className="text-2xl font-bold text-red-700 dark:text-red-300">{dashboardData.criticalIssues}</p>
                      </div>
                      <AlertTriangle className="w-8 h-8 text-red-500" />
                    </div>
                  </div>
                  <div className="bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded-lg p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-orange-600 dark:text-orange-400">High</p>
                        <p className="text-2xl font-bold text-orange-700 dark:text-orange-300">{dashboardData.highIssues}</p>
                      </div>
                      <Shield className="w-8 h-8 text-orange-500" />
                    </div>
                  </div>
                  <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-yellow-600 dark:text-yellow-400">Medium</p>
                        <p className="text-2xl font-bold text-yellow-700 dark:text-yellow-300">{dashboardData.mediumIssues}</p>
                      </div>
                      <Target className="w-8 h-8 text-yellow-500" />
                    </div>
                  </div>
                  <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-blue-600 dark:text-blue-400">Low</p>
                        <p className="text-2xl font-bold text-blue-700 dark:text-blue-300">{dashboardData.lowIssues}</p>
                      </div>
                      <CheckCircle className="w-8 h-8 text-blue-500" />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'results' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-bold">Test Results</h3>
                <div className="flex items-center space-x-2">
                  <span className="text-sm text-gray-600 dark:text-gray-400">
                    {testResults.length} results
                  </span>
                </div>
              </div>
              
              <div className="space-y-4">
                {testResults.length > 0 ? (
                  testResults.map((result) => (
                    <div key={result.id} className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-3">
                          <h4 className="font-bold">{result.type}</h4>
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(result.severity)}`}>
                            {result.severity}
                          </span>
                        </div>
                        <div className="flex items-center space-x-2">
                          {result.hasVulnerability ? (
                            <AlertTriangle className="w-5 h-5 text-red-500" />
                          ) : (
                            <CheckCircle className="w-5 h-5 text-green-500" />
                          )}
                          <span className="text-sm text-gray-500">
                            {new Date(result.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-400">{result.details}</p>
                    </div>
                  ))
                ) : (
                  <div className="text-center py-8 text-gray-500">
                    <Database className="w-12 h-12 mx-auto mb-4 opacity-50" />
                    <p>No test results yet. Run tests to see results here.</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'activity' && (
            <div className="space-y-6">
              <h3 className="text-lg font-bold">Recent Activity</h3>
              <div className="space-y-4">
                {dashboardData.recentActivity.map((activity, index) => (
                  <div key={index} className="flex items-start space-x-4 p-4 bg-gray-50 dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700">
                    <div className="flex-shrink-0">
                      {getSeverityIcon(activity.severity)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="font-medium">{activity.action}</p>
                      <p className="text-sm text-gray-600 dark:text-gray-400">{activity.result}</p>
                      <p className="text-xs text-gray-500 mt-1">{activity.time}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'trends' && (
            <div className="space-y-6">
              <h3 className="text-lg font-bold">Vulnerability Trends</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {vulnerabilityTrends.map((trend, index) => (
                  <div key={index} className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-medium">{trend.type}</h4>
                      <div className="flex items-center space-x-2">
                        <span className="text-lg font-bold">{trend.count}</span>
                        <div className={`w-2 h-2 rounded-full ${
                          trend.trend === 'up' ? 'bg-red-500' :
                          trend.trend === 'down' ? 'bg-green-500' : 'bg-yellow-500'
                        }`}></div>
                      </div>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div 
                        className={`h-2 rounded-full ${
                          trend.count > 10 ? 'bg-red-500' :
                          trend.count > 5 ? 'bg-yellow-500' : 'bg-green-500'
                        }`}
                        style={{ width: `${(trend.count / 15) * 100}%` }}
                      ></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Running Test Modal */}
      {isRunningTest && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 p-6 rounded-lg max-w-md w-full mx-4">
            <div className="text-center">
              <div className="w-12 h-12 mx-auto mb-4 border-4 border-gray-200 border-t-red-500 rounded-full animate-spin"></div>
              <h3 className="text-lg font-bold mb-2">Running Security Tests</h3>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                Executing comprehensive vulnerability tests across all attack vectors...
              </p>
              <div className="mt-4 space-y-2">
                <div className="text-xs text-green-600 dark:text-green-400">✓ SQL Injection tests</div>
                <div className="text-xs text-green-600 dark:text-green-400">✓ XSS payload tests</div>
                <div className="text-xs text-yellow-600 dark:text-yellow-400">→ CSRF token validation</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SecurityTestingDashboard;
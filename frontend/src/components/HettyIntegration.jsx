import React, { useState, useEffect, useCallback } from 'react';
import { 
  Network, Shield, Eye, Zap, Target, AlertTriangle, CheckCircle,
  Settings, Play, Pause, RotateCcw, Download, Upload, Search,
  Globe, Server, Lock, Key, Code, Database, Bug, TrendingUp
} from 'lucide-react';

const HettyIntegration = () => {
  // Core state
  const [isProxyActive, setIsProxyActive] = useState(false);
  const [proxyPort, setProxyPort] = useState(8080);
  const [interceptTraffic, setInterceptTraffic] = useState(true);
  
  // Traffic state
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [interceptedRequests, setInterceptedRequests] = useState([]);
  const [selectedRequest, setSelectedRequest] = useState(null);
  
  // Vulnerability testing state
  const [vulnerabilityScan, setVulnerabilityScan] = useState({
    isScanning: false,
    progress: 0,
    results: [],
    vulnerabilities: []
  });
  
  // HTTP/2 testing state
  const [http2Tests, setHttp2Tests] = useState([]);
  const [http2Enabled, setHttp2Enabled] = useState(true);
  
  // Dashboard state
  const [dashboardStats, setDashboardStats] = useState({
    totalRequests: 0,
    interceptedRequests: 0,
    vulnerabilitiesFound: 0,
    securityScore: 0
  });
  
  // Proxy settings
  const [proxySettings, setProxySettings] = useState({
    httpProxy: '127.0.0.1:8080',
    httpsProxy: '127.0.0.1:8080',
    sslStripping: false,
    certificatePinning: true,
    requestModification: true,
    responseModification: false
  });

  // Test templates
  const [testTemplates] = useState({
    http2_framing: [
      'Test HTTP/2 frame ordering',
      'Test stream priority manipulation',
      'Test flow control windows',
      'Test header compression (HPACK)',
      'Test connection pooling behavior'
    ],
    vulnerability_patterns: [
      'HTTP request smuggling',
      'Cache poisoning',
      'Server-side request forgery (SSRF)',
      'Insecure direct object references',
      'Broken authentication',
      'Sensitive data exposure',
      'XML external entity (XXE) injection',
      'Improper error handling',
      'Security misconfiguration',
      'Cross-site request forgery (CSRF)'
    ],
    http2_specific: [
      'Stream prioritization attacks',
      'Connection depletion attacks',
      'Window manipulation attacks',
      'Frame size manipulation',
      'Concurrent stream manipulation',
      'Header compression attacks',
      'Request forgeries via headers'
    ]
  });

  // Initialize mock traffic data
  useEffect(() => {
    loadMockTrafficData();
  }, []);

  const loadMockTrafficData = () => {
    const mockTraffic = [
      {
        id: 1,
        timestamp: new Date(Date.now() - 300000).toISOString(),
        method: 'GET',
        url: 'https://example.com/api/users',
        status: 200,
        httpVersion: 'HTTP/2',
        responseTime: 150,
        size: 2048,
        securityFlags: ['HTTPS', 'HSTS'],
        intercepted: false,
        hasVulnerability: false
      },
      {
        id: 2,
        timestamp: new Date(Date.now() - 240000).toISOString(),
        method: 'POST',
        url: 'https://example.com/login',
        status: 401,
        httpVersion: 'HTTP/2',
        responseTime: 200,
        size: 1024,
        securityFlags: ['HTTPS'],
        intercepted: false,
        hasVulnerability: true,
        vulnerabilityType: 'Missing rate limiting'
      },
      {
        id: 3,
        timestamp: new Date(Date.now() - 180000).toISOString(),
        method: 'GET',
        url: 'https://example.com/admin/dashboard',
        status: 200,
        httpVersion: 'HTTP/2',
        responseTime: 300,
        size: 8192,
        securityFlags: ['HTTPS', 'CSP'],
        intercepted: true,
        hasVulnerability: true,
        vulnerabilityType: 'Insufficient access control'
      },
      {
        id: 4,
        timestamp: new Date(Date.now() - 120000).toISOString(),
        method: 'PUT',
        url: 'https://api.example.com/user/profile',
        status: 500,
        httpVersion: 'HTTP/2',
        responseTime: 500,
        size: 512,
        securityFlags: ['HTTPS'],
        intercepted: false,
        hasVulnerability: true,
        vulnerabilityType: 'Error information disclosure'
      },
      {
        id: 5,
        timestamp: new Date(Date.now() - 60000).toISOString(),
        method: 'DELETE',
        url: 'https://api.example.com/admin/users/123',
        status: 403,
        httpVersion: 'HTTP/2',
        responseTime: 100,
        size: 256,
        securityFlags: ['HTTPS'],
        intercepted: false,
        hasVulnerability: false
      }
    ];

    setTrafficHistory(mockTraffic);
    setInterceptedRequests(mockTraffic.filter(req => req.intercepted));
    setDashboardStats({
      totalRequests: mockTraffic.length,
      interceptedRequests: mockTraffic.filter(req => req.intercepted).length,
      vulnerabilitiesFound: mockTraffic.filter(req => req.hasVulnerability).length,
      securityScore: Math.max(20, 100 - mockTraffic.filter(req => req.hasVulnerability).length * 15)
    });
  };

  // Start/stop proxy
  const toggleProxy = useCallback(() => {
    setIsProxyActive(!isProxyActive);
    
    if (!isProxyActive) {
      // Simulate proxy start
      console.log(`Starting HTTP/2 proxy on port ${proxyPort}...`);
    } else {
      // Simulate proxy stop
      console.log('Stopping proxy...');
    }
  }, [isProxyActive, proxyPort]);

  // Intercept request
  const interceptRequest = useCallback((requestId) => {
    const updatedTraffic = trafficHistory.map(req => 
      req.id === requestId ? { ...req, intercepted: true } : req
    );
    setTrafficHistory(updatedTraffic);
    setInterceptedRequests(updatedTraffic.filter(req => req.intercepted));
  }, [trafficHistory]);

  // Modify request
  const modifyRequest = useCallback((requestId, modifications) => {
    const updatedTraffic = trafficHistory.map(req => 
      req.id === requestId ? { ...req, modified: true, modifications } : req
    );
    setTrafficHistory(updatedTraffic);
  }, [trafficHistory]);

  // Start vulnerability scan
  const startVulnerabilityScan = useCallback(async () => {
    setVulnerabilityScan(prev => ({
      ...prev,
      isScanning: true,
      progress: 0,
      results: [],
      vulnerabilities: []
    }));

    const totalTests = 25;
    const testResults = [];
    const vulnerabilities = [];

    // Simulate vulnerability testing
    for (let i = 0; i < totalTests; i++) {
      await new Promise(resolve => setTimeout(resolve, 200));
      
      const progress = ((i + 1) / totalTests) * 100;
      setVulnerabilityScan(prev => ({ ...prev, progress }));

      // Simulate test results
      if (Math.random() > 0.7) { // 30% chance of finding vulnerability
        const vulnTypes = [
          'SQL Injection', 'XSS', 'CSRF', 'SSRF', 'Insecure Authentication',
          'Missing Rate Limiting', 'Information Disclosure', 'Broken Access Control'
        ];
        const vulnType = vulnTypes[Math.floor(Math.random() * vulnTypes.length)];
        
        const vulnerability = {
          id: i + 1,
          type: vulnType,
          severity: Math.random() > 0.5 ? 'High' : 'Medium',
          description: `${vulnType} vulnerability detected`,
          affectedUrl: 'https://example.com/api/endpoint',
          proofOfConcept: vulnType === 'SQL Injection' ? "1' OR '1'='1" : null,
          remediation: `Implement proper ${vulnType.toLowerCase()} prevention measures`
        };
        
        vulnerabilities.push(vulnerability);
        testResults.push({
          test: `Testing for ${vulnType}`,
          status: 'vulnerable',
          details: vulnerability.description
        });
      } else {
        testResults.push({
          test: `Testing for ${testTemplates.vulnerability_patterns[i % testTemplates.vulnerability_patterns.length]}`,
          status: 'safe',
          details: 'No vulnerability detected'
        });
      }
    }

    setVulnerabilityScan({
      isScanning: false,
      progress: 100,
      results: testResults,
      vulnerabilities
    });

    // Update dashboard stats
    setDashboardStats(prev => ({
      ...prev,
      vulnerabilitiesFound: prev.vulnerabilitiesFound + vulnerabilities.length,
      securityScore: Math.max(0, prev.securityScore - vulnerabilities.length * 10)
    }));
  }, [testTemplates]);

  // Export traffic data
  const exportTrafficData = useCallback(() => {
    const data = {
      timestamp: new Date().toISOString(),
      totalRequests: trafficHistory.length,
      interceptedRequests: interceptedRequests.length,
      vulnerabilities: vulnerabilityScan.vulnerabilities,
      traffic: trafficHistory
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `hetty-traffic-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [trafficHistory, interceptedRequests, vulnerabilityScan.vulnerabilities]);

  // Clear traffic
  const clearTraffic = useCallback(() => {
    setTrafficHistory([]);
    setInterceptedRequests([]);
    setSelectedRequest(null);
    setDashboardStats(prev => ({
      totalRequests: 0,
      interceptedRequests: 0,
      vulnerabilitiesFound: 0,
      securityScore: 100
    }));
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black text-white">
      <div className="flex h-screen">
        {/* Sidebar */}
        <div className="w-80 bg-gray-900 border-r border-gray-800 overflow-y-auto">
          {/* Dashboard Stats */}
          <div className="p-4 border-b border-gray-800">
            <h3 className="text-lg font-bold mb-3 flex items-center gap-2">
              <Database className="w-5 h-5" />
              Dashboard
            </h3>
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-gray-800 p-3 rounded-lg">
                <div className="text-2xl font-bold text-blue-400">{dashboardStats.totalRequests}</div>
                <div className="text-xs text-gray-400">Total Requests</div>
              </div>
              <div className="bg-gray-800 p-3 rounded-lg">
                <div className="text-2xl font-bold text-orange-400">{dashboardStats.interceptedRequests}</div>
                <div className="text-xs text-gray-400">Intercepted</div>
              </div>
              <div className="bg-gray-800 p-3 rounded-lg">
                <div className="text-2xl font-bold text-red-400">{dashboardStats.vulnerabilitiesFound}</div>
                <div className="text-xs text-gray-400">Vulnerabilities</div>
              </div>
              <div className="bg-gray-800 p-3 rounded-lg">
                <div className={`text-2xl font-bold ${
                  dashboardStats.securityScore >= 80 ? 'text-green-400' :
                  dashboardStats.securityScore >= 60 ? 'text-yellow-400' : 'text-red-400'
                }`}>
                  {dashboardStats.securityScore}
                </div>
                <div className="text-xs text-gray-400">Security Score</div>
              </div>
            </div>
          </div>

          {/* Proxy Controls */}
          <div className="p-4 border-b border-gray-800">
            <h4 className="font-bold mb-3 flex items-center gap-2">
              <Network className="w-4 h-4" />
              Proxy Controls
            </h4>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm">HTTP/2 Proxy</span>
                <button
                  onClick={toggleProxy}
                  className={`px-3 py-1 rounded text-sm font-medium transition ${
                    isProxyActive 
                      ? 'bg-green-600 hover:bg-green-700' 
                      : 'bg-red-600 hover:bg-red-700'
                  }`}
                >
                  {isProxyActive ? 'Stop' : 'Start'}
                </button>
              </div>
              
              <div>
                <label className="text-xs text-gray-400">Proxy Port</label>
                <input
                  type="number"
                  value={proxyPort}
                  onChange={(e) => setProxyPort(Number(e.target.value))}
                  className="w-full mt-1 bg-gray-800 px-2 py-1 rounded border border-gray-700 focus:border-purple-500 outline-none text-sm"
                />
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-xs">Intercept Traffic</span>
                <input
                  type="checkbox"
                  checked={interceptTraffic}
                  onChange={(e) => setInterceptTraffic(e.target.checked)}
                  className="w-4 h-4"
                />
              </div>
            </div>
          </div>

          {/* Traffic History */}
          <div className="p-4 border-b border-gray-800">
            <div className="flex items-center justify-between mb-3">
              <h4 className="font-bold flex items-center gap-2">
                <Eye className="w-4 h-4" />
                Traffic History ({trafficHistory.length})
              </h4>
              <button
                onClick={clearTraffic}
                className="text-xs text-red-400 hover:text-red-300"
              >
                Clear
              </button>
            </div>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {trafficHistory.map((request) => (
                <div
                  key={request.id}
                  onClick={() => setSelectedRequest(request)}
                  className={`p-2 rounded cursor-pointer transition ${
                    selectedRequest?.id === request.id 
                      ? 'bg-purple-600 border border-purple-400' 
                      : 'bg-gray-800 hover:bg-gray-750'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-xs font-bold ${
                      request.method === 'GET' ? 'text-green-400' :
                      request.method === 'POST' ? 'text-blue-400' :
                      request.method === 'PUT' ? 'text-yellow-400' :
                      request.method === 'DELETE' ? 'text-red-400' :
                      'text-gray-400'
                    }`}>
                      {request.method}
                    </span>
                    <span className={`text-xs font-bold ${
                      request.status >= 200 && request.status < 300 ? 'text-green-400' :
                      request.status >= 300 && request.status < 400 ? 'text-yellow-400' :
                      request.status >= 400 ? 'text-red-400' : 'text-gray-400'
                    }`}>
                      {request.status}
                    </span>
                  </div>
                  <div className="flex items-center space-x-1 mb-1">
                    {request.intercepted && <div className="w-2 h-2 bg-orange-400 rounded-full"></div>}
                    {request.hasVulnerability && <div className="w-2 h-2 bg-red-400 rounded-full"></div>}
                    {request.httpVersion && <div className="w-2 h-2 bg-blue-400 rounded-full"></div>}
                  </div>
                  <p className="text-xs text-gray-400 truncate">{request.url}</p>
                  <p className="text-xs text-gray-500">{request.responseTime}ms</p>
                </div>
              ))}
            </div>
          </div>

          {/* Intercepted Requests */}
          <div className="p-4">
            <h4 className="font-bold mb-3 flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Intercepted ({interceptedRequests.length})
            </h4>
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {interceptedRequests.map((request) => (
                <div
                  key={request.id}
                  className="p-2 bg-orange-900 border border-orange-600 rounded"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold">{request.method}</span>
                    <button
                      onClick={() => interceptRequest(request.id)}
                      className="text-xs px-2 py-1 bg-gray-800 rounded hover:bg-gray-700 transition"
                    >
                      Modify
                    </button>
                  </div>
                  <p className="text-xs text-gray-400 truncate">{request.url}</p>
                  {request.hasVulnerability && (
                    <span className="inline-block mt-1 px-1 py-0.5 bg-red-600 text-white text-xs rounded">
                      {request.vulnerabilityType}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 flex flex-col">
          {/* Header */}
          <div className="bg-gray-900 border-b border-gray-800 p-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold bg-gradient-to-r from-orange-400 to-red-500 bg-clip-text text-transparent">
                  HETTY Integration
                </h2>
                <p className="text-sm text-gray-400 mt-1">
                  HTTP/2 Security Testing & Vulnerability Assessment
                </p>
              </div>
              <div className="flex items-center space-x-2">
                <button
                  onClick={exportTrafficData}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition text-sm"
                >
                  <Download className="w-4 h-4 inline mr-1" />
                  Export
                </button>
                <button
                  onClick={startVulnerabilityScan}
                  disabled={vulnerabilityScan.isScanning}
                  className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 rounded-lg transition text-sm"
                >
                  {vulnerabilityScan.isScanning ? (
                    <Pause className="w-4 h-4 inline mr-1" />
                  ) : (
                    <Zap className="w-4 h-4 inline mr-1" />
                  )}
                  {vulnerabilityScan.isScanning ? 'Scanning...' : 'Start Scan'}
                </button>
              </div>
            </div>
          </div>

          {/* Main Tabs */}
          <div className="border-b border-gray-800">
            <div className="flex">
              {[
                { id: 'overview', label: 'Overview', icon: TrendingUp },
                { id: 'vulnerabilities', label: 'Vulnerabilities', icon: Bug },
                { id: 'http2-tests', label: 'HTTP/2 Tests', icon: Network },
                { id: 'proxy-settings', label: 'Proxy Settings', icon: Settings }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab?.(tab.id)}
                  className="flex items-center gap-2 px-4 py-3 font-medium transition border-b-2 border-transparent hover:border-orange-400"
                >
                  <tab.icon className="w-4 h-4" />
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-6">
            {selectedRequest ? (
              <div className="space-y-6">
                {/* Request Details */}
                <div className="bg-gray-800 rounded-lg p-6">
                  <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                    <Target className="w-5 h-5" />
                    Request Analysis
                  </h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <h4 className="font-bold mb-3">Request Information</h4>
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-400">Method:</span>
                          <span className={`font-bold ${
                            selectedRequest.method === 'GET' ? 'text-green-400' :
                            selectedRequest.method === 'POST' ? 'text-blue-400' :
                            selectedRequest.method === 'PUT' ? 'text-yellow-400' :
                            'text-red-400'
                          }`}>{selectedRequest.method}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">URL:</span>
                          <span className="font-mono text-xs">{selectedRequest.url}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">HTTP Version:</span>
                          <span className="text-blue-400">{selectedRequest.httpVersion}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Status:</span>
                          <span className={`font-bold ${getStatusColor(selectedRequest.status)}`}>
                            {selectedRequest.status}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Response Time:</span>
                          <span className="text-yellow-400">{selectedRequest.responseTime}ms</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Size:</span>
                          <span className="text-cyan-400">{(selectedRequest.size / 1024).toFixed(2)}KB</span>
                        </div>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-bold mb-3">Security Analysis</h4>
                      <div className="space-y-2">
                        {selectedRequest.securityFlags.map((flag, index) => (
                          <div key={index} className="flex items-center space-x-2">
                            <CheckCircle className="w-4 h-4 text-green-400" />
                            <span className="text-sm">{flag}</span>
                          </div>
                        ))}
                        {selectedRequest.hasVulnerability && (
                          <div className="flex items-center space-x-2 p-2 bg-red-900 rounded">
                            <AlertTriangle className="w-4 h-4 text-red-400" />
                            <span className="text-sm">Vulnerability: {selectedRequest.vulnerabilityType}</span>
                          </div>
                        )}
                        {selectedRequest.intercepted && (
                          <div className="flex items-center space-x-2 p-2 bg-orange-900 rounded">
                            <Eye className="w-4 h-4 text-orange-400" />
                            <span className="text-sm">Intercepted and Modified</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* HTTP/2 Specific Analysis */}
                  {selectedRequest.httpVersion === 'HTTP/2' && (
                    <div className="mt-6">
                      <h4 className="font-bold mb-3">HTTP/2 Specific Analysis</h4>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="bg-gray-900 p-3 rounded">
                          <h5 className="font-bold text-sm mb-2">Stream Priority</h5>
                          <div className="flex items-center space-x-2">
                            <CheckCircle className="w-4 h-4 text-green-400" />
                            <span className="text-sm">Normal</span>
                          </div>
                        </div>
                        <div className="bg-gray-900 p-3 rounded">
                          <h5 className="font-bold text-sm mb-2">Header Compression</h5>
                          <div className="flex items-center space-x-2">
                            <CheckCircle className="w-4 h-4 text-green-400" />
                            <span className="text-sm">HPACK Working</span>
                          </div>
                        </div>
                        <div className="bg-gray-900 p-3 rounded">
                          <h5 className="font-bold text-sm mb-2">Flow Control</h5>
                          <div className="flex items-center space-x-2">
                            <CheckCircle className="w-4 h-4 text-green-400" />
                            <span className="text-sm">Window OK</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="text-center py-12 text-gray-400">
                <Network className="w-16 h-16 mx-auto mb-4 opacity-50" />
                <h3 className="text-xl font-bold mb-2">HETTY HTTP/2 Testing Interface</h3>
                <p className="mb-6">Select a request from the sidebar to analyze traffic and security</p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-4xl mx-auto">
                  <div className="bg-gray-800 p-6 rounded-lg">
                    <Shield className="w-8 h-8 text-green-400 mb-3" />
                    <h4 className="font-bold mb-2">HTTP/2 Security Testing</h4>
                    <p className="text-sm text-gray-400">Test HTTP/2 specific vulnerabilities including stream manipulation, header compression attacks, and flow control bypasses.</p>
                  </div>
                  <div className="bg-gray-800 p-6 rounded-lg">
                    <Eye className="w-8 h-8 text-blue-400 mb-3" />
                    <h4 className="font-bold mb-2">Live Traffic Interception</h4>
                    <p className="text-sm text-gray-400">Intercept and modify HTTP/2 traffic in real-time with full protocol visibility and detailed analysis.</p>
                  </div>
                  <div className="bg-gray-800 p-6 rounded-lg">
                    <Zap className="w-8 h-8 text-yellow-400 mb-3" />
                    <h4 className="font-bold mb-2">Automated Vulnerability Scanning</h4>
                    <p className="text-sm text-gray-400">Comprehensive vulnerability assessment including OWASP Top 10 and HTTP/2 specific attack vectors.</p>
                  </div>
                  <div className="bg-gray-800 p-6 rounded-lg">
                    <Database className="w-8 h-8 text-purple-400 mb-3" />
                    <h4 className="font-bold mb-2">Detailed Reporting</h4>
                    <p className="text-sm text-gray-400">Generate comprehensive reports with proof-of-concept exploits and remediation guidance.</p>
                  </div>
                </div>
              </div>
            )}

            {/* Vulnerability Scan Progress */}
            {vulnerabilityScan.isScanning && (
              <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                <div className="bg-gray-800 p-6 rounded-lg max-w-md w-full mx-4">
                  <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                    <Zap className="w-5 h-5" />
                    Vulnerability Scan in Progress
                  </h3>
                  <div className="mb-4">
                    <div className="flex justify-between text-sm mb-2">
                      <span>Progress</span>
                      <span>{Math.round(vulnerabilityScan.progress)}%</span>
                    </div>
                    <div className="w-full bg-gray-700 rounded-full h-2">
                      <div
                        className="bg-gradient-to-r from-green-500 to-blue-500 h-2 rounded-full transition-all duration-300"
                        style={{ width: `${vulnerabilityScan.progress}%` }}
                      ></div>
                    </div>
                  </div>
                  <div className="text-sm text-gray-400">
                    Scanning for vulnerabilities across multiple attack vectors...
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default HettyIntegration;
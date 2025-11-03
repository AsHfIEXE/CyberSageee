import React, { useState, useEffect, useCallback } from 'react';
import { 
  Play, 
  Square, 
  Plus, 
  Trash2, 
  Copy, 
  Save, 
  Download,
  Upload,
  Settings,
  Code,
  Globe,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  Zap,
  Eye,
  EyeOff
} from 'lucide-react';
import { apiService, HttpRequestPayload } from '../services/api';

// Types
interface Header {
  key: string;
  value: string;
  enabled: boolean;
}

interface Request {
  id: string;
  name: string;
  method: string;
  url: string;
  headers: Header[];
  body: string;
  bodyType: 'raw' | 'json' | 'form';
  createdAt: Date;
  lastModified: Date;
}

interface Response {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string | object;
  time: number;
  size: number;
  timestamp: Date;
}

interface HistoryEntry {
  id: string;
  request: Request;
  response?: Response;
  timestamp: Date;
  duration: number;
}

const HttpRepeater: React.FC = () => {
  const [isDarkMode] = useState(true);
  const [requests, setRequests] = useState<Request[]>([
    {
      id: '1',
      name: 'GET Request',
      method: 'GET',
      url: 'https://example.com/api/users',
      headers: [
        { key: 'Content-Type', value: 'application/json', enabled: true },
        { key: 'Authorization', value: 'Bearer token-here', enabled: true }
      ],
      body: '',
      bodyType: 'raw',
      createdAt: new Date(),
      lastModified: new Date()
    }
  ]);
  
  const [activeRequestId, setActiveRequestId] = useState('1');
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'headers' | 'body' | 'params' | 'auth'>('headers');
  const [responseTab, setResponseTab] = useState<'body' | 'headers' | 'raw'>('body');
  const [showPayloadInjector, setShowPayloadInjector] = useState(false);
  const [selectedPayloads, setSelectedPayloads] = useState<string[]>([]);
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected' | 'connecting'>('connecting');

  const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];
  
  // Get active request
  const activeRequest = requests.find(r => r.id === activeRequestId) || requests[0];
  
  // Load from localStorage on component mount
  useEffect(() => {
    const savedRequests = localStorage.getItem('httpRepeater_requests');
    const savedHistory = localStorage.getItem('httpRepeater_history');
    
    if (savedRequests) {
      try {
        const parsed = JSON.parse(savedRequests);
        setRequests(parsed);
      } catch (e) {
        console.error('Failed to load saved requests:', e);
      }
    }
    
    if (savedHistory) {
      try {
        const parsed = JSON.parse(savedHistory);
        setHistory(parsed);
      } catch (e) {
        console.error('Failed to load saved history:', e);
      }
    }
  }, []);

  // Save to localStorage whenever data changes
  useEffect(() => {
    localStorage.setItem('httpRepeater_requests', JSON.stringify(requests));
  }, [requests]);

  useEffect(() => {
    localStorage.setItem('httpRepeater_history', JSON.stringify(history));
  }, [history]);

  // Test connection to CyberSage backend
  useEffect(() => {
    const testConnection = async () => {
      try {
        setConnectionStatus('connecting');
        const isConnected = await apiService.testConnection();
        setConnectionStatus(isConnected ? 'connected' : 'disconnected');
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

  // Payload injection patterns for vulnerability testing
  const securityPayloads = {
    xss: [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg/onload=alert(1)>',
      'javascript:alert(1)',
      '\"><script>alert(1)</script>',
      "javascript:alert('XSS')",
      '<iframe src=javascript:alert(1)>',
      '<body onload=alert(1)>'
    ],
    sqli: [
      "'",
      "' OR '1'='1",
      "' OR '1'='1' --",
      "' OR '1'='1' /*",
      "admin' --",
      "' UNION SELECT NULL--",
      "' AND 1=2 UNION SELECT 1,2,3--",
      "1; DROP TABLE users--"
    ],
    command: [
      '; ls -la',
      '; whoami',
      '| whoami',
      '& dir',
      '`whoami`',
      '$(whoami)',
      '; cat /etc/passwd',
      '| ping -c 1 127.0.0.1'
    ],
    pathTraversal: [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\win.ini',
      '....//....//....//etc/passwd',
      '..%252f..%252f..%252fetc%252fpasswd',
      'file:///etc/passwd',
      '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd'
    ],
    lfi: [
      '/etc/passwd',
      '/var/log/apache2/access.log',
      'C:\\Windows\\System32\\drivers\\etc\\hosts',
      '../../../../etc/passwd',
      '..\\..\\..\\..\\..\\..\\..\\windows\\win.ini'
    ]
  };

  // Update request
  const updateRequest = useCallback((updates: Partial<Request>) => {
    const updatedRequest = { ...activeRequest, ...updates, lastModified: new Date() };
    setRequests(prev => prev.map(r => r.id === activeRequest.id ? updatedRequest : r));
  }, [activeRequest]);

  // Add new request
  const addNewRequest = useCallback(() => {
    const newRequest: Request = {
      id: Date.now().toString(),
      name: `Request ${requests.length + 1}`,
      method: 'GET',
      url: '',
      headers: [{ key: 'Content-Type', value: 'application/json', enabled: true }],
      body: '',
      bodyType: 'raw',
      createdAt: new Date(),
      lastModified: new Date()
    };
    setRequests(prev => [...prev, newRequest]);
    setActiveRequestId(newRequest.id);
  }, [requests.length]);

  // Delete request
  const deleteRequest = useCallback((id: string) => {
    if (requests.length > 1) {
      setRequests(prev => prev.filter(r => r.id !== id));
      if (activeRequestId === id) {
        const remaining = requests.filter(r => r.id !== id);
        setActiveRequestId(remaining[0]?.id || '');
      }
    }
  }, [requests, activeRequestId]);

  // Send HTTP request using CyberSage backend
  const sendRequest = useCallback(async () => {
    if (!activeRequest.url) return;

    setLoading(true);
    const startTime = Date.now();

    try {
      // Build headers object
      const headersObj: Record<string, string> = {};
      activeRequest.headers
        .filter(h => h.enabled && h.key.trim())
        .forEach(h => {
          headersObj[h.key] = h.value;
        });

      // Build request payload for CyberSage API
      const requestPayload: HttpRequestPayload = {
        method: activeRequest.method,
        url: activeRequest.url,
        headers: headersObj,
        body: activeRequest.body || '',
        timeout: 30000,
        scan_id: `repeater_${Date.now()}`
      };

      console.log('Sending request via CyberSage API:', requestPayload);

      // Send request using CyberSage backend
      const result = await apiService.sendHttpRequest(requestPayload);
      const endTime = Date.now();
      const duration = endTime - startTime;

      // Process response
      let processedResponse: Response;
      if (result.status === 'error') {
        processedResponse = {
          status: 0,
          statusText: 'Request Failed',
          headers: {},
          body: result.error || 'Unknown error occurred',
          time: duration,
          size: 0,
          timestamp: new Date()
        };
      } else if (result.data) {
        const response = result.data.response;
        processedResponse = {
          status: response.code || 0,
          statusText: `HTTP ${response.code}`,
          headers: response.headers || {},
          body: response.body || '',
          time: response.time_ms || duration,
          size: (response.body || '').length,
          timestamp: new Date()
        };
      } else {
        processedResponse = {
          status: 0,
          statusText: 'No Response',
          headers: {},
          body: 'No response data received',
          time: duration,
          size: 0,
          timestamp: new Date()
        };
      }

      // Add to history
      const historyEntry: HistoryEntry = {
        id: Date.now().toString(),
        request: { ...activeRequest },
        response: processedResponse,
        timestamp: new Date(),
        duration
      };

      setHistory(prev => [historyEntry, ...prev.slice(0, 99)]); // Keep last 100 entries

      console.log('Request completed successfully');

    } catch (error) {
      console.error('Request failed:', error);
      
      const errorResponse: Response = {
        status: 0,
        statusText: 'Network Error',
        headers: {},
        body: `Request failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        time: Date.now() - startTime,
        size: 0,
        timestamp: new Date()
      };

      const historyEntry: HistoryEntry = {
        id: Date.now().toString(),
        request: { ...activeRequest },
        response: errorResponse,
        timestamp: new Date(),
        duration: Date.now() - startTime
      };

      setHistory(prev => [historyEntry, ...prev.slice(0, 99)]);
    } finally {
      setLoading(false);
    }
  }, [activeRequest]);

  // Inject payloads for security testing
  const injectPayloads = useCallback(() => {
    if (selectedPayloads.length === 0) return;

    const payloadResults = [];
    
    selectedPayloads.forEach((payload) => {
      let testValue = '';
      
      // Determine where to inject based on method and content
      if (activeRequest.method === 'GET') {
        // For GET requests, inject into URL parameters
        const url = new URL(activeRequest.url, 'http://localhost');
        const paramName = 'test_param';
        url.searchParams.set(paramName, payload);
        testValue = url.toString().replace('http://localhost', '');
      } else {
        // For POST/PUT requests, inject into body
        testValue = payload;
      }

      // Create test request
      const testRequest: Request = {
        ...activeRequest,
        id: `payload_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        name: `Payload Test: ${payload.substring(0, 30)}...`,
        url: activeRequest.method === 'GET' ? testValue : activeRequest.url,
        body: activeRequest.method === 'GET' ? '' : testValue,
        lastModified: new Date()
      };

      payloadResults.push(testRequest);
    });

    // Add test requests to the requests list
    setRequests(prev => [...prev, ...payloadResults]);
    setSelectedPayloads([]);
    setShowPayloadInjector(false);
  }, [selectedPayloads, activeRequest]);

  // Format response body for display
  const formatResponseBody = (body: string | object) => {
    if (typeof body === 'string') {
      try {
        const parsed = JSON.parse(body);
        return JSON.stringify(parsed, null, 2);
      } catch {
        return body;
      }
    }
    return JSON.stringify(body, null, 2);
  };

  // Keyboard shortcut
  useEffect(() => {
    const handleKeyPress = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        if (!loading && activeRequest.url) {
          sendRequest();
        }
      }
    };

    window.addEventListener('keydown', handleKeyPress);
    return () => window.removeEventListener('keydown', handleKeyPress);
  }, [sendRequest, loading, activeRequest.url]);

  return (
    <div className={`min-h-screen ${isDarkMode ? 'bg-gray-950' : 'bg-gray-50'}`}>
      <div className="flex h-screen">
        {/* Request List Sidebar */}
        <div className={`w-80 ${isDarkMode ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'} border-r overflow-y-auto`}>
          <div className="p-4">
            {/* Connection Status */}
            <div className="flex items-center justify-between mb-4 p-3 rounded-lg border ${
              connectionStatus === 'connected' ? 'bg-green-500/10 border-green-500/30 text-green-400' :
              connectionStatus === 'connecting' ? 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400' :
              'bg-red-500/10 border-red-500/30 text-red-400'
            }">
              <div className="flex items-center space-x-2">
                <div className={`w-2 h-2 rounded-full ${
                  connectionStatus === 'connected' ? 'bg-green-400' :
                  connectionStatus === 'connecting' ? 'bg-yellow-400 animate-pulse' :
                  'bg-red-400'
                }`}></div>
                <span className="text-sm font-medium">
                  {connectionStatus === 'connected' ? 'CyberSage Connected' :
                   connectionStatus === 'connecting' ? 'Connecting...' :
                   'Disconnected'}
                </span>
              </div>
              {connectionStatus === 'disconnected' && (
                <button
                  onClick={() => apiService.testConnection().then(isConnected => 
                    setConnectionStatus(isConnected ? 'connected' : 'disconnected')
                  )}
                  className="text-xs px-2 py-1 bg-red-500/20 hover:bg-red-500/30 rounded transition-colors"
                >
                  Retry
                </button>
              )}
            </div>

            <div className="flex items-center justify-between mb-4">
              <h3 className={`text-lg font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                Requests ({requests.length})
              </h3>
              <button
                onClick={addNewRequest}
                className="p-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors"
              >
                <Plus className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-2">
              {requests.map((request) => (
                <div
                  key={request.id}
                  className={`p-3 rounded-lg cursor-pointer transition-colors ${
                    request.id === activeRequestId
                      ? 'bg-blue-500 text-white'
                      : isDarkMode
                      ? 'bg-gray-800 hover:bg-gray-700 text-gray-300'
                      : 'bg-gray-100 hover:bg-gray-200 text-gray-700'
                  }`}
                  onClick={() => setActiveRequestId(request.id)}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      request.method === 'GET' ? 'bg-green-500/20 text-green-400' :
                      request.method === 'POST' ? 'bg-blue-500/20 text-blue-400' :
                      request.method === 'PUT' ? 'bg-yellow-500/20 text-yellow-400' :
                      request.method === 'DELETE' ? 'bg-red-500/20 text-red-400' :
                      'bg-gray-500/20 text-gray-400'
                    }`}>
                      {request.method}
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        deleteRequest(request.id);
                      }}
                      className="text-red-400 hover:text-red-300"
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>
                  <p className="text-sm font-medium truncate">{request.name}</p>
                  <p className={`text-xs truncate ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                    {request.url}
                  </p>
                </div>
              ))}
            </div>

            {/* Quick Payload Injector */}
            <div className="mt-6">
              <button
                onClick={() => setShowPayloadInjector(true)}
                className={`w-full p-3 rounded-lg border-2 border-dashed transition-colors ${
                  isDarkMode
                    ? 'border-yellow-500 text-yellow-400 hover:bg-yellow-500/10'
                    : 'border-yellow-500 text-yellow-600 hover:bg-yellow-50'
                }`}
              >
                <Zap className="w-4 h-4 inline mr-2" />
                Inject Security Payloads
              </button>
            </div>
          </div>
        </div>

        {/* Main Request/Response Panel */}
        <div className="flex-1 flex flex-col">
          {/* Request Builder Header */}
          <div className={`${isDarkMode ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'} border-b p-4`}>
            <div className="flex items-center space-x-4">
              {/* Method Selector */}
              <select
                value={activeRequest.method}
                onChange={(e) => updateRequest({ method: e.target.value })}
                className={`px-4 py-2 rounded-lg font-medium border ${
                  isDarkMode
                    ? 'bg-gray-800 border-gray-600 text-white'
                    : 'bg-white border-gray-300 text-gray-900'
                }`}
              >
                {httpMethods.map(method => (
                  <option key={method} value={method}>{method}</option>
                ))}
              </select>

              {/* URL Input */}
              <input
                type="text"
                value={activeRequest.url}
                onChange={(e) => updateRequest({ url: e.target.value })}
                placeholder="Enter URL (use {{variable}} for environment variables)"
                className={`flex-1 px-4 py-2 rounded-lg border ${
                  isDarkMode
                    ? 'bg-gray-800 border-gray-600 text-white placeholder-gray-400'
                    : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'
                }`}
              />

              {/* Send Button */}
              <button
                onClick={sendRequest}
                disabled={loading || !activeRequest.url}
                className="px-6 py-2 bg-green-500 hover:bg-green-600 disabled:bg-gray-500 text-white rounded-lg font-medium transition-colors flex items-center space-x-2"
              >
                {loading ? (
                  <Square className="w-4 h-4" />
                ) : (
                  <Play className="w-4 h-4" />
                )}
                <span>{loading ? 'Sending...' : 'Send (Ctrl+Enter)'}</span>
              </button>

              {/* Save Button */}
              <button
                className={`p-2 rounded-lg border transition-colors ${
                  isDarkMode
                    ? 'border-gray-600 hover:bg-gray-800 text-gray-300'
                    : 'border-gray-300 hover:bg-gray-100 text-gray-700'
                }`}
              >
                <Save className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Request/Response Split */}
          <div className="flex-1 flex">
            {/* Request Panel */}
            <div className="flex-1 border-r border-gray-700">
              <div className={`${isDarkMode ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'} border-b`}>
                <div className="flex">
                  {[
                    { id: 'headers', label: 'Headers', icon: Globe },
                    { id: 'body', label: 'Body', icon: Code },
                    { id: 'params', label: 'Params', icon: Settings },
                    { id: 'auth', label: 'Auth', icon: Shield }
                  ].map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id as any)}
                      className={`flex items-center space-x-2 px-4 py-3 border-b-2 font-medium transition-colors ${
                        activeTab === tab.id
                          ? 'border-blue-500 text-blue-400'
                          : 'border-transparent text-gray-400 hover:text-gray-300'
                      }`}
                    >
                      <tab.icon className="w-4 h-4" />
                      <span>{tab.label}</span>
                    </button>
                  ))}
                </div>
              </div>

              <div className="p-4 overflow-y-auto h-full">
                {activeTab === 'headers' && (
                  <div className="space-y-3">
                    {activeRequest.headers.map((header, index) => (
                      <div key={index} className="flex items-center space-x-2">
                        <input
                          type="checkbox"
                          checked={header.enabled}
                          onChange={(e) => {
                            const newHeaders = [...activeRequest.headers];
                            newHeaders[index] = { ...header, enabled: e.target.checked };
                            updateRequest({ headers: newHeaders });
                          }}
                          className="w-4 h-4"
                        />
                        <input
                          type="text"
                          value={header.key}
                          onChange={(e) => {
                            const newHeaders = [...activeRequest.headers];
                            newHeaders[index] = { ...header, key: e.target.value };
                            updateRequest({ headers: newHeaders });
                          }}
                          placeholder="Header name"
                          className={`flex-1 px-3 py-2 rounded border ${
                            isDarkMode
                              ? 'bg-gray-800 border-gray-600 text-white'
                              : 'bg-white border-gray-300 text-gray-900'
                          }`}
                        />
                        <input
                          type="text"
                          value={header.value}
                          onChange={(e) => {
                            const newHeaders = [...activeRequest.headers];
                            newHeaders[index] = { ...header, value: e.target.value };
                            updateRequest({ headers: newHeaders });
                          }}
                          placeholder="Header value"
                          className={`flex-1 px-3 py-2 rounded border ${
                            isDarkMode
                              ? 'bg-gray-800 border-gray-600 text-white'
                              : 'bg-white border-gray-300 text-gray-900'
                          }`}
                        />
                        <button
                          onClick={() => {
                            const newHeaders = activeRequest.headers.filter((_, i) => i !== index);
                            updateRequest({ headers: newHeaders });
                          }}
                          className="p-2 text-red-400 hover:text-red-300"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                    <button
                      onClick={() => {
                        const newHeaders = [...activeRequest.headers, { key: '', value: '', enabled: true }];
                        updateRequest({ headers: newHeaders });
                      }}
                      className={`px-4 py-2 rounded-lg border transition-colors ${
                        isDarkMode
                          ? 'border-gray-600 hover:bg-gray-800 text-gray-300'
                          : 'border-gray-300 hover:bg-gray-100 text-gray-700'
                      }`}
                    >
                      Add Header
                    </button>
                  </div>
                )}

                {activeTab === 'body' && (
                  <div className="space-y-4">
                    <div className="flex space-x-2">
                      {['raw', 'json', 'form'].map((type) => (
                        <button
                          key={type}
                          onClick={() => updateRequest({ bodyType: type as any })}
                          className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
                            activeRequest.bodyType === type
                              ? 'bg-blue-500 text-white'
                              : isDarkMode
                              ? 'bg-gray-800 text-gray-300 hover:bg-gray-700'
                              : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                          }`}
                        >
                          {type.toUpperCase()}
                        </button>
                      ))}
                    </div>
                    <textarea
                      value={activeRequest.body}
                      onChange={(e) => updateRequest({ body: e.target.value })}
                      placeholder={
                        activeRequest.bodyType === 'json'
                          ? '{\n  "key": "value"\n}'
                          : 'Request body...'
                      }
                      rows={12}
                      className={`w-full px-4 py-3 rounded-lg font-mono text-sm border ${
                        isDarkMode
                          ? 'bg-gray-800 border-gray-600 text-white'
                          : 'bg-white border-gray-300 text-gray-900'
                      }`}
                    />
                  </div>
                )}

                {activeTab === 'params' && (
                  <div className="text-center py-8">
                    <Settings className="w-12 h-12 mx-auto mb-4 text-gray-400" />
                    <p className="text-gray-400">Query parameters and other request options</p>
                  </div>
                )}

                {activeTab === 'auth' && (
                  <div className="space-y-4">
                    <div className={`p-4 rounded-lg border ${
                      isDarkMode ? 'bg-gray-800 border-gray-600' : 'bg-gray-50 border-gray-300'
                    }`}>
                      <h4 className="font-medium mb-3">Bearer Token</h4>
                      <input
                        type="text"
                        placeholder="Enter token or use {{token}}"
                        className={`w-full px-3 py-2 rounded border ${
                          isDarkMode
                            ? 'bg-gray-700 border-gray-600 text-white'
                            : 'bg-white border-gray-300 text-gray-900'
                        }`}
                      />
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Response Panel */}
            <div className="flex-1">
              <div className={`${isDarkMode ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'} border-b p-4`}>
                <div className="flex items-center justify-between">
                  <h3 className={`font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                    Response
                  </h3>
                  <div className="flex space-x-2">
                    <button
                      onClick={() => setResponseTab('body')}
                      className={`px-3 py-1 rounded text-sm transition-colors ${
                        responseTab === 'body'
                          ? 'bg-blue-500 text-white'
                          : isDarkMode
                          ? 'text-gray-400 hover:text-gray-300'
                          : 'text-gray-600 hover:text-gray-700'
                      }`}
                    >
                      Body
                    </button>
                    <button
                      onClick={() => setResponseTab('headers')}
                      className={`px-3 py-1 rounded text-sm transition-colors ${
                        responseTab === 'headers'
                          ? 'bg-blue-500 text-white'
                          : isDarkMode
                          ? 'text-gray-400 hover:text-gray-300'
                          : 'text-gray-600 hover:text-gray-700'
                      }`}
                    >
                      Headers
                    </button>
                    <button
                      onClick={() => setResponseTab('raw')}
                      className={`px-3 py-1 rounded text-sm transition-colors ${
                        responseTab === 'raw'
                          ? 'bg-blue-500 text-white'
                          : isDarkMode
                          ? 'text-gray-400 hover:text-gray-300'
                          : 'text-gray-600 hover:text-gray-700'
                      }`}
                    >
                      Raw
                    </button>
                  </div>
                </div>
              </div>

              <div className="p-4 overflow-y-auto h-full">
                {history.length > 0 && (
                  <div className="space-y-4">
                    {history.slice(0, 1).map((entry) => (
                      <div key={entry.id}>
                        {entry.response ? (
                          <div>
                            {/* Response Status */}
                            <div className="flex items-center space-x-4 mb-4">
                              <span className={`text-lg font-mono ${
                                entry.response.status < 300 ? 'text-green-400' :
                                entry.response.status < 400 ? 'text-yellow-400' :
                                entry.response.status < 500 ? 'text-orange-400' :
                                'text-red-400'
                              }`}>
                                {entry.response.status} {entry.response.statusText}
                              </span>
                              <span className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                {entry.response.time}ms
                              </span>
                              <span className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                {(entry.response.size / 1024).toFixed(2)}KB
                              </span>
                            </div>

                            {/* Response Content */}
                            {responseTab === 'body' && (
                              <pre className={`p-4 rounded-lg font-mono text-sm overflow-x-auto ${
                                isDarkMode ? 'bg-gray-800 text-white' : 'bg-gray-100 text-gray-900'
                              }`}>
                                {formatResponseBody(entry.response.body)}
                              </pre>
                            )}

                            {responseTab === 'headers' && (
                              <div className="space-y-2">
                                {Object.entries(entry.response.headers).map(([key, value]) => (
                                  <div key={key} className="flex">
                                    <span className={`font-mono text-sm w-1/3 ${
                                      isDarkMode ? 'text-blue-400' : 'text-blue-600'
                                    }`}>
                                      {key}:
                                    </span>
                                    <span className={`font-mono text-sm ${
                                      isDarkMode ? 'text-gray-300' : 'text-gray-700'
                                    }`}>
                                      {value}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            )}

                            {responseTab === 'raw' && (
                              <pre className={`p-4 rounded-lg font-mono text-sm overflow-x-auto ${
                                isDarkMode ? 'bg-gray-800 text-white' : 'bg-gray-100 text-gray-900'
                              }`}>
                                HTTP/1.1 {entry.response.status} {entry.response.statusText}
                                {Object.entries(entry.response.headers).map(([key, value]) => (
                                  <div key={key}>{key}: {value}</div>
                                ))}
                                
                                {typeof entry.response.body === 'string' ? entry.response.body : JSON.stringify(entry.response.body)}
                              </pre>
                            )}
                          </div>
                        ) : (
                          <div className="text-center py-8">
                            <div className="w-16 h-16 mx-auto mb-4 p-4 bg-yellow-500/20 rounded-full">
                              <AlertTriangle className="w-8 h-8 text-yellow-400 mx-auto" />
                            </div>
                            <p className="text-yellow-400">Request completed but no response data</p>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {history.length === 0 && !loading && (
                  <div className="text-center py-12">
                    <div className="w-16 h-16 mx-auto mb-4 p-4 bg-gray-500/20 rounded-full">
                      <Globe className="w-8 h-8 text-gray-400 mx-auto" />
                    </div>
                    <p className="text-gray-400">Send a request to see the response</p>
                    <p className="text-sm text-gray-500 mt-2">Use Ctrl+Enter to send quickly</p>
                  </div>
                )}

                {loading && (
                  <div className="text-center py-12">
                    <div className="w-16 h-16 mx-auto mb-4 p-4 bg-blue-500/20 rounded-full animate-pulse">
                      <Clock className="w-8 h-8 text-blue-400 mx-auto" />
                    </div>
                    <p className="text-blue-400">Sending request...</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Payload Injection Modal */}
      {showPayloadInjector && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-xl p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto`}>
            <h3 className={`text-xl font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-4`}>
              Inject Security Payloads
            </h3>
            
            <div className="space-y-6">
              {Object.entries(securityPayloads).map(([category, payloads]) => (
                <div key={category}>
                  <h4 className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-2 capitalize`}>
                    {category} Payloads
                  </h4>
                  <div className="grid grid-cols-2 gap-2">
                    {payloads.map((payload, index) => (
                      <label key={index} className="flex items-start space-x-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={selectedPayloads.includes(payload)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedPayloads(prev => [...prev, payload]);
                            } else {
                              setSelectedPayloads(prev => prev.filter(p => p !== payload));
                            }
                          }}
                          className="mt-1"
                        />
                        <span className={`text-sm font-mono ${
                          isDarkMode ? 'text-gray-300' : 'text-gray-700'
                        }`}>
                          {payload}
                        </span>
                      </label>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            <div className="flex justify-end space-x-3 mt-6">
              <button
                onClick={() => setShowPayloadInjector(false)}
                className={`px-4 py-2 rounded-lg border transition-colors ${
                  isDarkMode
                    ? 'border-gray-600 hover:bg-gray-700 text-gray-300'
                    : 'border-gray-300 hover:bg-gray-50 text-gray-700'
                }`}
              >
                Cancel
              </button>
              <button
                onClick={injectPayloads}
                disabled={selectedPayloads.length === 0}
                className="px-4 py-2 bg-yellow-500 hover:bg-yellow-600 disabled:bg-gray-500 text-white rounded-lg transition-colors"
              >
                Create {selectedPayloads.length} Test Requests
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default HttpRepeater;
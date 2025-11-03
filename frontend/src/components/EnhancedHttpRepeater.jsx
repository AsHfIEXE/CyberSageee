import React, { useState, useEffect, useCallback } from 'react';
import { 
  Send, Plus, Trash2, Copy, Play, Square, Settings, Code, Globe, 
  Shield, AlertTriangle, CheckCircle, Target, Search, Bug,
  Database, Terminal, Eye, Layers, Zap, Cpu
} from 'lucide-react';

const EnhancedHttpRepeater = () => {
  // Core request state
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('');
  const [headers, setHeaders] = useState([{ key: '', value: '', enabled: true }]);
  const [body, setBody] = useState('');
  const [bodyType, setBodyType] = useState('raw');
  
  // Response state
  const [response, setResponse] = useState(null);
  const [loading, setLoading] = useState(false);
  const [responseTime, setResponseTime] = useState(0);
  const [responseSize, setResponseSize] = useState(0);
  
  // UI state
  const [activeTab, setActiveTab] = useState('request');
  const [responseTab, setResponseTab] = useState('body');
  const [responseFormat, setResponseFormat] = useState('pretty');
  
  // Security testing state
  const [injectionParams, setInjectionParams] = useState([]);
  const [selectedPayloads, setSelectedPayloads] = useState([]);
  const [injectionResults, setInjectionResults] = useState([]);
  const [fuzzingResults, setFuzzingResults] = useState([]);
  const [payloadTemplates, setPayloadTemplates] = useState({});
  const [securityAnalysis, setSecurityAnalysis] = useState(null);
  const [wordlist, setWordlist] = useState([
    'admin', 'test', 'api', 'config', 'backup', 'old', 'dev', 'staging',
    'debug', 'login', 'user', 'users', 'dashboard', 'panel', 'cpanel',
    'phpmyadmin', 'mysql', 'sql', 'db', 'database', 'data'
  ]);
  
  // Session state
  const [sessionId, setSessionId] = useState(null);
  const [history, setHistory] = useState([]);
  const [collections, setCollections] = useState([]);
  
  // Methods
  const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
  
  // Status colors
  const getStatusColor = (status) => {
    if (status >= 200 && status < 300) return 'text-green-400';
    if (status >= 300 && status < 400) return 'text-yellow-400';
    if (status >= 400 && status < 500) return 'text-orange-400';
    if (status >= 500) return 'text-red-400';
    return 'text-gray-400';
  };

  // Load payload templates on component mount
  useEffect(() => {
    loadPayloadTemplates();
  }, []);

  const loadPayloadTemplates = async () => {
    try {
      const res = await fetch('http://localhost:5000/api/repeater/payloads/templates');
      const templates = await res.json();
      setPayloadTemplates(templates);
    } catch (error) {
      console.error('Failed to load payload templates:', error);
    }
  };

  // Send request
  const sendRequest = useCallback(async () => {
    const startTime = Date.now();
    setLoading(true);
    setResponse(null);
    
    try {
      const headersObj = {};
      headers.forEach(h => {
        if (h.enabled && h.key) {
          headersObj[h.key] = h.value;
        }
      });
      
      const options = {
        method,
        headers: headersObj
      };
      
      if (['POST', 'PUT', 'PATCH'].includes(method) && body) {
        if (bodyType === 'json') {
          options.headers['Content-Type'] = 'application/json';
          options.body = body;
        } else if (bodyType === 'form') {
          options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
          options.body = body;
        } else {
          options.body = body;
        }
      }
      
      const res = await fetch('http://localhost:5000/api/repeater/proxy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url,
          method: options.method,
          headers: options.headers,
          body: options.body
        })
      });
      
      const responseData = await res.json();
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      const size = new Blob([JSON.stringify(responseData)]).size;
      
      setResponseTime(duration);
      setResponseSize(size);
      setResponse(responseData);
      
      // Add to history
      const historyEntry = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        method,
        url,
        status: responseData.status,
        duration,
        size,
        request: { method, url, headers: headersObj, body },
        response: responseData
      };
      
      setHistory(prev => [historyEntry, ...prev].slice(0, 100));
      
      // Analyze security headers
      if (responseData.headers) {
        analyzeSecurityHeaders(responseData.headers);
      }
      
    } catch (error) {
      setResponse({
        error: true,
        message: error.message,
        status: 0
      });
      setResponseTime(Date.now() - startTime);
    } finally {
      setLoading(false);
    }
  }, [url, method, headers, body, bodyType]);

  // Parameter injection testing
  const performInjectionTest = async () => {
    if (!url || injectionParams.length === 0 || selectedPayloads.length === 0) {
      alert('Please select parameters and payloads for injection testing');
      return;
    }

    setLoading(true);
    try {
      const headersObj = {};
      headers.forEach(h => {
        if (h.enabled && h.key) {
          headersObj[h.key] = h.value;
        }
      });

      const res = await fetch('http://localhost:5000/api/repeater/inject', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url,
          headers: headersObj,
          params: injectionParams,
          payloads: selectedPayloads
        })
      });
      
      const data = await res.json();
      setInjectionResults(data.results || []);
      setActiveTab('injection');
      
    } catch (error) {
      console.error('Injection test failed:', error);
    } finally {
      setLoading(false);
    }
  };

  // Endpoint fuzzing
  const performFuzzing = async () => {
    if (!url || wordlist.length === 0) {
      alert('Please provide a base URL and wordlist for fuzzing');
      return;
    }

    setLoading(true);
    try {
      const res = await fetch('http://localhost:5000/api/repeater/fuzz', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url,
          wordlist,
          methods: ['GET', 'POST']
        })
      });
      
      const data = await res.json();
      setFuzzingResults(data.results || []);
      setActiveTab('fuzzing');
      
    } catch (error) {
      console.error('Fuzzing failed:', error);
    } finally {
      setLoading(false);
    }
  };

  // Security header analysis
  const analyzeSecurityHeaders = async (responseHeaders) => {
    try {
      const res = await fetch('http://localhost:5000/api/repeater/headers/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url,
          headers: responseHeaders
        })
      });
      
      const data = await res.json();
      setSecurityAnalysis(data);
      
    } catch (error) {
      console.error('Security analysis failed:', error);
    }
  };

  // Add/Remove headers
  const addHeader = () => {
    setHeaders([...headers, { key: '', value: '', enabled: true }]);
  };
  
  const removeHeader = (index) => {
    setHeaders(headers.filter((_, i) => i !== index));
  };
  
  const updateHeader = (index, field, value) => {
    const newHeaders = [...headers];
    newHeaders[index][field] = value;
    setHeaders(newHeaders);
  };

  // Format JSON
  const formatJson = (data) => {
    try {
      if (responseFormat === 'pretty') {
        return JSON.stringify(data, null, 2);
      }
      return JSON.stringify(data);
    } catch {
      return data;
    }
  };

  // Keyboard shortcut
  useEffect(() => {
    const handleKeyPress = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        sendRequest();
      }
    };
    window.addEventListener('keydown', handleKeyPress);
    return () => window.removeEventListener('keydown', handleKeyPress);
  }, [sendRequest]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black text-white">
      <div className="flex h-screen">
        {/* History Sidebar */}
        <div className="w-80 bg-gray-900 border-r border-gray-800 overflow-y-auto">
          <div className="p-4 border-b border-gray-800">
            <h3 className="text-lg font-bold mb-3">Request History</h3>
            <div className="space-y-2">
              {history.map(entry => (
                <div
                  key={entry.id}
                  onClick={() => {
                    setMethod(entry.method);
                    setUrl(entry.url);
                    setResponse(entry.response);
                    setResponseTime(entry.duration);
                    setResponseSize(entry.size);
                  }}
                  className="p-3 bg-gray-800 rounded-lg hover:bg-gray-750 cursor-pointer transition"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className={`px-2 py-1 rounded text-xs font-bold ${
                      entry.method === 'GET' ? 'bg-green-500' :
                      entry.method === 'POST' ? 'bg-blue-500' :
                      entry.method === 'PUT' ? 'bg-yellow-500' :
                      entry.method === 'DELETE' ? 'bg-red-500' :
                      'bg-gray-500'
                    }`}>
                      {entry.method}
                    </span>
                    <span className={`text-xs font-bold ${getStatusColor(entry.status)}`}>
                      {entry.status || 'ERR'}
                    </span>
                  </div>
                  <p className="text-xs text-gray-400 truncate">{entry.url}</p>
                  <div className="flex items-center justify-between mt-2 text-xs text-gray-500">
                    <span>{entry.duration}ms</span>
                    <span>{(entry.size / 1024).toFixed(2)}KB</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 flex flex-col">
          {/* Top Bar */}
          <div className="bg-gray-900 border-b border-gray-800 p-4">
            <div className="flex items-center space-x-4">
              <select
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                className={`px-4 py-2 rounded-lg font-bold text-white ${
                  method === 'GET' ? 'bg-green-500' :
                  method === 'POST' ? 'bg-blue-500' :
                  method === 'PUT' ? 'bg-yellow-500' :
                  method === 'DELETE' ? 'bg-red-500' :
                  'bg-gray-500'
                }`}
              >
                {methods.map(m => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
              
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter URL..."
                className="flex-1 bg-gray-800 text-white px-4 py-2 rounded-lg border border-gray-700 focus:border-purple-500 outline-none"
              />
              
              <button
                onClick={sendRequest}
                disabled={loading || !url}
                className="px-6 py-2 bg-gradient-to-r from-purple-600 to-pink-600 rounded-lg font-bold hover:from-purple-700 hover:to-pink-700 disabled:opacity-50 transition"
              >
                {loading ? 'Sending...' : 'Send (Ctrl+Enter)'}
              </button>
            </div>
          </div>

          {/* Main Tabs */}
          <div className="border-b border-gray-800">
            <div className="flex">
              {[
                { id: 'request', label: 'Request', icon: Settings },
                { id: 'response', label: 'Response', icon: Globe },
                { id: 'injection', label: 'Parameter Injection', icon: Bug },
                { id: 'fuzzing', label: 'Endpoint Fuzzing', icon: Search },
                { id: 'security', label: 'Security Analysis', icon: Shield }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-4 py-3 font-medium transition ${
                    activeTab === tab.id 
                      ? 'bg-gray-800 text-purple-400 border-b-2 border-purple-400' 
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  <tab.icon className="w-4 h-4" />
                  {tab.label}
                </button>
              ))}
            </div>
          </div>
          
          <div className="flex-1 flex overflow-hidden">
            {/* Main Panel */}
            <div className="flex-1 overflow-y-auto">
              <div className="p-6">
                {activeTab === 'request' && (
                  <div className="space-y-6">
                    {/* Headers Section */}
                    <div>
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-lg font-bold flex items-center gap-2">
                          <Layers className="w-5 h-5" />
                          Headers
                        </h3>
                        <button
                          onClick={addHeader}
                          className="px-3 py-1 bg-gray-800 rounded hover:bg-gray-700 transition text-sm"
                        >
                          <Plus className="w-4 h-4 inline mr-1" />
                          Add Header
                        </button>
                      </div>
                      <div className="space-y-2">
                        {headers.map((header, index) => (
                          <div key={index} className="flex items-center space-x-2">
                            <input
                              type="checkbox"
                              checked={header.enabled}
                              onChange={(e) => updateHeader(index, 'enabled', e.target.checked)}
                              className="w-4 h-4"
                            />
                            <input
                              type="text"
                              value={header.key}
                              onChange={(e) => updateHeader(index, 'key', e.target.value)}
                              placeholder="Header name"
                              className="flex-1 bg-gray-800 px-3 py-2 rounded border border-gray-700 focus:border-purple-500 outline-none"
                            />
                            <input
                              type="text"
                              value={header.value}
                              onChange={(e) => updateHeader(index, 'value', e.target.value)}
                              placeholder="Header value"
                              className="flex-1 bg-gray-800 px-3 py-2 rounded border border-gray-700 focus:border-purple-500 outline-none"
                            />
                            <button
                              onClick={() => removeHeader(index)}
                              className="px-3 py-2 bg-red-500 rounded hover:bg-red-600 transition"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Body Section */}
                    <div>
                      <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                        <Code className="w-5 h-5" />
                        Request Body
                      </h3>
                      <div className="flex space-x-2 mb-4">
                        {['raw', 'json', 'form'].map((type) => (
                          <button
                            key={type}
                            onClick={() => setBodyType(type)}
                            className={`px-3 py-1 rounded ${bodyType === type ? 'bg-purple-600' : 'bg-gray-800'}`}
                          >
                            {type.toUpperCase()}
                          </button>
                        ))}
                      </div>
                      <textarea
                        value={body}
                        onChange={(e) => setBody(e.target.value)}
                        placeholder={bodyType === 'json' ? '{\n  "key": "value"\n}' : 'Request body...'}
                        className="w-full h-64 bg-gray-800 text-white px-4 py-3 rounded-lg border border-gray-700 focus:border-purple-500 outline-none font-mono"
                      />
                    </div>
                  </div>
                )}

                {activeTab === 'response' && response && (
                  <div>
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center space-x-4">
                        <span className={`font-bold ${getStatusColor(response.status)}`}>
                          {response.status} {response.statusText}
                        </span>
                        <span className="text-gray-400">{responseTime}ms</span>
                        <span className="text-gray-400">{(responseSize / 1024).toFixed(2)}KB</span>
                      </div>
                      <div className="flex space-x-2">
                        <button
                          onClick={() => navigator.clipboard.writeText(JSON.stringify(response, null, 2))}
                          className="px-3 py-1 bg-gray-800 rounded hover:bg-gray-700 transition text-sm"
                        >
                          <Copy className="w-4 h-4 inline mr-1" />
                          Copy
                        </button>
                      </div>
                    </div>
                    
                    <div className="flex mb-4">
                      {['body', 'headers'].map((tab) => (
                        <button
                          key={tab}
                          onClick={() => setResponseTab(tab)}
                          className={`px-4 py-2 font-medium transition ${
                            responseTab === tab 
                              ? 'bg-gray-800 text-purple-400 border-b-2 border-purple-400' 
                              : 'text-gray-400 hover:text-white'
                          }`}
                        >
                          {tab.charAt(0).toUpperCase() + tab.slice(1)}
                        </button>
                      ))}
                    </div>
                    
                    {responseTab === 'body' && (
                      <div>
                        <div className="flex justify-end mb-2 space-x-2">
                          <button
                            onClick={() => setResponseFormat('pretty')}
                            className={`px-3 py-1 rounded text-sm ${
                              responseFormat === 'pretty' ? 'bg-purple-600' : 'bg-gray-800'
                            }`}
                          >
                            Pretty
                          </button>
                          <button
                            onClick={() => setResponseFormat('raw')}
                            className={`px-3 py-1 rounded text-sm ${
                              responseFormat === 'raw' ? 'bg-purple-600' : 'bg-gray-800'
                            }`}
                          >
                            Raw
                          </button>
                        </div>
                        <pre className="bg-gray-900 p-4 rounded-lg overflow-x-auto">
                          <code className="text-sm text-gray-300">
                            {formatJson(response.body || response)}
                          </code>
                        </pre>
                      </div>
                    )}
                    
                    {responseTab === 'headers' && (
                      <div className="space-y-2">
                        {response.headers && Object.entries(response.headers).map(([key, value]) => (
                          <div key={key} className="flex bg-gray-800 p-3 rounded">
                            <span className="font-bold text-purple-400 w-1/3">{key}:</span>
                            <span className="text-gray-300">{value}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {activeTab === 'injection' && (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between">
                      <h3 className="text-lg font-bold flex items-center gap-2">
                        <Target className="w-5 h-5" />
                        Parameter Injection Testing
                      </h3>
                      <button
                        onClick={performInjectionTest}
                        disabled={loading || injectionParams.length === 0 || selectedPayloads.length === 0}
                        className="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 rounded-lg transition"
                      >
                        <Zap className="w-4 h-4 inline mr-1" />
                        Start Injection Test
                      </button>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div>
                        <h4 className="font-bold mb-3">Parameters to Test</h4>
                        <div className="space-y-2">
                          {injectionParams.map((param, index) => (
                            <div key={index} className="flex items-center space-x-2">
                              <input
                                type="text"
                                value={param}
                                onChange={(e) => {
                                  const newParams = [...injectionParams];
                                  newParams[index] = e.target.value;
                                  setInjectionParams(newParams);
                                }}
                                placeholder="Parameter name"
                                className="flex-1 bg-gray-800 px-3 py-2 rounded border border-gray-700 focus:border-purple-500 outline-none"
                              />
                              <button
                                onClick={() => setInjectionParams(injectionParams.filter((_, i) => i !== index))}
                                className="px-3 py-2 bg-red-500 rounded hover:bg-red-600 transition"
                              >
                                <Trash2 className="w-4 h-4" />
                              </button>
                            </div>
                          ))}
                          <button
                            onClick={() => setInjectionParams([...injectionParams, ''])}
                            className="w-full py-2 bg-gray-800 rounded hover:bg-gray-700 transition"
                          >
                            <Plus className="w-4 h-4 inline mr-1" />
                            Add Parameter
                          </button>
                        </div>
                      </div>
                      
                      <div>
                        <h4 className="font-bold mb-3">Select Payloads</h4>
                        <div className="space-y-3 max-h-64 overflow-y-auto">
                          {Object.entries(payloadTemplates).map(([category, payloads]) => (
                            <div key={category}>
                              <h5 className="font-medium text-sm text-gray-400 mb-2 capitalize">
                                {category.replace('_', ' ')}
                              </h5>
                              <div className="space-y-1">
                                {payloads.slice(0, 3).map((payload, index) => (
                                  <label key={index} className="flex items-center space-x-2 text-sm">
                                    <input
                                      type="checkbox"
                                      checked={selectedPayloads.includes(payload)}
                                      onChange={(e) => {
                                        if (e.target.checked) {
                                          setSelectedPayloads([...selectedPayloads, payload]);
                                        } else {
                                          setSelectedPayloads(selectedPayloads.filter(p => p !== payload));
                                        }
                                      }}
                                      className="w-3 h-3"
                                    />
                                    <span className="text-gray-300 font-mono text-xs">{payload}</span>
                                  </label>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                    
                    {injectionResults.length > 0 && (
                      <div>
                        <h4 className="font-bold mb-3">Injection Test Results</h4>
                        <div className="space-y-2 max-h-96 overflow-y-auto">
                          {injectionResults.map((result, index) => (
                            <div
                              key={index}
                              className={`p-3 rounded-lg border ${
                                result.suspicious 
                                  ? 'bg-red-900 border-red-500' 
                                  : 'bg-gray-800 border-gray-700'
                              }`}
                            >
                              <div className="flex items-center justify-between mb-2">
                                <span className="font-bold">{result.parameter}</span>
                                <div className="flex items-center space-x-2">
                                  {result.suspicious && (
                                    <AlertTriangle className="w-4 h-4 text-red-400" />
                                  )}
                                  <span className={`font-bold ${getStatusColor(result.status)}`}>
                                    {result.status}
                                  </span>
                                </div>
                              </div>
                              <p className="text-sm text-gray-400 mb-2">{result.payload}</p>
                              {result.flag && (
                                <span className="inline-block px-2 py-1 bg-red-600 text-white text-xs rounded">
                                  {result.flag}
                                </span>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {activeTab === 'fuzzing' && (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between">
                      <h3 className="text-lg font-bold flex items-center gap-2">
                        <Search className="w-5 h-5" />
                        Endpoint Fuzzing
                      </h3>
                      <button
                        onClick={performFuzzing}
                        disabled={loading || !url || wordlist.length === 0}
                        className="px-4 py-2 bg-orange-600 hover:bg-orange-700 disabled:opacity-50 rounded-lg transition"
                      >
                        <Target className="w-4 h-4 inline mr-1" />
                        Start Fuzzing
                      </button>
                    </div>
                    
                    <div>
                      <h4 className="font-bold mb-3">Wordlist</h4>
                      <div className="grid grid-cols-3 md:grid-cols-4 gap-2 mb-4">
                        {wordlist.map((word, index) => (
                          <span key={index} className="px-2 py-1 bg-gray-800 rounded text-sm">
                            {word}
                          </span>
                        ))}
                      </div>
                      <div className="flex space-x-2">
                        <input
                          type="text"
                          onKeyPress={(e) => {
                            if (e.key === 'Enter' && e.target.value) {
                              setWordlist([...wordlist, e.target.value]);
                              e.target.value = '';
                            }
                          }}
                          placeholder="Add word to list..."
                          className="flex-1 bg-gray-800 px-3 py-2 rounded border border-gray-700 focus:border-purple-500 outline-none"
                        />
                        <button
                          onClick={() => {
                            const input = document.querySelector('input[placeholder="Add word to list..."]');
                            if (input && input.value) {
                              setWordlist([...wordlist, input.value]);
                              input.value = '';
                            }
                          }}
                          className="px-4 py-2 bg-gray-800 rounded hover:bg-gray-700 transition"
                        >
                          <Plus className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                    
                    {fuzzingResults.length > 0 && (
                      <div>
                        <h4 className="font-bold mb-3">Fuzzing Results</h4>
                        <div className="space-y-2 max-h-96 overflow-y-auto">
                          {fuzzingResults.map((result, index) => (
                            <div
                              key={index}
                              className={`p-3 rounded-lg border ${
                                result.interesting 
                                  ? 'bg-green-900 border-green-500' 
                                  : 'bg-gray-800 border-gray-700'
                              }`}
                            >
                              <div className="flex items-center justify-between mb-2">
                                <span className="font-bold">{result.method}</span>
                                <div className="flex items-center space-x-2">
                                  {result.interesting && (
                                    <CheckCircle className="w-4 h-4 text-green-400" />
                                  )}
                                  <span className={`font-bold ${getStatusColor(result.status)}`}>
                                    {result.status}
                                  </span>
                                </div>
                              </div>
                              <p className="text-sm text-gray-400 mb-1">{result.url}</p>
                              <p className="text-xs text-gray-500">{result.time}ms | {result.size} bytes</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {activeTab === 'security' && (
                  <div className="space-y-6">
                    <h3 className="text-lg font-bold flex items-center gap-2">
                      <Shield className="w-5 h-5" />
                      Security Analysis
                    </h3>
                    
                    {securityAnalysis && (
                      <div className="space-y-4">
                        <div className="bg-gray-800 rounded-lg p-4">
                          <div className="flex items-center justify-between mb-4">
                            <h4 className="font-bold">Security Score</h4>
                            <div className={`text-2xl font-bold ${
                              securityAnalysis.score >= 80 ? 'text-green-400' :
                              securityAnalysis.score >= 60 ? 'text-yellow-400' :
                              'text-red-400'
                            }`}>
                              {securityAnalysis.score}/100
                            </div>
                          </div>
                          
                          {securityAnalysis.security_issues.length > 0 && (
                            <div>
                              <h5 className="font-bold mb-3">Security Issues Found:</h5>
                              <div className="space-y-2">
                                {securityAnalysis.security_issues.map((issue, index) => (
                                  <div key={index} className="flex items-center space-x-2 p-2 bg-red-900 rounded">
                                    <AlertTriangle className="w-4 h-4 text-red-400" />
                                    <span className="text-sm">{issue}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                    
                    {!securityAnalysis && (
                      <div className="text-center py-8 text-gray-400">
                        <Eye className="w-12 h-12 mx-auto mb-4 opacity-50" />
                        <p>Send a request to analyze security headers</p>
                      </div>
                    )}
                  </div>
                )}

                {!response && !loading && activeTab === 'response' && (
                  <div className="flex items-center justify-center h-64 text-gray-500">
                    <div className="text-center">
                      <div className="text-6xl mb-4">📡</div>
                      <p className="text-xl">Send a request to see the response</p>
                      <p className="text-sm mt-2">Use Ctrl+Enter to send quickly</p>
                    </div>
                  </div>
                )}
                
                {loading && (
                  <div className="flex items-center justify-center h-64">
                    <div className="text-center">
                      <div className="text-6xl mb-4 animate-pulse">⏳</div>
                      <p className="text-xl">Processing request...</p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EnhancedHttpRepeater;
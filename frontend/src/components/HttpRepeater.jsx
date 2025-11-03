import React, { useState, useEffect, useCallback } from 'react';
import { saveAs } from 'file-saver';

const HttpRepeater = () => {
  // Request State
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('');
  const [headers, setHeaders] = useState([{ key: '', value: '', enabled: true }]);
  const [body, setBody] = useState('');
  const [bodyType, setBodyType] = useState('raw');
  
  // Response State
  const [response, setResponse] = useState(null);
  const [loading, setLoading] = useState(false);
  const [responseTime, setResponseTime] = useState(0);
  const [responseSize, setResponseSize] = useState(0);
  
  // UI State
  const [activeTab, setActiveTab] = useState('headers');
  const [responseTab, setResponseTab] = useState('body');
  const [responseFormat, setResponseFormat] = useState('pretty');
  const [history, setHistory] = useState([]);
  const [collections, setCollections] = useState([]);
  // const [selectedCollection, setSelectedCollection] = useState(null);
  // const [environment, setEnvironment] = useState('dev');
  // const [envVariables, setEnvVariables] = useState({
  //   dev: { baseUrl: 'http://localhost:3000', token: '' },
  //   staging: { baseUrl: 'https://staging.example.com', token: '' },
  //   prod: { baseUrl: 'https://api.example.com', token: '' }
  // });
  
  // Refs
  // const requestEditorRef = useRef(null);
  
  // Methods array
  const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
  
  // Method colors
  const methodColors = {
    GET: 'bg-green-500',
    POST: 'bg-blue-500',
    PUT: 'bg-yellow-500',
    PATCH: 'bg-purple-500',
    DELETE: 'bg-red-500',
    HEAD: 'bg-gray-500',
    OPTIONS: 'bg-indigo-500'
  };
  
  // Status code colors
  const getStatusColor = (status) => {
    if (status >= 200 && status < 300) return 'text-green-400';
    if (status >= 300 && status < 400) return 'text-yellow-400';
    if (status >= 400 && status < 500) return 'text-orange-400';
    if (status >= 500) return 'text-red-400';
    return 'text-gray-400';
  };
  
  // Replace environment variables in text
  const replaceEnvVariables = useCallback((text) => {
    // const vars = envVariables[environment];
    const vars = {
      dev: { baseUrl: 'http://localhost:3000', token: '' },
      staging: { baseUrl: 'https://staging.example.com', token: '' },
      prod: { baseUrl: 'https://api.example.com', token: '' }
    };
    let result = text;
    Object.keys(vars).forEach(key => {
      result = result.replace(new RegExp(`{{${key}}}`, 'g'), vars[key]);
    });
    return result;
  }, []);
  
  // Send Request
  const sendRequest = useCallback(async () => {
    const startTime = Date.now();
    setLoading(true);
    setResponse(null);
    
    try {
      // Build headers object
      const headersObj = {};
      headers.forEach(h => {
        if (h.enabled && h.key) {
          headersObj[h.key] = replaceEnvVariables(h.value);
        }
      });
      
      // Build request options
      const options = {
        method,
        headers: headersObj
      };
      
      // Add body for appropriate methods
      if (['POST', 'PUT', 'PATCH'].includes(method) && body) {
        if (bodyType === 'json') {
          options.headers['Content-Type'] = 'application/json';
          options.body = replaceEnvVariables(body);
        } else if (bodyType === 'form') {
          options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
          options.body = replaceEnvVariables(body);
        } else {
          options.body = replaceEnvVariables(body);
        }
      }
      
      // Send request
      const processedUrl = replaceEnvVariables(url);
      const res = await fetch(`http://localhost:5000/api/repeater/proxy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: processedUrl,
          method: options.method,
          headers: options.headers,
          body: options.body
        })
      });
      
      const responseData = await res.json();
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      // Calculate response size
      const size = new Blob([JSON.stringify(responseData)]).size;
      
      setResponseTime(duration);
      setResponseSize(size);
      setResponse(responseData);
      
      // Add to history
      const historyEntry = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        method,
        url: processedUrl,
        status: responseData.status,
        duration,
        size,
        request: { method, url: processedUrl, headers: headersObj, body },
        response: responseData
      };
      
      setHistory(prev => [historyEntry, ...prev].slice(0, 100));
      
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
  }, [url, method, headers, body, bodyType, replaceEnvVariables]);
  
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
  
  // Save request to collection
  const saveToCollection = () => {
    const name = prompt('Enter request name:');
    if (name) {
      const request = {
        id: Date.now(),
        name,
        method,
        url,
        headers,
        body,
        bodyType
      };
      setCollections([...collections, request]);
    }
  };
  
  // Load request from history
  const loadFromHistory = (entry) => {
    setMethod(entry.method);
    setUrl(entry.url);
    setResponse(entry.response);
    setResponseTime(entry.duration);
    setResponseSize(entry.size);
  };
  
  // Export response
  const exportResponse = (format) => {
    if (!response) return;
    
    let content, filename, type;
    
    switch (format) {
      case 'json':
        content = JSON.stringify(response, null, 2);
        filename = 'response.json';
        type = 'application/json';
        break;
      case 'har':
        content = JSON.stringify({
          log: {
            version: '1.2',
            creator: { name: 'CyberSage', version: '2.0' },
            entries: [{
              request: { method, url, headers },
              response: response,
              time: responseTime
            }]
          }
        }, null, 2);
        filename = 'response.har';
        type = 'application/json';
        break;
      case 'curl':
        content = `curl -X ${method} "${url}" ${headers.filter(h => h.enabled && h.key).map(h => `-H "${h.key}: ${h.value}"`).join(' ')}`;
        filename = 'request.sh';
        type = 'text/plain';
        break;
      default:
        content = JSON.stringify(response);
        filename = 'response.txt';
        type = 'text/plain';
    }
    
    const blob = new Blob([content], { type });
    saveAs(blob, filename);
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
                  onClick={() => loadFromHistory(entry)}
                  className="p-3 bg-gray-800 rounded-lg hover:bg-gray-750 cursor-pointer transition"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className={`px-2 py-1 rounded text-xs font-bold ${methodColors[entry.method]}`}>
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
                    <span>{new Date(entry.timestamp).toLocaleTimeString()}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
          
          {/* Collections */}
          <div className="p-4">
            <h3 className="text-lg font-bold mb-3">Collections</h3>
            <div className="space-y-2">
              {collections.map(req => (
                <div
                  key={req.id}
                  onClick={() => {
                    setMethod(req.method);
                    setUrl(req.url);
                    setHeaders(req.headers);
                    setBody(req.body);
                    setBodyType(req.bodyType);
                  }}
                  className="p-2 bg-gray-800 rounded hover:bg-gray-750 cursor-pointer transition"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm">{req.name}</span>
                    <span className={`px-2 py-1 rounded text-xs ${methodColors[req.method]}`}>
                      {req.method}
                    </span>
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
              {/* Environment Selector - Temporarily commented out */}
              {/*
              <select
                value={environment}
                onChange={(e) => setEnvironment(e.target.value)}
                className="bg-gray-800 text-white px-3 py-2 rounded-lg border border-gray-700 focus:border-purple-500 outline-none"
              >
                <option value="dev">Development</option>
                <option value="staging">Staging</option>
                <option value="prod">Production</option>
              </select>
              */}
              
              {/* Method Selector */}
              <select
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                className={`px-4 py-2 rounded-lg font-bold text-white ${methodColors[method]}`}
              >
                {methods.map(m => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
              
              {/* URL Input */}
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter URL (use {{baseUrl}} for environment variable)"
                className="flex-1 bg-gray-800 text-white px-4 py-2 rounded-lg border border-gray-700 focus:border-purple-500 outline-none"
              />
              
              {/* Send Button */}
              <button
                onClick={sendRequest}
                disabled={loading || !url}
                className="px-6 py-2 bg-gradient-to-r from-purple-600 to-pink-600 rounded-lg font-bold hover:from-purple-700 hover:to-pink-700 disabled:opacity-50 transition"
              >
                {loading ? 'Sending...' : 'Send (Ctrl+Enter)'}
              </button>
              
              {/* Save Button */}
              <button
                onClick={saveToCollection}
                className="px-4 py-2 bg-gray-800 rounded-lg hover:bg-gray-700 transition"
              >
                Save
              </button>
            </div>
          </div>

          {/* Request/Response Split */}
          <div className="flex-1 flex">
            {/* Request Panel */}
            <div className="flex-1 border-r border-gray-800">
              <div className="border-b border-gray-800">
                <div className="flex">
                  <button
                    onClick={() => setActiveTab('headers')}
                    className={`px-4 py-2 font-medium transition ${
                      activeTab === 'headers' 
                        ? 'bg-gray-800 text-purple-400 border-b-2 border-purple-400' 
                        : 'text-gray-400 hover:text-white'
                    }`}
                  >
                    Headers
                  </button>
                  <button
                    onClick={() => setActiveTab('body')}
                    className={`px-4 py-2 font-medium transition ${
                      activeTab === 'body' 
                        ? 'bg-gray-800 text-purple-400 border-b-2 border-purple-400' 
                        : 'text-gray-400 hover:text-white'
                    }`}
                  >
                    Body
                  </button>
                  <button
                    onClick={() => setActiveTab('auth')}
                    className={`px-4 py-2 font-medium transition ${
                      activeTab === 'auth' 
                        ? 'bg-gray-800 text-purple-400 border-b-2 border-purple-400' 
                        : 'text-gray-400 hover:text-white'
                    }`}
                  >
                    Auth
                  </button>
                  <button
                    onClick={() => setActiveTab('scripts')}
                    className={`px-4 py-2 font-medium transition ${
                      activeTab === 'scripts' 
                        ? 'bg-gray-800 text-purple-400 border-b-2 border-purple-400' 
                        : 'text-gray-400 hover:text-white'
                    }`}
                  >
                    Scripts
                  </button>
                </div>
              </div>
              
              <div className="p-4 overflow-y-auto" style={{ height: 'calc(100% - 48px)' }}>
                {activeTab === 'headers' && (
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
                          ✕
                        </button>
                      </div>
                    ))}
                    <button
                      onClick={addHeader}
                      className="px-4 py-2 bg-gray-800 rounded hover:bg-gray-700 transition"
                    >
                      + Add Header
                    </button>
                  </div>
                )}
                
                {activeTab === 'body' && (
                  <div className="space-y-4">
                    <div className="flex space-x-2">
                      <button
                        onClick={() => setBodyType('raw')}
                        className={`px-3 py-1 rounded ${bodyType === 'raw' ? 'bg-purple-600' : 'bg-gray-800'}`}
                      >
                        Raw
                      </button>
                      <button
                        onClick={() => setBodyType('json')}
                        className={`px-3 py-1 rounded ${bodyType === 'json' ? 'bg-purple-600' : 'bg-gray-800'}`}
                      >
                        JSON
                      </button>
                      <button
                        onClick={() => setBodyType('form')}
                        className={`px-3 py-1 rounded ${bodyType === 'form' ? 'bg-purple-600' : 'bg-gray-800'}`}
                      >
                        Form
                      </button>
                    </div>
                    <textarea
                      value={body}
                      onChange={(e) => setBody(e.target.value)}
                      placeholder={bodyType === 'json' ? '{\n  "key": "value"\n}' : 'Request body...'}
                      className="w-full h-96 bg-gray-800 text-white px-4 py-3 rounded-lg border border-gray-700 focus:border-purple-500 outline-none font-mono"
                    />
                  </div>
                )}
                
                {activeTab === 'auth' && (
                  <div className="space-y-4">
                    <div className="p-4 bg-gray-800 rounded-lg">
                      <h4 className="font-bold mb-3">Bearer Token</h4>
                      <input
                        type="text"
                        placeholder="Enter token or use {{token}}"
                        className="w-full bg-gray-900 px-3 py-2 rounded border border-gray-700 focus:border-purple-500 outline-none"
                      />
                    </div>
                  </div>
                )}
                
                {activeTab === 'scripts' && (
                  <div className="space-y-4">
                    <div className="p-4 bg-gray-800 rounded-lg">
                      <h4 className="font-bold mb-3">Pre-request Script</h4>
                      <textarea
                        placeholder="// JavaScript code to run before request"
                        className="w-full h-32 bg-gray-900 px-3 py-2 rounded border border-gray-700 focus:border-purple-500 outline-none font-mono text-sm"
                      />
                    </div>
                    <div className="p-4 bg-gray-800 rounded-lg">
                      <h4 className="font-bold mb-3">Post-response Script</h4>
                      <textarea
                        placeholder="// JavaScript code to run after response"
                        className="w-full h-32 bg-gray-900 px-3 py-2 rounded border border-gray-700 focus:border-purple-500 outline-none font-mono text-sm"
                      />
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Response Panel */}
            <div className="flex-1">
              {response && (
                <>
                  <div className="border-b border-gray-800 p-3 bg-gray-900">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-4">
                        <span className={`font-bold ${getStatusColor(response.status)}`}>
                          {response.status} {response.statusText}
                        </span>
                        <span className="text-gray-400">
                          {responseTime}ms
                        </span>
                        <span className="text-gray-400">
                          {(responseSize / 1024).toFixed(2)}KB
                        </span>
                      </div>
                      <div className="flex space-x-2">
                        <button
                          onClick={() => exportResponse('json')}
                          className="px-3 py-1 bg-gray-800 rounded hover:bg-gray-700 transition text-sm"
                        >
                          Export JSON
                        </button>
                        <button
                          onClick={() => exportResponse('har')}
                          className="px-3 py-1 bg-gray-800 rounded hover:bg-gray-700 transition text-sm"
                        >
                          Export HAR
                        </button>
                        <button
                          onClick={() => exportResponse('curl')}
                          className="px-3 py-1 bg-gray-800 rounded hover:bg-gray-700 transition text-sm"
                        >
                          Export cURL
                        </button>
                      </div>
                    </div>
                  </div>
                  
                  <div className="border-b border-gray-800">
                    <div className="flex">
                      <button
                        onClick={() => setResponseTab('body')}
                        className={`px-4 py-2 font-medium transition ${
                          responseTab === 'body' 
                            ? 'bg-gray-800 text-purple-400 border-b-2 border-purple-400' 
                            : 'text-gray-400 hover:text-white'
                        }`}
                      >
                        Body
                      </button>
                      <button
                        onClick={() => setResponseTab('headers')}
                        className={`px-4 py-2 font-medium transition ${
                          responseTab === 'headers' 
                            ? 'bg-gray-800 text-purple-400 border-b-2 border-purple-400' 
                            : 'text-gray-400 hover:text-white'
                        }`}
                      >
                        Headers
                      </button>
                      <button
                        onClick={() => setResponseTab('timeline')}
                        className={`px-4 py-2 font-medium transition ${
                          responseTab === 'timeline' 
                            ? 'bg-gray-800 text-purple-400 border-b-2 border-purple-400' 
                            : 'text-gray-400 hover:text-white'
                        }`}
                      >
                        Timeline
                      </button>
                    </div>
                  </div>
                  
                  <div className="p-4 overflow-y-auto" style={{ height: 'calc(100% - 120px)' }}>
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
                    
                    {responseTab === 'timeline' && (
                      <div className="space-y-4">
                        <div className="bg-gray-800 p-4 rounded-lg">
                          <h4 className="font-bold mb-3">Request Timeline</h4>
                          <div className="space-y-2">
                            <div className="flex justify-between">
                              <span className="text-gray-400">DNS Lookup</span>
                              <span>-</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-400">TCP Connection</span>
                              <span>-</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-400">Request Sent</span>
                              <span>0ms</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-400">Response Received</span>
                              <span>{responseTime}ms</span>
                            </div>
                            <div className="flex justify-between font-bold">
                              <span className="text-gray-400">Total Time</span>
                              <span className="text-purple-400">{responseTime}ms</span>
                            </div>
                          </div>
                        </div>
                        
                        <div className="bg-gray-800 p-4 rounded-lg">
                          <h4 className="font-bold mb-3">Response Size</h4>
                          <div className="space-y-2">
                            <div className="flex justify-between">
                              <span className="text-gray-400">Headers</span>
                              <span>-</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-400">Body</span>
                              <span>{(responseSize / 1024).toFixed(2)}KB</span>
                            </div>
                            <div className="flex justify-between font-bold">
                              <span className="text-gray-400">Total</span>
                              <span className="text-purple-400">{(responseSize / 1024).toFixed(2)}KB</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </>
              )}
              
              {!response && !loading && (
                <div className="flex items-center justify-center h-full text-gray-500">
                  <div className="text-center">
                    <div className="text-6xl mb-4">📡</div>
                    <p className="text-xl">Send a request to see the response</p>
                    <p className="text-sm mt-2">Use Ctrl+Enter to send quickly</p>
                  </div>
                </div>
              )}
              
              {loading && (
                <div className="flex items-center justify-center h-full">
                  <div className="text-center">
                    <div className="text-6xl mb-4 animate-pulse">⏳</div>
                    <p className="text-xl">Sending request...</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HttpRepeater;

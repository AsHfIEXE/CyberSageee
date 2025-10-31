import React, { useState } from 'react';
import { Send, Plus, Trash2, Copy, Play, Square, Settings, Code, Globe } from 'lucide-react';
import { useTheme } from '../components/ThemeComponents';
import { RepeaterSkeleton } from '../components/EnhancedLoadingSkeletons';
import { EnhancedModal } from '../components/ThemeComponents';

const EnhancedRepeaterPage = () => {
  const { isDark } = useTheme();
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('builder');
  const [showResponseModal, setShowResponseModal] = useState(false);
  const [currentResponse, setCurrentResponse] = useState(null);
  const [requests, setRequests] = useState([
    {
      id: 1,
      name: 'GET Request',
      method: 'GET',
      url: 'https://example.com/api/users',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer token-here'
      },
      body: '',
      isActive: true,
      response: null
    }
  ]);

  React.useEffect(() => {
    // Simulate loading
    const timer = setTimeout(() => setIsLoading(false), 1500);
    return () => clearTimeout(timer);
  }, []);

  const [currentRequest, setCurrentRequest] = useState(requests[0]);

  const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];

  const requestTemplates = [
    {
      name: 'Login Request',
      method: 'POST',
      url: 'https://api.example.com/auth/login',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'user@example.com', password: 'password123' }, null, 2)
    },
    {
      name: 'API Fetch',
      method: 'GET',
      url: 'https://api.example.com/data',
      headers: { 'Authorization': 'Bearer your-token' },
      body: ''
    },
    {
      name: 'File Upload',
      method: 'POST',
      url: 'https://api.example.com/upload',
      headers: { 'Content-Type': 'multipart/form-data' },
      body: ''
    }
  ];

  const addNewRequest = () => {
    const newRequest = {
      id: Date.now(),
      name: `Request ${requests.length + 1}`,
      method: 'GET',
      url: '',
      headers: { 'Content-Type': 'application/json' },
      body: '',
      isActive: false,
      response: null
    };
    setRequests([...requests, newRequest]);
    setCurrentRequest(newRequest);
  };

  const deleteRequest = (id) => {
    const updatedRequests = requests.filter(req => req.id !== id);
    setRequests(updatedRequests);
    if (currentRequest.id === id && updatedRequests.length > 0) {
      setCurrentRequest(updatedRequests[0]);
    }
  };

  const updateRequest = (field, value) => {
    const updatedRequest = { ...currentRequest, [field]: value };
    setCurrentRequest(updatedRequest);
    setRequests(requests.map(req => req.id === currentRequest.id ? updatedRequest : req));
  };

  const updateHeader = (index, field, value) => {
    const updatedHeaders = { ...currentRequest.headers };
    updatedHeaders[field] = value;
    updateRequest('headers', updatedHeaders);
  };

  const addHeader = () => {
    const updatedHeaders = { ...currentRequest.headers, 'X-New-Header': '' };
    updateRequest('headers', updatedHeaders);
  };

  const removeHeader = (headerKey) => {
    const updatedHeaders = { ...currentRequest.headers };
    delete updatedHeaders[headerKey];
    updateRequest('headers', updatedHeaders);
  };

  const sendRequest = async () => {
    // Simulate API call
    setIsLoading(true);
    
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const mockResponse = {
      status: 200,
      statusText: 'OK',
      headers: {
        'content-type': 'application/json',
        'server': 'nginx/1.18.0',
        'date': new Date().toUTCString()
      },
      body: JSON.stringify({
        success: true,
        data: {
          id: 12345,
          username: 'john.doe',
          email: 'john.doe@example.com',
          created_at: '2024-01-15T10:30:00Z'
        },
        message: 'Request processed successfully'
      }, null, 2)
    };

    const updatedRequest = { ...currentRequest, response: mockResponse };
    setCurrentRequest(updatedRequest);
    setRequests(requests.map(req => req.id === currentRequest.id ? updatedRequest : req));
    setCurrentResponse(mockResponse);
    setShowResponseModal(true);
    setIsLoading(false);
  };

  const loadTemplate = (template) => {
    const newRequest = {
      ...currentRequest,
      name: template.name,
      method: template.method,
      url: template.url,
      headers: template.headers,
      body: template.body
    };
    setCurrentRequest(newRequest);
    setRequests(requests.map(req => req.id === currentRequest.id ? newRequest : req));
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    // You could add a toast notification here
  };

  const formatJson = (jsonString) => {
    try {
      return JSON.stringify(JSON.parse(jsonString), null, 2);
    } catch {
      return jsonString;
    }
  };

  if (isLoading) {
    return <RepeaterSkeleton />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-bold bg-gradient-to-r from-green-400 to-blue-500 bg-clip-text text-transparent">
            HTTP Repeater
          </h2>
          <p className="text-sm text-gray-400 mt-1">
            Test and modify HTTP requests with detailed response analysis
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={addNewRequest}
            className="inline-flex items-center px-4 py-2 bg-primary hover:bg-primary/90 text-white rounded-lg transition-all duration-200 hover:scale-105"
          >
            <Plus className="w-4 h-4 mr-2" />
            New Request
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
        {/* Request List Sidebar */}
        <div className="xl:col-span-3">
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="p-4 border-b border-gray-200 dark:border-gray-700">
              <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
                Requests ({requests.length})
              </h3>
            </div>
            <div className="p-2 space-y-1 max-h-96 overflow-y-auto">
              {requests.map((request) => (
                <div
                  key={request.id}
                  className={`flex items-center justify-between p-3 rounded-lg cursor-pointer transition-colors duration-200 ${
                    currentRequest.id === request.id
                      ? 'bg-primary/20 border border-primary/30'
                      : 'hover:bg-gray-50 dark:hover:bg-gray-700'
                  }`}
                  onClick={() => setCurrentRequest(request)}
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        request.method === 'GET' ? 'bg-green-500/20 text-green-400' :
                        request.method === 'POST' ? 'bg-blue-500/20 text-blue-400' :
                        request.method === 'PUT' ? 'bg-yellow-500/20 text-yellow-400' :
                        request.method === 'DELETE' ? 'bg-red-500/20 text-red-400' :
                        'bg-gray-500/20 text-gray-400'
                      }`}>
                        {request.method}
                      </span>
                      {request.response && (
                        <span className="w-2 h-2 bg-green-400 rounded-full"></span>
                      )}
                    </div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                      {request.name}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                      {request.url}
                    </p>
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      deleteRequest(request.id);
                    }}
                    className="p-1 text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors duration-200"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Request Builder */}
        <div className="xl:col-span-9 space-y-6">
          {/* Request Configuration */}
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="p-6">
              {/* Method and URL */}
              <div className="flex items-center gap-4 mb-6">
                <select
                  value={currentRequest.method}
                  onChange={(e) => updateRequest('method', e.target.value)}
                  className="px-3 py-2 bg-gray-50 dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent transition-all duration-200"
                >
                  {httpMethods.map(method => (
                    <option key={method} value={method}>{method}</option>
                  ))}
                </select>
                
                <input
                  type="text"
                  placeholder="Enter URL..."
                  value={currentRequest.url}
                  onChange={(e) => updateRequest('url', e.target.value)}
                  className="flex-1 px-4 py-2 bg-gray-50 dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent transition-all duration-200"
                />
                
                <button
                  onClick={sendRequest}
                  disabled={!currentRequest.url || isLoading}
                  className="inline-flex items-center px-6 py-2 bg-primary hover:bg-primary/90 disabled:bg-gray-400 disabled:cursor-not-allowed text-white rounded-lg transition-all duration-200 hover:scale-105"
                >
                  {isLoading ? (
                    <Square className="w-4 h-4 mr-2" />
                  ) : (
                    <Send className="w-4 h-4 mr-2" />
                  )}
                  {isLoading ? 'Sending...' : 'Send'}
                </button>
              </div>

              {/* Request Templates */}
              <div className="mb-6">
                <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Quick Templates
                </h4>
                <div className="flex flex-wrap gap-2">
                  {requestTemplates.map((template, index) => (
                    <button
                      key={index}
                      onClick={() => loadTemplate(template)}
                      className="inline-flex items-center px-3 py-1.5 text-xs font-medium text-primary bg-primary/10 hover:bg-primary/20 rounded-lg transition-colors duration-200"
                    >
                      {template.name}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Tabs */}
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="border-b border-gray-200 dark:border-gray-700">
              <nav className="flex space-x-8 px-6">
                {[
                  { id: 'builder', label: 'Builder', icon: Settings },
                  { id: 'headers', label: 'Headers', icon: Globe },
                  { id: 'body', label: 'Body', icon: Code }
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center gap-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors duration-200 ${
                      activeTab === tab.id
                        ? 'border-primary text-primary'
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
              {activeTab === 'builder' && (
                <div className="space-y-6">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Request Name
                    </label>
                    <input
                      type="text"
                      value={currentRequest.name}
                      onChange={(e) => updateRequest('name', e.target.value)}
                      className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent transition-all duration-200"
                      placeholder="My HTTP Request"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      Full Request Preview
                    </label>
                    <div className="bg-gray-900 dark:bg-gray-950 rounded-lg p-4 font-mono text-sm overflow-x-auto">
                      <div className="text-green-400">
                        {currentRequest.method} {currentRequest.url || 'URL_HERE'} HTTP/1.1
                      </div>
                      {Object.entries(currentRequest.headers).map(([key, value]) => (
                        <div key={key} className="text-blue-400">
                          {key}: {value || 'VALUE_HERE'}
                        </div>
                      ))}
                      {currentRequest.body && (
                        <div className="text-white mt-2">
                          {currentRequest.body}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'headers' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">
                      Headers
                    </h4>
                    <button
                      onClick={addHeader}
                      className="inline-flex items-center px-3 py-1.5 text-xs font-medium text-primary bg-primary/10 hover:bg-primary/20 rounded-lg transition-colors duration-200"
                    >
                      <Plus className="w-3 h-3 mr-1" />
                      Add Header
                    </button>
                  </div>
                  
                  <div className="space-y-3">
                    {Object.entries(currentRequest.headers).map(([key, value], index) => (
                      <div key={index} className="flex items-center gap-2">
                        <input
                          type="text"
                          placeholder="Header name"
                          value={key}
                          onChange={(e) => updateHeader(index, key, e.target.value)}
                          className="flex-1 px-3 py-2 bg-gray-50 dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent transition-all duration-200"
                        />
                        <input
                          type="text"
                          placeholder="Header value"
                          value={value}
                          onChange={(e) => updateHeader(index, key, e.target.value)}
                          className="flex-1 px-3 py-2 bg-gray-50 dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent transition-all duration-200"
                        />
                        <button
                          onClick={() => removeHeader(key)}
                          className="p-2 text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors duration-200"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {activeTab === 'body' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">
                      Request Body
                    </h4>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => copyToClipboard(currentRequest.body)}
                        className="inline-flex items-center px-3 py-1.5 text-xs font-medium text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white rounded-lg transition-colors duration-200"
                      >
                        <Copy className="w-3 h-3 mr-1" />
                        Copy
                      </button>
                      <button
                        onClick={() => updateRequest('body', formatJson(currentRequest.body))}
                        className="inline-flex items-center px-3 py-1.5 text-xs font-medium text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white rounded-lg transition-colors duration-200"
                      >
                        Format
                      </button>
                    </div>
                  </div>
                  
                  <textarea
                    value={currentRequest.body}
                    onChange={(e) => updateRequest('body', e.target.value)}
                    placeholder="Enter request body..."
                    rows={12}
                    className="w-full px-3 py-2 bg-gray-900 dark:bg-gray-950 border border-gray-200 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent transition-all duration-200 font-mono text-sm text-white"
                  />
                </div>
              )}
            </div>
          </div>

          {/* Response Preview */}
          {currentRequest.response && (
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
              <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Response Preview
                  </h3>
                  <button
                    onClick={() => setShowResponseModal(true)}
                    className="inline-flex items-center px-3 py-1.5 text-xs font-medium text-primary bg-primary/10 hover:bg-primary/20 rounded-lg transition-colors duration-200"
                  >
                    View Details
                  </button>
                </div>
              </div>
              
              <div className="p-6">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                  <div>
                    <span className="text-sm text-gray-500 dark:text-gray-400">Status:</span>
                    <div className={`text-sm font-medium ${
                      currentRequest.response.status < 300 ? 'text-green-400' :
                      currentRequest.response.status < 400 ? 'text-yellow-400' :
                      'text-red-400'
                    }`}>
                      {currentRequest.response.status}
                    </div>
                  </div>
                  <div>
                    <span className="text-sm text-gray-500 dark:text-gray-400">Size:</span>
                    <div className="text-sm font-medium text-gray-900 dark:text-white">
                      {Math.round(currentRequest.response.body.length / 1024)} KB
                    </div>
                  </div>
                  <div>
                    <span className="text-sm text-gray-500 dark:text-gray-400">Time:</span>
                    <div className="text-sm font-medium text-gray-900 dark:text-white">
                      ~2.1s
                    </div>
                  </div>
                  <div>
                    <span className="text-sm text-gray-500 dark:text-gray-400">Type:</span>
                    <div className="text-sm font-medium text-gray-900 dark:text-white">
                      JSON
                    </div>
                  </div>
                </div>
                
                <div className="bg-gray-900 dark:bg-gray-950 rounded-lg p-4 font-mono text-sm max-h-64 overflow-y-auto">
                  <pre className="text-green-400">
                    {currentRequest.response.body.slice(0, 500)}
                    {currentRequest.response.body.length > 500 && '...'}
                  </pre>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Response Details Modal */}
      <EnhancedModal
        isOpen={showResponseModal}
        onClose={() => setShowResponseModal(false)}
        title="Response Details"
        maxWidth="4xl"
      >
        {currentResponse && (
          <div className="space-y-6">
            {/* Response Headers */}
            <div>
              <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
                Response Headers
              </h4>
              <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4 font-mono text-sm">
                {Object.entries(currentResponse.headers).map(([key, value]) => (
                  <div key={key} className="flex justify-between">
                    <span className="text-blue-400">{key}:</span>
                    <span className="text-white">{value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Response Body */}
            <div>
              <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
                Response Body
              </h4>
              <div className="bg-gray-900 dark:bg-gray-950 rounded-lg p-4 font-mono text-sm text-white max-h-96 overflow-y-auto">
                <pre>{currentResponse.body}</pre>
              </div>
            </div>
          </div>
        )}
      </EnhancedModal>
    </div>
  );
};

export default EnhancedRepeaterPage;
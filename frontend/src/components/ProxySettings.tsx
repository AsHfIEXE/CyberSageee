import React, { useState, useEffect } from 'react';
import { 
  Globe, 
  Settings, 
  Shield, 
  Lock, 
  Unlock,
  CheckCircle, 
  AlertTriangle,
  Server,
  Network,
  Key,
  Eye,
  EyeOff,
  Save,
  RefreshCw,
  TestTube,
  Wifi,
  Monitor,
  Database,
  Clock,
  Activity,
  Trash2
} from 'lucide-react';

// Types
interface ProxyConfig {
  enabled: boolean;
  host: string;
  port: number;
  username?: string;
  password?: string;
  protocol: 'http' | 'https' | 'socks4' | 'socks5';
  authRequired: boolean;
  timeout: number;
  retryAttempts: number;
  bypassList: string[];
  sslVerification: boolean;
  headers: { key: string; value: string; enabled: boolean }[];
}

interface CertificateConfig {
  enabled: boolean;
  certificatePath: string;
  privateKeyPath: string;
  caBundlePath?: string;
  autoGenerate: boolean;
  commonName: string;
  organization: string;
  country: string;
  state: string;
  city: string;
}

interface ProxyStats {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageResponseTime: number;
  activeConnections: number;
  bytesTransferred: number;
}

const ProxySettings: React.FC = () => {
  const [isDarkMode] = useState(true);
  const [activeTab, setActiveTab] = useState<'proxy' | 'certificate' | 'certificates' | 'monitoring'>('proxy');
  const [proxyConfig, setProxyConfig] = useState<ProxyConfig>({
    enabled: false,
    host: '127.0.0.1',
    port: 8080,
    username: '',
    password: '',
    protocol: 'http',
    authRequired: false,
    timeout: 30000,
    retryAttempts: 3,
    bypassList: ['localhost', '127.0.0.1', '::1'],
    sslVerification: true,
    headers: [
      { key: 'User-Agent', value: 'CyberSage-Scanner/2.0', enabled: true },
      { key: 'X-Forwarded-For', value: '', enabled: false },
      { key: 'X-Real-IP', value: '', enabled: false }
    ]
  });
  const [certificateConfig, setCertificateConfig] = useState<CertificateConfig>({
    enabled: false,
    certificatePath: '',
    privateKeyPath: '',
    caBundlePath: '',
    autoGenerate: true,
    commonName: 'CyberSage Proxy',
    organization: 'Security Testing',
    country: 'US',
    state: 'CA',
    city: 'San Francisco'
  });
  const [proxyStats, setProxyStats] = useState<ProxyStats>({
    totalRequests: 1247,
    successfulRequests: 1189,
    failedRequests: 58,
    averageResponseTime: 245,
    activeConnections: 12,
    bytesTransferred: 15728640
  });
  const [showPassword, setShowPassword] = useState(false);
  const [testResult, setTestResult] = useState<'idle' | 'testing' | 'success' | 'error'>('idle');
  const [testMessage, setTestMessage] = useState('');

  // Load configuration from localStorage
  useEffect(() => {
    const savedProxyConfig = localStorage.getItem('proxyConfig');
    const savedCertificateConfig = localStorage.getItem('certificateConfig');
    const savedProxyStats = localStorage.getItem('proxyStats');

    if (savedProxyConfig) {
      try {
        setProxyConfig(JSON.parse(savedProxyConfig));
      } catch (e) {
        console.error('Failed to load proxy config:', e);
      }
    }

    if (savedCertificateConfig) {
      try {
        setCertificateConfig(JSON.parse(savedCertificateConfig));
      } catch (e) {
        console.error('Failed to load certificate config:', e);
      }
    }

    if (savedProxyStats) {
      try {
        setProxyStats(JSON.parse(savedProxyStats));
      } catch (e) {
        console.error('Failed to load proxy stats:', e);
      }
    }
  }, []);

  // Save configuration to localStorage
  useEffect(() => {
    localStorage.setItem('proxyConfig', JSON.stringify(proxyConfig));
  }, [proxyConfig]);

  useEffect(() => {
    localStorage.setItem('certificateConfig', JSON.stringify(certificateConfig));
  }, [certificateConfig]);

  useEffect(() => {
    localStorage.setItem('proxyStats', JSON.stringify(proxyStats));
  }, [proxyStats]);

  // Test proxy connection
  const testProxyConnection = async () => {
    setTestResult('testing');
    setTestMessage('Testing proxy connection...');

    try {
      // Simulate proxy connection test
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Random success/failure for demonstration
      const success = Math.random() > 0.3;
      
      if (success) {
        setTestResult('success');
        setTestMessage('Proxy connection successful! Traffic is being routed through the proxy.');
        // Update stats
        setProxyStats(prev => ({
          ...prev,
          totalRequests: prev.totalRequests + 1,
          successfulRequests: prev.successfulRequests + 1,
          activeConnections: prev.activeConnections + 1
        }));
      } else {
        setTestResult('error');
        setTestMessage('Proxy connection failed. Please check your configuration and network connectivity.');
        // Update stats
        setProxyStats(prev => ({
          ...prev,
          totalRequests: prev.totalRequests + 1,
          failedRequests: prev.failedRequests + 1
        }));
      }
    } catch (error) {
      setTestResult('error');
      setTestMessage('Connection test failed: ' + (error instanceof Error ? error.message : 'Unknown error'));
    }
  };

  // Save configuration
  const saveConfiguration = () => {
    // In a real implementation, this would save to the backend
    setTestResult('success');
    setTestMessage('Configuration saved successfully!');
    setTimeout(() => setTestResult('idle'), 3000);
  };

  // Reset to defaults
  const resetToDefaults = () => {
    setProxyConfig({
      enabled: false,
      host: '127.0.0.1',
      port: 8080,
      username: '',
      password: '',
      protocol: 'http',
      authRequired: false,
      timeout: 30000,
      retryAttempts: 3,
      bypassList: ['localhost', '127.0.0.1', '::1'],
      sslVerification: true,
      headers: [
        { key: 'User-Agent', value: 'CyberSage-Scanner/2.0', enabled: true },
        { key: 'X-Forwarded-For', value: '', enabled: false },
        { key: 'X-Real-IP', value: '', enabled: false }
      ]
    });
  };

  // Add custom header
  const addCustomHeader = () => {
    setProxyConfig(prev => ({
      ...prev,
      headers: [...prev.headers, { key: '', value: '', enabled: true }]
    }));
  };

  // Remove header
  const removeHeader = (index: number) => {
    setProxyConfig(prev => ({
      ...prev,
      headers: prev.headers.filter((_, i) => i !== index)
    }));
  };

  // Update header
  const updateHeader = (index: number, field: 'key' | 'value' | 'enabled', value: any) => {
    setProxyConfig(prev => ({
      ...prev,
      headers: prev.headers.map((header, i) => 
        i === index ? { ...header, [field]: value } : header
      )
    }));
  };

  // Add bypass domain
  const addBypassDomain = (domain: string) => {
    if (domain.trim()) {
      setProxyConfig(prev => ({
        ...prev,
        bypassList: [...prev.bypassList, domain.trim()]
      }));
    }
  };

  // Remove bypass domain
  const removeBypassDomain = (index: number) => {
    setProxyConfig(prev => ({
      ...prev,
      bypassList: prev.bypassList.filter((_, i) => i !== index)
    }));
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className={`min-h-screen ${isDarkMode ? 'bg-gray-950' : 'bg-gray-50'}`}>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className={`text-3xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-2`}>
              Proxy Settings
            </h1>
            <p className={`${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
              Configure proxy servers, SSL certificates, and network monitoring
            </p>
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={testProxyConnection}
              disabled={!proxyConfig.enabled || testResult === 'testing'}
              className="px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:bg-gray-500 text-white rounded-lg flex items-center space-x-2"
            >
              {testResult === 'testing' ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <TestTube className="w-4 h-4" />
              )}
              <span>{testResult === 'testing' ? 'Testing...' : 'Test Connection'}</span>
            </button>
            <button
              onClick={saveConfiguration}
              className="px-4 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg flex items-center space-x-2"
            >
              <Save className="w-4 h-4" />
              <span>Save Config</span>
            </button>
          </div>
        </div>

        {/* Test Result Alert */}
        {testResult !== 'idle' && (
          <div className={`p-4 rounded-lg border ${
            testResult === 'success' 
              ? 'bg-green-500/20 border-green-500/30 text-green-400'
              : testResult === 'error'
              ? 'bg-red-500/20 border-red-500/30 text-red-400'
              : 'bg-blue-500/20 border-blue-500/30 text-blue-400'
          }`}>
            <div className="flex items-center space-x-2">
              {testResult === 'success' && <CheckCircle className="w-5 h-5" />}
              {testResult === 'error' && <AlertTriangle className="w-5 h-5" />}
              {testResult === 'testing' && <RefreshCw className="w-5 h-5 animate-spin" />}
              <span>{testMessage}</span>
            </div>
          </div>
        )}

        {/* Tab Navigation */}
        <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-xl`}>
          <div className="border-b border-gray-700">
            <nav className="flex space-x-8 px-6">
              {[
                { id: 'proxy', label: 'Proxy Configuration', icon: Globe },
                { id: 'certificate', label: 'SSL Certificate', icon: Lock },
                { id: 'certificates', label: 'Certificate Management', icon: Shield },
                { id: 'monitoring', label: 'Monitoring', icon: Activity }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`flex items-center space-x-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                    activeTab === tab.id
                      ? 'border-blue-500 text-blue-400'
                      : 'border-transparent text-gray-400 hover:text-gray-300'
                  }`}
                >
                  <tab.icon className="w-4 h-4" />
                  <span>{tab.label}</span>
                </button>
              ))}
            </nav>
          </div>

          <div className="p-6">
            {/* Proxy Configuration Tab */}
            {activeTab === 'proxy' && (
              <div className="space-y-6">
                {/* Enable/Disable Proxy */}
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className={`text-lg font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                      Proxy Server
                    </h3>
                    <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                      Enable HTTP/HTTPS proxy for request interception
                    </p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={proxyConfig.enabled}
                      onChange={(e) => setProxyConfig(prev => ({ ...prev, enabled: e.target.checked }))}
                      className="sr-only peer"
                    />
                    <div className={`w-11 h-6 rounded-full peer ${
                      proxyConfig.enabled ? 'bg-blue-600' : 'bg-gray-600'
                    } peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all`}></div>
                  </label>
                </div>

                {proxyConfig.enabled && (
                  <>
                    {/* Proxy Settings */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div>
                        <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-2`}>
                          Proxy Host
                        </label>
                        <input
                          type="text"
                          value={proxyConfig.host}
                          onChange={(e) => setProxyConfig(prev => ({ ...prev, host: e.target.value }))}
                          placeholder="127.0.0.1"
                          className={`w-full px-4 py-2 rounded-lg border ${
                            isDarkMode
                              ? 'bg-gray-700 border-gray-600 text-white'
                              : 'bg-white border-gray-300 text-gray-900'
                          }`}
                        />
                      </div>
                      <div>
                        <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-2`}>
                          Proxy Port
                        </label>
                        <input
                          type="number"
                          value={proxyConfig.port}
                          onChange={(e) => setProxyConfig(prev => ({ ...prev, port: parseInt(e.target.value) || 8080 }))}
                          placeholder="8080"
                          className={`w-full px-4 py-2 rounded-lg border ${
                            isDarkMode
                              ? 'bg-gray-700 border-gray-600 text-white'
                              : 'bg-white border-gray-300 text-gray-900'
                          }`}
                        />
                      </div>
                      <div>
                        <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-2`}>
                          Protocol
                        </label>
                        <select
                          value={proxyConfig.protocol}
                          onChange={(e) => setProxyConfig(prev => ({ ...prev, protocol: e.target.value as any }))}
                          className={`w-full px-4 py-2 rounded-lg border ${
                            isDarkMode
                              ? 'bg-gray-700 border-gray-600 text-white'
                              : 'bg-white border-gray-300 text-gray-900'
                          }`}
                        >
                          <option value="http">HTTP</option>
                          <option value="https">HTTPS</option>
                          <option value="socks4">SOCKS4</option>
                          <option value="socks5">SOCKS5</option>
                        </select>
                      </div>
                      <div>
                        <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-2`}>
                          Timeout (ms)
                        </label>
                        <input
                          type="number"
                          value={proxyConfig.timeout}
                          onChange={(e) => setProxyConfig(prev => ({ ...prev, timeout: parseInt(e.target.value) || 30000 }))}
                          placeholder="30000"
                          className={`w-full px-4 py-2 rounded-lg border ${
                            isDarkMode
                              ? 'bg-gray-700 border-gray-600 text-white'
                              : 'bg-white border-gray-300 text-gray-900'
                          }`}
                        />
                      </div>
                    </div>

                    {/* Authentication */}
                    <div className={`p-4 rounded-lg border ${
                      isDarkMode ? 'bg-gray-700 border-gray-600' : 'bg-gray-50 border-gray-200'
                    }`}>
                      <div className="flex items-center justify-between mb-4">
                        <h4 className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                          Authentication
                        </h4>
                        <label className="flex items-center space-x-2">
                          <input
                            type="checkbox"
                            checked={proxyConfig.authRequired}
                            onChange={(e) => setProxyConfig(prev => ({ ...prev, authRequired: e.target.checked }))}
                            className="w-4 h-4"
                          />
                          <span className={`text-sm ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                            Authentication Required
                          </span>
                        </label>
                      </div>
                      {proxyConfig.authRequired && (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-2`}>
                              Username
                            </label>
                            <input
                              type="text"
                              value={proxyConfig.username}
                              onChange={(e) => setProxyConfig(prev => ({ ...prev, username: e.target.value }))}
                              className={`w-full px-4 py-2 rounded-lg border ${
                                isDarkMode
                                  ? 'bg-gray-600 border-gray-500 text-white'
                                  : 'bg-white border-gray-300 text-gray-900'
                              }`}
                            />
                          </div>
                          <div>
                            <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-2`}>
                              Password
                            </label>
                            <div className="relative">
                              <input
                                type={showPassword ? 'text' : 'password'}
                                value={proxyConfig.password}
                                onChange={(e) => setProxyConfig(prev => ({ ...prev, password: e.target.value }))}
                                className={`w-full px-4 py-2 pr-10 rounded-lg border ${
                                  isDarkMode
                                    ? 'bg-gray-600 border-gray-500 text-white'
                                    : 'bg-white border-gray-300 text-gray-900'
                                }`}
                              />
                              <button
                                type="button"
                                onClick={() => setShowPassword(!showPassword)}
                                className={`absolute right-3 top-1/2 transform -translate-y-1/2 ${
                                  isDarkMode ? 'text-gray-400 hover:text-gray-300' : 'text-gray-600 hover:text-gray-700'
                                }`}
                              >
                                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                              </button>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* SSL Verification */}
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                          SSL Certificate Verification
                        </h4>
                        <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                          Verify SSL certificates when connecting through proxy
                        </p>
                      </div>
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input
                          type="checkbox"
                          checked={proxyConfig.sslVerification}
                          onChange={(e) => setProxyConfig(prev => ({ ...prev, sslVerification: e.target.checked }))}
                          className="sr-only peer"
                        />
                        <div className={`w-11 h-6 rounded-full peer ${
                          proxyConfig.sslVerification ? 'bg-blue-600' : 'bg-gray-600'
                        } peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all`}></div>
                      </label>
                    </div>

                    {/* Custom Headers */}
                    <div>
                      <div className="flex items-center justify-between mb-4">
                        <h4 className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                          Custom Headers
                        </h4>
                        <button
                          onClick={addCustomHeader}
                          className="px-3 py-1 bg-blue-500 hover:bg-blue-600 text-white rounded text-sm"
                        >
                          Add Header
                        </button>
                      </div>
                      <div className="space-y-2">
                        {proxyConfig.headers.map((header, index) => (
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
                              className={`flex-1 px-3 py-2 rounded border ${
                                isDarkMode
                                  ? 'bg-gray-700 border-gray-600 text-white'
                                  : 'bg-white border-gray-300 text-gray-900'
                              }`}
                            />
                            <input
                              type="text"
                              value={header.value}
                              onChange={(e) => updateHeader(index, 'value', e.target.value)}
                              placeholder="Header value"
                              className={`flex-1 px-3 py-2 rounded border ${
                                isDarkMode
                                  ? 'bg-gray-700 border-gray-600 text-white'
                                  : 'bg-white border-gray-300 text-gray-900'
                              }`}
                            />
                            <button
                              onClick={() => removeHeader(index)}
                              className="p-2 text-red-400 hover:text-red-300"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Bypass List */}
                    <div>
                      <h4 className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-4`}>
                        Bypass Proxy For
                      </h4>
                      <div className="space-y-2 mb-4">
                        {proxyConfig.bypassList.map((domain, index) => (
                          <div key={index} className="flex items-center space-x-2">
                            <span className={`flex-1 px-3 py-2 rounded border ${
                              isDarkMode ? 'bg-gray-700 border-gray-600 text-white' : 'bg-white border-gray-300 text-gray-900'
                            }`}>
                              {domain}
                            </span>
                            <button
                              onClick={() => removeBypassDomain(index)}
                              className="p-2 text-red-400 hover:text-red-300"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        ))}
                      </div>
                      <div className="flex space-x-2">
                        <input
                          type="text"
                          placeholder="Add domain to bypass (e.g., localhost)"
                          className={`flex-1 px-4 py-2 rounded-lg border ${
                            isDarkMode
                              ? 'bg-gray-700 border-gray-600 text-white'
                              : 'bg-white border-gray-300 text-gray-900'
                          }`}
                          onKeyPress={(e) => {
                            if (e.key === 'Enter') {
                              addBypassDomain(e.currentTarget.value);
                              e.currentTarget.value = '';
                            }
                          }}
                        />
                        <button
                          onClick={() => {
                            const input = document.querySelector('input[placeholder="Add domain to bypass"]') as HTMLInputElement;
                            if (input) {
                              addBypassDomain(input.value);
                              input.value = '';
                            }
                          }}
                          className="px-4 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg"
                        >
                          Add
                        </button>
                      </div>
                    </div>
                  </>
                )}
              </div>
            )}

            {/* SSL Certificate Tab */}
            {activeTab === 'certificate' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className={`text-lg font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                      SSL Certificate Generation
                    </h3>
                    <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                      Generate SSL certificates for HTTPS interception
                    </p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={certificateConfig.enabled}
                      onChange={(e) => setCertificateConfig(prev => ({ ...prev, enabled: e.target.checked }))}
                      className="sr-only peer"
                    />
                    <div className={`w-11 h-6 rounded-full peer ${
                      certificateConfig.enabled ? 'bg-blue-600' : 'bg-gray-600'
                    } peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all`}></div>
                  </label>
                </div>

                {certificateConfig.enabled && (
                  <>
                    {/* Auto-generate option */}
                    <div className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        checked={certificateConfig.autoGenerate}
                        onChange={(e) => setCertificateConfig(prev => ({ ...prev, autoGenerate: e.target.checked }))}
                        className="w-4 h-4"
                      />
                      <span className={`${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                        Auto-generate certificates
                      </span>
                    </div>

                    {certificateConfig.autoGenerate ? (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-2`}>
                            Common Name
                          </label>
                          <input
                            type="text"
                            value={certificateConfig.commonName}
                            onChange={(e) => setCertificateConfig(prev => ({ ...prev, commonName: e.target.value }))}
                            className={`w-full px-4 py-2 rounded-lg border ${
                              isDarkMode
                                ? 'bg-gray-700 border-gray-600 text-white'
                                : 'bg-white border-gray-300 text-gray-900'
                            }`}
                          />
                        </div>
                        <div>
                          <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-2`}>
                            Organization
                          </label>
                          <input
                            type="text"
                            value={certificateConfig.organization}
                            onChange={(e) => setCertificateConfig(prev => ({ ...prev, organization: e.target.value }))}
                            className={`w-full px-4 py-2 rounded-lg border ${
                              isDarkMode
                                ? 'bg-gray-700 border-gray-600 text-white'
                                : 'bg-white border-gray-300 text-gray-900'
                            }`}
                          />
                        </div>
                        <div>
                          <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-2`}>
                            Country
                          </label>
                          <input
                            type="text"
                            value={certificateConfig.country}
                            onChange={(e) => setCertificateConfig(prev => ({ ...prev, country: e.target.value }))}
                            className={`w-full px-4 py-2 rounded-lg border ${
                              isDarkMode
                                ? 'bg-gray-700 border-gray-600 text-white'
                                : 'bg-white border-gray-300 text-gray-900'
                            }`}
                          />
                        </div>
                        <div>
                          <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-2`}>
                            State/Province
                          </label>
                          <input
                            type="text"
                            value={certificateConfig.state}
                            onChange={(e) => setCertificateConfig(prev => ({ ...prev, state: e.target.value }))}
                            className={`w-full px-4 py-2 rounded-lg border ${
                              isDarkMode
                                ? 'bg-gray-700 border-gray-600 text-white'
                                : 'bg-white border-gray-300 text-gray-900'
                            }`}
                          />
                        </div>
                      </div>
                    ) : (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-2`}>
                            Certificate Path
                          </label>
                          <input
                            type="text"
                            value={certificateConfig.certificatePath}
                            onChange={(e) => setCertificateConfig(prev => ({ ...prev, certificatePath: e.target.value }))}
                            placeholder="/path/to/certificate.pem"
                            className={`w-full px-4 py-2 rounded-lg border ${
                              isDarkMode
                                ? 'bg-gray-700 border-gray-600 text-white'
                                : 'bg-white border-gray-300 text-gray-900'
                            }`}
                          />
                        </div>
                        <div>
                          <label className={`block text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-2`}>
                            Private Key Path
                          </label>
                          <input
                            type="text"
                            value={certificateConfig.privateKeyPath}
                            onChange={(e) => setCertificateConfig(prev => ({ ...prev, privateKeyPath: e.target.value }))}
                            placeholder="/path/to/private.key"
                            className={`w-full px-4 py-2 rounded-lg border ${
                              isDarkMode
                                ? 'bg-gray-700 border-gray-600 text-white'
                                : 'bg-white border-gray-300 text-gray-900'
                            }`}
                          />
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* Certificate Management Tab */}
            {activeTab === 'certificates' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <h3 className={`text-lg font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                    Installed Certificates
                  </h3>
                  <button className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg">
                    Import Certificate
                  </button>
                </div>

                <div className={`${isDarkMode ? 'bg-gray-700 border-gray-600' : 'bg-gray-50 border-gray-200'} border rounded-lg p-4`}>
                  <div className="flex items-center space-x-3">
                    <Shield className="w-8 h-8 text-green-400" />
                    <div>
                      <h4 className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                        CyberSage Proxy CA
                      </h4>
                      <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                        Issued: 2024-01-01 • Expires: 2025-01-01 • Status: Active
                      </p>
                    </div>
                    <div className="ml-auto">
                      <span className="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs font-medium">
                        TRUSTED
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Monitoring Tab */}
            {activeTab === 'monitoring' && (
              <div className="space-y-6">
                <h3 className={`text-lg font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                  Proxy Statistics
                </h3>

                {/* Statistics Cards */}
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  <div className={`${isDarkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-200'} border rounded-lg p-4`}>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className={`text-2xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                          {proxyStats.totalRequests}
                        </p>
                        <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                          Total Requests
                        </p>
                      </div>
                      <Network className="w-8 h-8 text-blue-400" />
                    </div>
                  </div>
                  <div className={`${isDarkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-200'} border rounded-lg p-4`}>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className={`text-2xl font-bold text-green-400`}>
                          {proxyStats.successfulRequests}
                        </p>
                        <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                          Successful
                        </p>
                      </div>
                      <CheckCircle className="w-8 h-8 text-green-400" />
                    </div>
                  </div>
                  <div className={`${isDarkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-200'} border rounded-lg p-4`}>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className={`text-2xl font-bold text-red-400`}>
                          {proxyStats.failedRequests}
                        </p>
                        <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                          Failed
                        </p>
                      </div>
                      <AlertTriangle className="w-8 h-8 text-red-400" />
                    </div>
                  </div>
                  <div className={`${isDarkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-200'} border rounded-lg p-4`}>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className={`text-2xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                          {proxyStats.averageResponseTime}ms
                        </p>
                        <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                          Avg Response
                        </p>
                      </div>
                      <Clock className="w-8 h-8 text-yellow-400" />
                    </div>
                  </div>
                  <div className={`${isDarkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-200'} border rounded-lg p-4`}>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className={`text-2xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                          {proxyStats.activeConnections}
                        </p>
                        <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                          Active Connections
                        </p>
                      </div>
                      <Wifi className="w-8 h-8 text-purple-400" />
                    </div>
                  </div>
                  <div className={`${isDarkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-200'} border rounded-lg p-4`}>
                    <div className="flex items-center justify-between">
                      <div>
                        <p className={`text-2xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                          {formatBytes(proxyStats.bytesTransferred)}
                        </p>
                        <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                          Data Transferred
                        </p>
                      </div>
                      <Database className="w-8 h-8 text-indigo-400" />
                    </div>
                  </div>
                </div>

                {/* Success Rate */}
                <div className={`${isDarkMode ? 'bg-gray-700 border-gray-600' : 'bg-gray-50 border-gray-200'} border rounded-lg p-4`}>
                  <h4 className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-3`}>
                    Success Rate
                  </h4>
                  <div className="flex items-center space-x-4">
                    <div className="flex-1">
                      <div className={`w-full ${isDarkMode ? 'bg-gray-600' : 'bg-gray-200'} rounded-full h-3`}>
                        <div
                          className="bg-green-500 h-3 rounded-full transition-all duration-300"
                          style={{ 
                            width: `${proxyStats.totalRequests > 0 ? (proxyStats.successfulRequests / proxyStats.totalRequests) * 100 : 0}%` 
                          }}
                        />
                      </div>
                    </div>
                    <span className={`text-lg font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                      {proxyStats.totalRequests > 0 
                        ? ((proxyStats.successfulRequests / proxyStats.totalRequests) * 100).toFixed(1)
                        : 0}%
                    </span>
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

export default ProxySettings;
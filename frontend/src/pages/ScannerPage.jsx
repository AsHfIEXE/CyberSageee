import React, { useState } from 'react';
import { useScan } from '../context/EnhancedScanContext';
import { SCAN_STATUS } from '../utils/constants';

const ScannerPage = () => {
  const { scanStatus, connected, actions } = useScan();
  const [targetUrl, setTargetUrl] = useState('');
  const [scanConfig, setScanConfig] = useState({
    depth: 2,
    threads: 5,
    timeout: 30,
    follow_redirects: true,
    user_agent: 'CyberSage Scanner 2.0',
    include_subdomains: false,
    custom_headers: {},
    exclude_paths: ['/admin', '/test', '/dev'],
    modules: {
      vulnerability_scanner: true,
      directory_bruteforce: true,
      sql_injection: true,
      xss_detection: true,
      csrf_check: true,
      ssl_analysis: true,
      header_analysis: true,
      technology_detection: true,
    }
  });

  const handleStartScan = () => {
    if (!targetUrl.trim()) {
      alert('Please enter a target URL');
      return;
    }

    const scanPayload = {
      target: targetUrl,
      config: scanConfig,
      timestamp: Date.now(),
    };

    actions.startScan(scanPayload);
    setTargetUrl('');
  };

  const handleConfigChange = (key, value) => {
    setScanConfig(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const handleModuleToggle = (module) => {
    setScanConfig(prev => ({
      ...prev,
      modules: {
        ...prev.modules,
        [module]: !prev.modules[module]
      }
    }));
  };

  const scanModules = [
    { key: 'vulnerability_scanner', name: 'Vulnerability Scanner', icon: '🔍', desc: 'Detect known vulnerabilities' },
    { key: 'directory_bruteforce', name: 'Directory Bruteforce', icon: '📁', desc: 'Find hidden directories' },
    { key: 'sql_injection', name: 'SQL Injection', icon: '💉', desc: 'Test for SQL injection flaws' },
    { key: 'xss_detection', name: 'XSS Detection', icon: '⚡', desc: 'Cross-site scripting testing' },
    { key: 'csrf_check', name: 'CSRF Protection', icon: '🛡️', desc: 'Cross-site request forgery tests' },
    { key: 'ssl_analysis', name: 'SSL/TLS Analysis', icon: '🔒', desc: 'Certificate and protocol analysis' },
    { key: 'header_analysis', name: 'Header Analysis', icon: '📋', desc: 'Security header evaluation' },
    { key: 'technology_detection', name: 'Tech Stack Detection', icon: '🔧', desc: 'Identify technologies used' },
  ];

  if (!connected) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <div className="text-center">
          <div className="text-red-400 text-lg mb-4">⚠️ Backend Not Connected</div>
          <p className="text-gray-400">
            Make sure the backend server is running on {process.env.REACT_APP_BACKEND_URL || 'http://localhost:5000'}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold">Security Scanner</h2>
        {scanStatus !== SCAN_STATUS.IDLE && (
          <div className={`px-4 py-2 rounded-lg font-semibold ${
            scanStatus === SCAN_STATUS.RUNNING ? 'bg-green-500/20 text-green-400' :
            scanStatus === SCAN_STATUS.COMPLETED ? 'bg-blue-500/20 text-blue-400' :
            'bg-red-500/20 text-red-400'
          }`}>
            {scanStatus === SCAN_STATUS.RUNNING ? '🔄 Scanning...' :
             scanStatus === SCAN_STATUS.COMPLETED ? '✅ Scan Complete' :
             '⚠️ Scan Failed'}
          </div>
        )}
      </div>

      {/* Target Configuration */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
        <h3 className="text-xl font-bold mb-4">Target Configuration</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Target URL
              </label>
              <input
                type="url"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://example.com"
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                disabled={scanStatus === SCAN_STATUS.RUNNING}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Scan Depth
                </label>
                <select
                  value={scanConfig.depth}
                  onChange={(e) => handleConfigChange('depth', parseInt(e.target.value))}
                  className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-purple-500"
                  disabled={scanStatus === SCAN_STATUS.RUNNING}
                >
                  <option value={1}>1 - Surface</option>
                  <option value={2}>2 - Moderate</option>
                  <option value={3}>3 - Deep</option>
                  <option value={4}>4 - Extensive</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Threads
                </label>
                <select
                  value={scanConfig.threads}
                  onChange={(e) => handleConfigChange('threads', parseInt(e.target.value))}
                  className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-purple-500"
                  disabled={scanStatus === SCAN_STATUS.RUNNING}
                >
                  <option value={1}>1 Thread</option>
                  <option value={3}>3 Threads</option>
                  <option value={5}>5 Threads</option>
                  <option value={10}>10 Threads</option>
                </select>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={scanConfig.follow_redirects}
                  onChange={(e) => handleConfigChange('follow_redirects', e.target.checked)}
                  className="mr-2"
                  disabled={scanStatus === SCAN_STATUS.RUNNING}
                />
                <span className="text-sm text-gray-300">Follow redirects</span>
              </label>

              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={scanConfig.include_subdomains}
                  onChange={(e) => handleConfigChange('include_subdomains', e.target.checked)}
                  className="mr-2"
                  disabled={scanStatus === SCAN_STATUS.RUNNING}
                />
                <span className="text-sm text-gray-300">Include subdomains</span>
              </label>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                User Agent
              </label>
              <input
                type="text"
                value={scanConfig.user_agent}
                onChange={(e) => handleConfigChange('user_agent', e.target.value)}
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-purple-500"
                disabled={scanStatus === SCAN_STATUS.RUNNING}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Timeout (seconds)
              </label>
              <input
                type="number"
                value={scanConfig.timeout}
                onChange={(e) => handleConfigChange('timeout', parseInt(e.target.value))}
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-purple-500"
                min="10"
                max="120"
                disabled={scanStatus === SCAN_STATUS.RUNNING}
              />
            </div>
          </div>
        </div>

        <div className="mt-6">
          <button
            onClick={handleStartScan}
            disabled={scanStatus === SCAN_STATUS.RUNNING || !targetUrl.trim()}
            className={`px-6 py-3 rounded-lg font-semibold transition-all ${
              scanStatus === SCAN_STATUS.RUNNING || !targetUrl.trim()
                ? 'bg-gray-700 text-gray-400 cursor-not-allowed'
                : 'bg-gradient-to-r from-purple-600 to-pink-600 text-white hover:from-purple-700 hover:to-pink-700'
            }`}
          >
            {scanStatus === SCAN_STATUS.RUNNING ? '⏳ Scanning in Progress' : '🚀 Start Security Scan'}
          </button>
        </div>
      </div>

      {/* Scanner Modules */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
        <h3 className="text-xl font-bold mb-4">Scanner Modules</h3>
        <p className="text-sm text-gray-400 mb-4">
          Select which security modules to include in the scan
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {scanModules.map((module) => (
            <div 
              key={module.key}
              className={`p-4 rounded-lg border-2 cursor-pointer transition-all ${
                scanConfig.modules[module.key]
                  ? 'border-purple-500 bg-purple-900/20'
                  : 'border-gray-700 bg-gray-800/50 hover:border-gray-600'
              }`}
              onClick={() => handleModuleToggle(module.key)}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-2xl">{module.icon}</span>
                <div className={`w-4 h-4 rounded border-2 ${
                  scanConfig.modules[module.key]
                    ? 'bg-purple-500 border-purple-500'
                    : 'border-gray-500'
                }`}>
                  {scanConfig.modules[module.key] && (
                    <div className="w-full h-full bg-white rounded-sm scale-50"></div>
                  )}
                </div>
              </div>
              <h4 className="font-semibold text-sm">{module.name}</h4>
              <p className="text-xs text-gray-400 mt-1">{module.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Quick Tips */}
      <div className="bg-gradient-to-br from-blue-900/30 to-cyan-900/30 rounded-xl border border-blue-500/50 p-6">
        <h3 className="text-lg font-bold mb-3 flex items-center">
          <span className="mr-2">💡</span>
          Quick Tips
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-gray-300">
          <div>
            <strong>Target Selection:</strong> Always scan only websites you own or have explicit permission to test.
          </div>
          <div>
            <strong>Scan Depth:</strong> Higher depths take longer but provide more comprehensive results.
          </div>
          <div>
            <strong>Thread Usage:</strong> More threads speed up scanning but may trigger rate limiting.
          </div>
          <div>
            <strong>User Agent:</strong> Customize to avoid basic blocking mechanisms.
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScannerPage;
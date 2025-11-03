import React, { useState } from 'react';

const SpiderConfig = ({ onConfigChange, isScanning }) => {
  const [config, setConfig] = useState({
    maxDepth: 2,
    maxPages: 30,
    timeout: 10,
    userAgent: 'CyberSage/2.0 (Security Scanner)',
    enableAjax: true,
    enableForms: true,
    enableButtons: true,
    enableNetworkMonitoring: true
  });

  const handleConfigChange = (key, value) => {
    const newConfig = { ...config, [key]: value };
    setConfig(newConfig);
    onConfigChange(newConfig);
  };

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
      <h2 className="text-xl font-bold text-white mb-4 flex items-center">
        <span className="mr-2">⚙️</span>
        Spider Configuration
      </h2>

      <div className="space-y-4">
        {/* Basic Settings */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-gray-400 text-sm font-bold mb-2">Max Depth</label>
            <input
              type="number"
              min="1"
              max="5"
              value={config.maxDepth}
              onChange={(e) => handleConfigChange('maxDepth', parseInt(e.target.value))}
              disabled={isScanning}
              className="w-full p-2 bg-gray-900 border border-gray-700 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-purple-500 disabled:opacity-50"
            />
          </div>
          
          <div>
            <label className="block text-gray-400 text-sm font-bold mb-2">Max Pages</label>
            <input
              type="number"
              min="10"
              max="100"
              value={config.maxPages}
              onChange={(e) => handleConfigChange('maxPages', parseInt(e.target.value))}
              disabled={isScanning}
              className="w-full p-2 bg-gray-900 border border-gray-700 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-purple-500 disabled:opacity-50"
            />
          </div>
        </div>

        <div>
          <label className="block text-gray-400 text-sm font-bold mb-2">Timeout (seconds)</label>
          <input
            type="number"
            min="5"
            max="30"
            value={config.timeout}
            onChange={(e) => handleConfigChange('timeout', parseInt(e.target.value))}
            disabled={isScanning}
            className="w-full p-2 bg-gray-900 border border-gray-700 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-purple-500 disabled:opacity-50"
          />
        </div>

        <div>
          <label className="block text-gray-400 text-sm font-bold mb-2">User Agent</label>
          <input
            type="text"
            value={config.userAgent}
            onChange={(e) => handleConfigChange('userAgent', e.target.value)}
            disabled={isScanning}
            className="w-full p-2 bg-gray-900 border border-gray-700 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-purple-500 disabled:opacity-50"
          />
        </div>

        {/* Feature Toggles */}
        <div className="space-y-3">
          <h3 className="text-white font-semibold">🤖 AJAX Spider Features</h3>
          
          <div className="space-y-2">
            <label className="flex items-center space-x-3">
              <input
                type="checkbox"
                checked={config.enableAjax}
                onChange={(e) => handleConfigChange('enableAjax', e.target.checked)}
                disabled={isScanning}
                className="w-4 h-4 text-purple-600 bg-gray-900 border-gray-700 rounded focus:ring-purple-500 disabled:opacity-50"
              />
              <span className="text-gray-300 text-sm">Enable AJAX-aware crawling</span>
            </label>
            
            <label className="flex items-center space-x-3">
              <input
                type="checkbox"
                checked={config.enableForms}
                onChange={(e) => handleConfigChange('enableForms', e.target.checked)}
                disabled={isScanning}
                className="w-4 h-4 text-purple-600 bg-gray-900 border-gray-700 rounded focus:ring-purple-500 disabled:opacity-50"
              />
              <span className="text-gray-300 text-sm">Interact with forms</span>
            </label>
            
            <label className="flex items-center space-x-3">
              <input
                type="checkbox"
                checked={config.enableButtons}
                onChange={(e) => handleConfigChange('enableButtons', e.target.checked)}
                disabled={isScanning}
                className="w-4 h-4 text-purple-600 bg-gray-900 border-gray-700 rounded focus:ring-purple-500 disabled:opacity-50"
              />
              <span className="text-gray-300 text-sm">Click interactive buttons</span>
            </label>
            
            <label className="flex items-center space-x-3">
              <input
                type="checkbox"
                checked={config.enableNetworkMonitoring}
                onChange={(e) => handleConfigChange('enableNetworkMonitoring', e.target.checked)}
                disabled={isScanning}
                className="w-4 h-4 text-purple-600 bg-gray-900 border-gray-700 rounded focus:ring-purple-500 disabled:opacity-50"
              />
              <span className="text-gray-300 text-sm">Monitor network traffic</span>
            </label>
          </div>
        </div>

        {/* Info Panel */}
        <div className="bg-blue-900/20 border border-blue-500/30 rounded p-3">
          <h4 className="text-blue-400 font-semibold text-sm mb-2">💡 Configuration Tips</h4>
          <div className="text-xs text-gray-300 space-y-1">
            <div>• <strong>Max Depth:</strong> How many levels deep to crawl (1-5)</div>
            <div>• <strong>Max Pages:</strong> Maximum pages to discover (10-100)</div>
            <div>• <strong>AJAX Spider:</strong> Essential for JavaScript-heavy applications</div>
            <div>• <strong>Form Interaction:</strong> Discovers endpoints through form submissions</div>
            <div>• <strong>Network Monitoring:</strong> Captures API calls and AJAX requests</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SpiderConfig;


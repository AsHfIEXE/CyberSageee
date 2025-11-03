import React, { useState, useEffect } from 'react';

const CrawlingScannerDisplay = ({ socket, scanId }) => {
  const [crawlStatus, setCrawlStatus] = useState({
    crawled: 0,
    queued: 0,
    currentDepth: 0,
    maxDepth: 5,
    formsFound: 0,
    parametersFound: 0,
    apiEndpoints: 0,
    currentlyCrawling: null,
    inScope: null
  });

  const [scanProgress, setScanProgress] = useState({
    totalTests: 0,
    completed: 0,
    progressPercent: 0,
    vulnerabilitiesFound: 0,
    currentAttack: null,
    lastAttacks: []
  });

  const [crawlLog, setCrawlLog] = useState([]);
  const [attackLog, setAttackLog] = useState([]);
  const [activeTab, setActiveTab] = useState('crawl');

  useEffect(() => {
    if (!socket) return;

    // Crawling events
    socket.on('crawl_status', (data) => {
      setCrawlStatus(data);
    });

    socket.on('crawl_log', (log) => {
      setCrawlLog(prev => [...prev.slice(-99), log].slice(-100));
    });

    // Scanning events
    socket.on('scan_progress', (data) => {
      setScanProgress(data);
    });

    socket.on('attack_log', (log) => {
      setAttackLog(prev => [...prev.slice(-99), log].slice(-100));
    });

    return () => {
      socket.off('crawl_status');
      socket.off('crawl_log');
      socket.off('scan_progress');
      socket.off('attack_log');
    };
  }, [socket]);

  const getStatusColor = (status) => {
    switch (status) {
      case 'CRAWLING': return 'text-blue-400';
      case 'CRAWLED': return 'text-green-400';
      case 'ATTACKING': return 'text-yellow-400';
      case 'VULNERABLE': return 'text-red-400';
      case 'ERROR': return 'text-red-500';
      case 'OUT_OF_SCOPE': return 'text-gray-500';
      case 'BLOCKED': return 'text-orange-400';
      default: return 'text-gray-400';
    }
  };

  const getAttackTypeColor = (type) => {
    switch (type) {
      case 'XSS': return 'bg-yellow-500';
      case 'SQLi': return 'bg-red-500';
      case 'Command': return 'bg-purple-500';
      case 'Path Traversal': return 'bg-orange-500';
      case 'XXE': return 'bg-pink-500';
      default: return 'bg-gray-500';
    }
  };

  return (
    <div className="bg-gray-900 rounded-lg p-6">
      {/* Header with Tabs */}
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">
          Live Scanning Details
        </h2>
        
        <div className="flex space-x-2">
          <button
            onClick={() => setActiveTab('crawl')}
            className={`px-4 py-2 rounded-lg transition ${
              activeTab === 'crawl' 
                ? 'bg-purple-600 text-white' 
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            🕷️ Crawling
          </button>
          <button
            onClick={() => setActiveTab('scan')}
            className={`px-4 py-2 rounded-lg transition ${
              activeTab === 'scan' 
                ? 'bg-purple-600 text-white' 
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            ⚔️ Attacking
          </button>
        </div>
      </div>

      {/* Crawling Tab */}
      {activeTab === 'crawl' && (
        <div className="space-y-6">
          {/* Crawl Status Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-gray-400 text-sm mb-1">Pages Crawled</div>
              <div className="text-2xl font-bold text-green-400">{crawlStatus.crawled}</div>
              <div className="text-xs text-gray-500 mt-1">Queued: {crawlStatus.queued}</div>
            </div>
            
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-gray-400 text-sm mb-1">Current Depth</div>
              <div className="text-2xl font-bold text-blue-400">
                {crawlStatus.currentDepth}/{crawlStatus.maxDepth}
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2 mt-2">
                <div 
                  className="bg-blue-500 h-2 rounded-full transition-all"
                  style={{ width: `${(crawlStatus.currentDepth / crawlStatus.maxDepth) * 100}%` }}
                />
              </div>
            </div>
            
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-gray-400 text-sm mb-1">Forms Found</div>
              <div className="text-2xl font-bold text-yellow-400">{crawlStatus.formsFound}</div>
              <div className="text-xs text-gray-500 mt-1">Parameters: {crawlStatus.parametersFound}</div>
            </div>
            
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-gray-400 text-sm mb-1">API Endpoints</div>
              <div className="text-2xl font-bold text-purple-400">{crawlStatus.apiEndpoints}</div>
              <div className="text-xs text-gray-500 mt-1">In Scope: {crawlStatus.inScope}</div>
            </div>
          </div>

          {/* Currently Crawling */}
          {crawlStatus.currentlyCrawling && (
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="flex items-center space-x-3">
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-500"></div>
                <span className="text-gray-400">Currently crawling:</span>
                <span className="text-blue-400 font-mono text-sm truncate flex-1">
                  {crawlStatus.currentlyCrawling}
                </span>
              </div>
            </div>
          )}

          {/* Crawl Log */}
          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-lg font-semibold mb-3 text-gray-300">Crawl Activity Log</h3>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {crawlLog.map((log, index) => (
                <div key={index} className="flex items-start space-x-3 text-sm">
                  <span className={`font-bold ${getStatusColor(log.type)}`}>
                    [{log.type}]
                  </span>
                  <span className="text-gray-400 flex-1 font-mono break-all">
                    {log.message}
                  </span>
                  <span className="text-gray-600 text-xs">
                    {new Date(log.timestamp * 1000).toLocaleTimeString()}
                  </span>
                </div>
              ))}
              {crawlLog.length === 0 && (
                <div className="text-gray-500 text-center py-8">
                  Waiting for crawl activity...
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Scanning/Attacking Tab */}
      {activeTab === 'scan' && (
        <div className="space-y-6">
          {/* Scan Progress */}
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-lg font-semibold text-gray-300">Attack Progress</h3>
              <span className="text-sm text-gray-400">
                {scanProgress.completed}/{scanProgress.totalTests} tests
              </span>
            </div>
            
            <div className="w-full bg-gray-700 rounded-full h-3">
              <div 
                className="bg-gradient-to-r from-purple-500 to-pink-500 h-3 rounded-full transition-all flex items-center justify-center"
                style={{ width: `${scanProgress.progressPercent}%` }}
              >
                {scanProgress.progressPercent > 10 && (
                  <span className="text-xs text-white font-bold">
                    {scanProgress.progressPercent.toFixed(1)}%
                  </span>
                )}
              </div>
            </div>
            
            <div className="flex items-center justify-between mt-3">
              <span className="text-sm text-gray-400">
                Vulnerabilities Found: 
                <span className="text-red-400 font-bold ml-2">
                  {scanProgress.vulnerabilitiesFound}
                </span>
              </span>
            </div>
          </div>

          {/* Current Attack */}
          {scanProgress.currentAttack && (
            <div className="bg-gray-800 rounded-lg p-4 border-l-4 border-yellow-500">
              <div className="flex items-center space-x-3 mb-2">
                <div className="animate-pulse rounded-full h-3 w-3 bg-yellow-500"></div>
                <span className="text-yellow-400 font-semibold">Currently Testing</span>
              </div>
              
              <div className="space-y-2 text-sm">
                <div className="flex">
                  <span className="text-gray-500 w-24">Type:</span>
                  <span className={`px-2 py-1 rounded text-xs font-bold text-white ${
                    getAttackTypeColor(scanProgress.currentAttack.type)
                  }`}>
                    {scanProgress.currentAttack.type}
                  </span>
                </div>
                <div className="flex">
                  <span className="text-gray-500 w-24">Parameter:</span>
                  <span className="text-orange-400 font-mono">
                    {scanProgress.currentAttack.parameter}
                  </span>
                </div>
                <div className="flex">
                  <span className="text-gray-500 w-24">URL:</span>
                  <span className="text-blue-400 font-mono text-xs truncate">
                    {scanProgress.currentAttack.url}
                  </span>
                </div>
                <div className="flex">
                  <span className="text-gray-500 w-24">Payload:</span>
                  <span className="text-red-400 font-mono text-xs bg-gray-900 p-1 rounded">
                    {scanProgress.currentAttack.payload}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Attack Log */}
          <div className="bg-gray-800 rounded-lg p-4">
            <h3 className="text-lg font-semibold mb-3 text-gray-300">Attack Log</h3>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {attackLog.map((log, index) => (
                <div key={index} className={`p-3 rounded-lg bg-gray-900 ${
                  log.status === 'VULNERABLE' ? 'border border-red-500' : ''
                }`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className={`font-bold text-sm ${getStatusColor(log.status)}`}>
                      [{log.status}]
                    </span>
                    <span className="text-gray-600 text-xs">
                      {new Date(log.timestamp * 1000).toLocaleTimeString()}
                    </span>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <span className="text-gray-500">Parameter:</span>
                      <span className="text-yellow-400 ml-2">{log.parameter}</span>
                    </div>
                    <div>
                      <span className="text-gray-500">Payload:</span>
                      <span className="text-red-400 ml-2 font-mono">
                        {log.payload ? log.payload.substring(0, 30) + '...' : 'N/A'}
                      </span>
                    </div>
                  </div>
                  
                  <div className="mt-1">
                    <span className="text-gray-500 text-xs">URL:</span>
                    <span className="text-blue-400 text-xs ml-2 font-mono">
                      {log.url ? log.url.substring(0, 60) + '...' : 'N/A'}
                    </span>
                  </div>
                  
                  {log.message && (
                    <div className="mt-2 text-xs text-gray-400">
                      {log.message}
                    </div>
                  )}
                </div>
              ))}
              
              {attackLog.length === 0 && (
                <div className="text-gray-500 text-center py-8">
                  Waiting for attack activity...
                </div>
              )}
            </div>
          </div>

          {/* Last Attacks Summary */}
          {scanProgress.lastAttacks && scanProgress.lastAttacks.length > 0 && (
            <div className="bg-gray-800 rounded-lg p-4">
              <h3 className="text-lg font-semibold mb-3 text-gray-300">Recent Attack Summary</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {scanProgress.lastAttacks.slice(-6).map((attack, index) => (
                  <div key={index} className="bg-gray-900 rounded p-3 text-xs">
                    <div className="flex items-center justify-between mb-1">
                      <span className={`font-bold ${
                        attack.status === 'VULNERABLE' ? 'text-red-400' : 'text-gray-400'
                      }`}>
                        {attack.status}
                      </span>
                      <span className="text-gray-600">
                        {new Date(attack.timestamp * 1000).toLocaleTimeString()}
                      </span>
                    </div>
                    <div className="text-gray-500">
                      {attack.parameter} @ {attack.url?.substring(0, 40)}...
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Scope Information */}
      <div className="mt-6 bg-gray-800 rounded-lg p-4 border-t-2 border-purple-500">
        <div className="flex items-center space-x-2">
          <span className="text-gray-400">🎯 Scanning Scope:</span>
          <span className="text-purple-400 font-semibold">{crawlStatus.inScope || 'Not set'}</span>
          <span className="text-gray-500 text-sm">(Staying within scope boundaries)</span>
        </div>
      </div>
    </div>
  );
};

export default CrawlingScannerDisplay;

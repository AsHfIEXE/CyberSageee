import React, { useState, useEffect } from 'react';

const SpiderProgress = ({ scanId, isActive }) => {
  const [spiderStats, setSpiderStats] = useState({
    pagesDiscovered: 0,
    ajaxCalls: 0,
    formsInteracted: 0,
    buttonsClicked: 0,
    currentPage: '',
    status: 'idle'
  });

  const backendUrl = process.env.REACT_APP_BACKEND_URL || `${window.location.protocol}//${window.location.hostname}:5000`;

  useEffect(() => {
    if (!isActive || !scanId) return;

    const fetchSpiderStats = async () => {
      try {
        const response = await fetch(`${backendUrl}/api/scan/${scanId}/statistics`);
        const data = await response.json();
        if (data.statistics) {
          setSpiderStats(prev => ({
            ...prev,
            pagesDiscovered: data.statistics.endpoints_discovered || 0,
            status: 'active'
          }));
        }
      } catch (e) {
        // Ignore errors, stats will update via WebSocket
      }
    };

    const interval = setInterval(fetchSpiderStats, 2000);
    return () => clearInterval(interval);
  }, [scanId, isActive, backendUrl]);

  if (!isActive) {
    return null;
  }

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
      <h2 className="text-xl font-bold text-white mb-4 flex items-center">
        <span className="mr-2">🤖</span>
        AJAX Spider Progress
      </h2>

      <div className="space-y-4">
        {/* Status Indicator */}
        <div className="flex items-center space-x-3">
          <div className={`w-3 h-3 rounded-full ${spiderStats.status === 'active' ? 'bg-green-500 animate-pulse' : 'bg-gray-500'}`}></div>
          <span className="text-gray-300 text-sm">
            {spiderStats.status === 'active' ? 'Crawling JavaScript-heavy applications...' : 'Waiting for AJAX spider...'}
          </span>
        </div>

        {/* Statistics Grid */}
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-gray-900 rounded p-3">
            <div className="flex items-center justify-between">
              <span className="text-gray-400 text-sm">Pages Discovered</span>
              <span className="text-white font-bold text-lg">{spiderStats.pagesDiscovered}</span>
            </div>
          </div>
          
          <div className="bg-gray-900 rounded p-3">
            <div className="flex items-center justify-between">
              <span className="text-gray-400 text-sm">AJAX Calls</span>
              <span className="text-white font-bold text-lg">{spiderStats.ajaxCalls}</span>
            </div>
          </div>
          
          <div className="bg-gray-900 rounded p-3">
            <div className="flex items-center justify-between">
              <span className="text-gray-400 text-sm">Forms Interacted</span>
              <span className="text-white font-bold text-lg">{spiderStats.formsInteracted}</span>
            </div>
          </div>
          
          <div className="bg-gray-900 rounded p-3">
            <div className="flex items-center justify-between">
              <span className="text-gray-400 text-sm">Buttons Clicked</span>
              <span className="text-white font-bold text-lg">{spiderStats.buttonsClicked}</span>
            </div>
          </div>
        </div>

        {/* Current Activity */}
        {spiderStats.currentPage && (
          <div className="bg-gray-900 rounded p-3">
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
              <span className="text-gray-400 text-sm">Currently crawling:</span>
              <span className="text-white text-sm font-mono truncate">{spiderStats.currentPage}</span>
            </div>
          </div>
        )}

        {/* Progress Bar */}
        <div className="w-full bg-gray-700 rounded-full h-2">
          <div 
            className="h-2 bg-gradient-to-r from-blue-500 to-purple-500 rounded-full transition-all duration-500"
            style={{ width: `${Math.min(100, (spiderStats.pagesDiscovered / 50) * 100)}%` }}
          ></div>
        </div>

        {/* Capabilities Info */}
        <div className="bg-blue-900/20 border border-blue-500/30 rounded p-3">
          <h4 className="text-blue-400 font-semibold text-sm mb-2">🤖 AJAX Spider Capabilities</h4>
          <div className="grid grid-cols-2 gap-2 text-xs text-gray-300">
            <div>• JavaScript Rendering</div>
            <div>• Form Interaction</div>
            <div>• Button Clicking</div>
            <div>• AJAX Monitoring</div>
            <div>• Dynamic Content</div>
            <div>• API Discovery</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SpiderProgress;


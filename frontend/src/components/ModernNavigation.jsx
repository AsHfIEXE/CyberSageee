// Modern Navigation Component
import React from 'react';

const ModernNavigation = ({ currentPage, setCurrentPage, stats, scanStatus }) => {
  const navigation = [
    { id: 'dashboard', label: 'Dashboard', icon: '📊', desc: 'Overview & Stats' },
    { id: 'scanner', label: 'Scanner', icon: '🎯', desc: 'Start New Scan' },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: '⚠️', desc: 'View Findings', badge: stats.critical + stats.high + stats.medium + stats.low },
    { id: 'repeater', label: 'Repeater', icon: '🔄', desc: 'HTTP Testing' },
    { id: 'chains', label: 'Attack Chains', icon: '⛓️', desc: 'Linked Vulns' },
    { id: 'tools', label: 'Tools', icon: '🛠️', desc: 'Pro Tools' },
  ];

  return (
    <nav className="fixed top-0 left-0 h-full w-72 bg-gradient-to-b from-gray-900 via-gray-900 to-black border-r border-purple-500/30 flex flex-col">
      {/* Logo & Title */}
      <div className="p-6 border-b border-purple-500/30">
        <div className="flex items-center space-x-3">
          <div className="w-12 h-12 bg-gradient-to-br from-purple-600 to-pink-600 rounded-xl flex items-center justify-center text-2xl shadow-lg shadow-purple-500/50">
            🛡️
          </div>
          <div>
            <h1 className="text-2xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">
              CyberSage
            </h1>
            <p className="text-xs text-gray-400">Enterprise Security Platform</p>
          </div>
        </div>
        
        {/* Scan Status Indicator */}
        {scanStatus !== 'idle' && (
          <div className={`mt-4 px-3 py-2 rounded-lg text-xs font-semibold flex items-center space-x-2 ${
            scanStatus === 'running' ? 'bg-green-500/20 text-green-400' :
            scanStatus === 'completed' ? 'bg-blue-500/20 text-blue-400' :
            'bg-red-500/20 text-red-400'
          }`}>
            <div className={`w-2 h-2 rounded-full ${
              scanStatus === 'running' ? 'bg-green-500 animate-pulse' :
              scanStatus === 'completed' ? 'bg-blue-500' :
              'bg-red-500'
            }`} />
            <span>
              {scanStatus === 'running' ? 'Scan Running' :
               scanStatus === 'completed' ? 'Scan Complete' :
               'Scan Failed'}
            </span>
          </div>
        )}
      </div>

      {/* Navigation Items */}
      <div className="flex-1 overflow-y-auto p-4 space-y-2">
        {navigation.map((item) => {
          const isActive = currentPage === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setCurrentPage(item.id)}
              className={`w-full group relative overflow-hidden rounded-xl transition-all duration-300 ${
                isActive
                  ? 'bg-gradient-to-r from-purple-600 to-pink-600 shadow-lg shadow-purple-500/50'
                  : 'bg-gray-800/50 hover:bg-gray-800 hover:shadow-md hover:shadow-purple-500/20'
              }`}
            >
              {/* Active Indicator */}
              {isActive && (
                <div className="absolute inset-0 bg-gradient-to-r from-purple-400 to-pink-400 opacity-20 animate-pulse" />
              )}
              
              <div className="relative p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <span className="text-2xl">{item.icon}</span>
                    <div className="text-left">
                      <p className="font-semibold text-white">{item.label}</p>
                      <p className="text-xs text-gray-400">{item.desc}</p>
                    </div>
                  </div>
                  {item.badge && item.badge > 0 && (
                    <span className="px-2 py-1 bg-red-500 text-white text-xs font-bold rounded-full">
                      {item.badge}
                    </span>
                  )}
                </div>
              </div>
            </button>
          );
        })}
      </div>

      {/* Footer */}
      <div className="p-4 border-t border-purple-500/30">
        <div className="flex items-center justify-between text-xs text-gray-500">
          <span>v2.0 Elite</span>
          <div className="flex items-center space-x-1">
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
            <span>Online</span>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default ModernNavigation;

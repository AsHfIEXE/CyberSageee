import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useScan } from '../context/EnhancedScanContext';
import { NAVIGATION_ITEMS } from '../utils/constants';

const Navigation = () => {
  const location = useLocation();
  const { stats, scanStatus, connected } = useScan();

  return (
    <nav className="fixed top-0 left-0 h-full w-72 bg-gradient-to-b from-gray-900 via-gray-900 to-black border-r border-purple-500/30 flex flex-col z-40">
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

        {/* Connection Status */}
        <div className={`mt-2 px-3 py-1 rounded text-xs ${
          connected ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
        }`}>
          {connected ? '🟢 Backend Connected' : '🔴 Backend Disconnected'}
        </div>
      </div>

      {/* Navigation Items */}
      <div className="flex-1 overflow-y-auto py-4">
        <div className="space-y-1 px-4">
          {NAVIGATION_ITEMS.map((item) => {
            const isActive = location.pathname === item.route;
            const totalVulnerabilities = stats.critical + stats.high + stats.medium + stats.low;
            const badge = item.id === 'vulnerabilities' ? totalVulnerabilities : undefined;

            return (
              <Link
                key={item.id}
                to={item.route}
                className={`group flex items-center px-4 py-3 text-sm font-medium rounded-lg transition-all ${
                  isActive
                    ? 'bg-purple-600 text-white shadow-lg shadow-purple-600/30'
                    : 'text-gray-300 hover:text-white hover:bg-gray-800/50'
                }`}
              >
                <span className="text-xl mr-3">{item.icon}</span>
                <div className="flex-1">
                  <div className="font-medium">{item.label}</div>
                  <div className="text-xs text-gray-400 group-hover:text-gray-300">
                    {item.desc}
                  </div>
                </div>
                {badge !== undefined && badge > 0 && (
                  <span className="ml-3 px-2 py-1 bg-red-600 text-white text-xs rounded-full font-bold">
                    {badge}
                  </span>
                )}
              </Link>
            );
          })}
        </div>
      </div>

      {/* Footer */}
      <div className="p-4 border-t border-purple-500/30">
        <div className="text-center">
          <div className="text-xs text-gray-500">
            CyberSage v{process.env.REACT_APP_VERSION || '2.0.0'}
          </div>
          <div className="text-xs text-gray-600 mt-1">
            Enterprise Security Platform
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navigation;
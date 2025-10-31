import React, { useState } from 'react';
import { useScan } from '../context/EnhancedScanContext';
import { 
  ThemeToggle, 
  StatusIndicator, 
  LoadingDots,
  Badge 
} from './ThemeComponents';

const EnhancedNavigation = ({ currentPage, setCurrentPage }) => {
  const { 
    stats, 
    scanStatus, 
    connected, 
    connectionState,
    connectionQuality,
    progress,
    currentPhase 
  } = useScan();
  
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Enhanced navigation items with icons
  const navigationItems = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2H5a2 2 0 00-2-2z" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 5a2 2 0 012-2h4a2 2 0 012 2v3H8V5z" />
        </svg>
      ),
      description: 'Overview & Analytics'
    },
    {
      id: 'scanner',
      label: 'Scanner',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM13 10H7" />
        </svg>
      ),
      description: 'Security Scanning'
    },
    {
      id: 'vulnerabilities',
      label: 'Vulnerabilities',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
      ),
      description: 'Vulnerability Analysis',
      badge: stats.critical + stats.high
    },
    {
      id: 'chains',
      label: 'Attack Chains',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
        </svg>
      ),
      description: 'Chain Detection'
    },
    {
      id: 'repeater',
      label: 'Repeater',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
      ),
      description: 'HTTP Repeater'
    },
    {
      id: 'history',
      label: 'History',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
      description: 'Scan History'
    },
    {
      id: 'blueprint',
      label: 'Blueprint',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
        </svg>
      ),
      description: 'Security Blueprint'
    },
    {
      id: 'statistics',
      label: 'Statistics',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
        </svg>
      ),
      description: 'Analytics & Reports'
    },
    {
      id: 'tools',
      label: 'Tools',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
        </svg>
      ),
      description: 'Security Tools'
    }
  ];

  const getConnectionStatus = () => {
    if (!connected) return 'offline';
    if (connectionState === 'connecting') return 'connecting';
    if (connectionQuality === 'poor') return 'warning';
    return 'online';
  };

  return (
    <>
      {/* Mobile Menu Button */}
      <button
        onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
        className="lg:hidden fixed top-4 left-4 z-50 p-2 bg-gray-800 rounded-lg text-white touch-target"
        aria-label="Toggle mobile menu"
      >
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
        </svg>
      </button>

      {/* Enhanced Navigation Sidebar */}
      <nav className="fixed top-0 left-0 h-full w-80 bg-gradient-to-b from-gray-900 via-gray-900 to-black border-r border-purple-500/30 flex flex-col z-40 lg:translate-x-0 transition-transform duration-300 lg:static lg:h-screen">
        <div className="flex-1 flex flex-col overflow-y-auto">
          {/* Logo & Header */}
          <div className="p-6 border-b border-purple-500/30 animate-fade-in-down">
            <div className="flex items-center space-x-4">
              <div className="w-14 h-14 bg-gradient-to-br from-purple-600 via-pink-600 to-purple-800 rounded-2xl flex items-center justify-center text-3xl shadow-lg shadow-purple-500/50 animate-glow">
                🛡️
              </div>
              <div className="flex-1">
                <h1 className="text-2xl font-bold text-gradient">
                  CyberSage
                </h1>
                <p className="text-sm text-gray-400 font-medium">Enterprise Security Platform</p>
              </div>
            </div>
          </div>

          {/* Status Dashboard */}
          <div className="p-6 border-b border-gray-800 animate-fade-in-left" style={{ animationDelay: '0.1s' }}>
            <div className="space-y-4">
              {/* Scan Status */}
              {scanStatus !== 'idle' && (
                <div className="p-4 rounded-xl bg-gray-800/50 border border-gray-700 animate-fade-in">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-semibold text-gray-300">Scan Status</span>
                    <Badge 
                      variant={scanStatus === 'running' ? 'primary' : scanStatus === 'completed' ? 'success' : 'error'}
                      size="sm"
                      pulse={scanStatus === 'running'}
                    >
                      {scanStatus === 'running' ? 'Scanning...' : scanStatus === 'completed' ? 'Complete' : 'Failed'}
                    </Badge>
                  </div>
                  
                  {scanStatus === 'running' && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-xs text-gray-400">
                        <span>{currentPhase}</span>
                        <span>{Math.round(progress)}%</span>
                      </div>
                      <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-gradient-to-r from-purple-500 to-pink-500 rounded-full transition-all duration-300 animate-pulse"
                          style={{ width: `${progress}%` }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Connection Status */}
              <div className="p-3 rounded-lg bg-gray-800/30 border border-gray-700">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-300">Backend Status</span>
                  <StatusIndicator 
                    status={getConnectionStatus()} 
                    size="sm"
                  />
                </div>
                
                {connected && (
                  <div className="text-xs text-gray-400">
                    Quality: {connectionQuality}
                    {connectionState === 'connecting' && (
                      <LoadingDots text="Connecting" size="sm" className="mt-1" />
                    )}
                  </div>
                )}
              </div>

              {/* Vulnerability Summary */}
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30">
                  <div className="text-xs text-red-400 font-medium">Critical</div>
                  <div className="text-lg font-bold text-red-400">{stats.critical}</div>
                </div>
                <div className="p-3 rounded-lg bg-orange-500/10 border border-orange-500/30">
                  <div className="text-xs text-orange-400 font-medium">High</div>
                  <div className="text-lg font-bold text-orange-400">{stats.high}</div>
                </div>
              </div>
            </div>
          </div>

          {/* Navigation Items */}
          <div className="flex-1 p-6 animate-fade-in" style={{ animationDelay: '0.2s' }}>
            <div className="space-y-2">
              {navigationItems.map((item, index) => (
                <button
                  key={item.id}
                  onClick={() => {
                    setCurrentPage(item.id);
                    setMobileMenuOpen(false);
                  }}
                  className={`nav-item group w-full text-left ${
                    currentPage === item.id ? 'active' : ''
                  }`}
                  style={{ animationDelay: `${0.3 + index * 0.1}s` }}
                >
                  <div className="flex items-center gap-3 flex-1">
                    <div className="p-2 rounded-lg bg-gray-800 group-hover:bg-purple-500/20 transition-colors duration-200">
                      {item.icon}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-sm">{item.label}</div>
                      <div className="text-xs text-gray-500 truncate">{item.description}</div>
                    </div>
                    {item.badge && item.badge > 0 && (
                      <Badge variant="error" size="sm">
                        {item.badge}
                      </Badge>
                    )}
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Footer with Theme Toggle */}
          <div className="p-6 border-t border-gray-800 animate-fade-in" style={{ animationDelay: '0.8s' }}>
            <div className="space-y-4">
              {/* Theme Toggle */}
              <ThemeToggle />
              
              {/* Version Info */}
              <div className="text-xs text-gray-500 text-center">
                <div className="font-medium">CyberSage v2.0</div>
                <div>Enterprise Security Platform</div>
              </div>
            </div>
          </div>
        </div>
      </nav>

      {/* Mobile Overlay */}
      {mobileMenuOpen && (
        <div 
          className="lg:hidden fixed inset-0 bg-black/50 backdrop-blur-sm z-30"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}
    </>
  );
};

export default EnhancedNavigation;

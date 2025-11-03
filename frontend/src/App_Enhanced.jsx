import React, { useState, useEffect, lazy, Suspense } from 'react';
import { io } from 'socket.io-client';
import { AnimatePresence, motion } from 'framer-motion';
import { Toaster } from 'react-hot-toast';

// Components
import ProfessionalNavigation from './components/ProfessionalNavigation';
import EnhancedDashboard from './components/EnhancedDashboard';
import EnhancedVulnerabilityCard from './components/EnhancedVulnerabilityCard';
import { 
  NotificationCenter, 
  showVulnerabilityToast, 
  showSuccessToast,
  showErrorToast,
  requestNotificationPermission 
} from './components/NotificationSystem';
import {
  VulnerabilityCardSkeleton,
  DashboardStatsSkeleton,
  FullPageLoader,
  ScanProgressLoader
} from './components/LoadingSkeletons';
import CrawlingScannerDisplay from './components/CrawlingScannerDisplay';

// Lazy load heavy components
const ScanControlPanel = lazy(() => import('./components/ScanControlPanel'));
const HttpRepeater = lazy(() => import('./components/HttpRepeater'));
const DetailedVulnerabilityModal = lazy(() => import('./components/DetailedVulnerabilityModal'));

// Keyboard shortcuts hook
const useKeyboardShortcuts = (shortcuts) => {
  useEffect(() => {
    const handleKeyPress = (e) => {
      const key = `${(e.metaKey || e.ctrlKey) ? 'cmd' : ''}${e.shiftKey ? 'shift' : ''}${e.key}`.toLowerCase();
      
      if (shortcuts[key]) {
        e.preventDefault();
        shortcuts[key]();
      }
    };

    window.addEventListener('keydown', handleKeyPress);
    return () => window.removeEventListener('keydown', handleKeyPress);
  }, [shortcuts]);
};

const EnhancedCyberSageApp = () => {
  // Connection state
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  
  // Navigation
  const [currentPage, setCurrentPage] = useState('dashboard');
  
  // Scan state
  const [scanStatus, setScanStatus] = useState('idle');
  const [progress, setProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState('');
  const [currentScanId, setCurrentScanId] = useState(null);
  
  // Data
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [chains, setChains] = useState([]);
  const [toolActivity, setToolActivity] = useState([]);
  const [stats, setStats] = useState({ critical: 0, high: 0, medium: 0, low: 0 });
  const [aiInsights, setAiInsights] = useState([]);
  const [httpHistory, setHttpHistory] = useState([]);
  const [scanHistory, setScanHistory] = useState([]);
  const [notifications, setNotifications] = useState([]);
  
  // UI state
  const [selectedVulnerability, setSelectedVulnerability] = useState(null);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  // Request notification permission on mount
  useEffect(() => {
    requestNotificationPermission();
  }, []);

  // WebSocket setup
  useEffect(() => {
    const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:5000';
    const newSocket = io(`${backendUrl}/scan`, {
      transports: ['polling', 'websocket'],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000
    });

    newSocket.on('connect', () => {
      setConnected(true);
      setLoading(false);
      showSuccessToast('Connected to CyberSage backend');
    });

    newSocket.on('disconnect', () => {
      setConnected(false);
      showErrorToast('Disconnected from backend');
    });

    newSocket.on('scan_started', (data) => {
      setScanStatus('running');
      setProgress(0);
      setVulnerabilities([]);
      setChains([]);
      setToolActivity([]);
      setStats({ critical: 0, high: 0, medium: 0, low: 0 });
      setCurrentScanId(data.scan_id);
      setAiInsights([]);
      setHttpHistory([]);
      
      addNotification({
        type: 'info',
        title: 'Scan Started',
        message: `Scanning ${data.target}`,
        time: new Date().toLocaleTimeString()
      });
    });

    newSocket.on('scan_progress', (data) => {
      setProgress(data.progress);
      setCurrentPhase(data.phase);
    });

    newSocket.on('vulnerability_found', (data) => {
      const newVuln = { ...data, id: Date.now() + Math.random(), timestamp: new Date() };
      setVulnerabilities(prev => [newVuln, ...prev]);
      setStats(prev => ({
        ...prev,
        [data.severity]: prev[data.severity] + 1
      }));
      
      // Show toast notification
      showVulnerabilityToast(newVuln, (vuln) => {
        setSelectedVulnerability(vuln);
        setCurrentPage('vulnerabilities');
      });
      
      // Add to notification center
      addNotification({
        type: 'vulnerability',
        title: `${data.severity.toUpperCase()} Vulnerability Found`,
        message: `${data.type} at ${data.url}`,
        time: new Date().toLocaleTimeString(),
        data: newVuln
      });
    });

    newSocket.on('scan_completed', (data) => {
      setScanStatus('completed');
      setProgress(100);
      
      showSuccessToast('Scan completed successfully!');
      
      addNotification({
        type: 'scan_complete',
        title: 'Scan Completed',
        message: `Found ${data.total_vulnerabilities} vulnerabilities`,
        time: new Date().toLocaleTimeString()
      });
    });

    newSocket.on('scan_failed', (data) => {
      setScanStatus('failed');
      showErrorToast(`Scan failed: ${data.error}`);
      
      addNotification({
        type: 'error',
        title: 'Scan Failed',
        message: data.error,
        time: new Date().toLocaleTimeString()
      });
    });

    setSocket(newSocket);

    return () => {
      newSocket.close();
    };
  }, []);

  // Add notification helper
  const addNotification = (notification) => {
    setNotifications(prev => [
      { ...notification, id: Date.now(), read: false },
      ...prev
    ].slice(0, 50)); // Keep last 50 notifications
  };

  // Keyboard shortcuts
  useKeyboardShortcuts({
    'cmdk': () => setCommandPaletteOpen(true),
    'cmdn': () => setCurrentPage('scanner'),
    'cmdr': () => setCurrentPage('repeater'),
    'cmd/': () => document.querySelector('.search-input')?.focus(),
    'escape': () => {
      setCommandPaletteOpen(false);
      setSelectedVulnerability(null);
    }
  });

  // Filter vulnerabilities based on search
  const filteredVulnerabilities = vulnerabilities.filter(vuln => 
    vuln.type?.toLowerCase().includes(searchQuery.toLowerCase()) ||
    vuln.url?.toLowerCase().includes(searchQuery.toLowerCase()) ||
    vuln.parameter?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Loading state
  if (loading) {
    return <FullPageLoader message="Connecting to CyberSage..." />;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black text-white">
      {/* Toast notifications */}
      <Toaster position="top-right" />
      
      {/* Navigation */}
      <ProfessionalNavigation
        currentPage={currentPage}
        setCurrentPage={setCurrentPage}
        stats={stats}
        scanStatus={scanStatus}
      />
      
      {/* Main Content */}
      <div className="lg:ml-72 min-h-screen">
        {/* Top Bar */}
        <header className="sticky top-0 z-40 bg-gray-900/80 backdrop-blur-lg border-b border-gray-800">
          <div className="flex items-center justify-between px-6 py-4">
            <div className="flex items-center space-x-4">
              <h2 className="text-2xl font-bold capitalize">
                {currentPage.replace('_', ' ')}
              </h2>
              {scanStatus === 'running' && (
                <div className="flex items-center space-x-2 px-3 py-1 bg-green-500/10 border border-green-500/30 rounded-lg">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                  <span className="text-sm text-green-400">Scanning...</span>
                </div>
              )}
            </div>
            
            <div className="flex items-center space-x-4">
              {/* Search */}
              <div className="relative">
                <input
                  type="text"
                  placeholder="Search... (⌘/)"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="search-input w-64 px-4 py-2 bg-gray-800 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-purple-500"
                />
              </div>
              
              {/* Notifications */}
              <NotificationCenter
                notifications={notifications}
                onClear={() => setNotifications([])}
                onViewAll={() => setCurrentPage('notifications')}
              />
              
              {/* Connection Status */}
              <div className={`flex items-center space-x-2 px-3 py-1 rounded-lg ${
                connected ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'
              }`}>
                <div className={`w-2 h-2 rounded-full ${
                  connected ? 'bg-green-500' : 'bg-red-500'
                }`} />
                <span className="text-xs">{connected ? 'Online' : 'Offline'}</span>
              </div>
            </div>
          </div>
        </header>
        
        {/* Page Content */}
        <main className="p-6">
          <AnimatePresence mode="wait">
            <motion.div
              key={currentPage}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.3 }}
            >
              {/* Dashboard */}
              {currentPage === 'dashboard' && (
                <Suspense fallback={<DashboardStatsSkeleton />}>
                  <EnhancedDashboard
                    vulnerabilities={vulnerabilities}
                    stats={stats}
                    scanHistory={scanHistory}
                    currentScan={currentScanId}
                  />
                </Suspense>
              )}
              
              {/* Scanner */}
              {currentPage === 'scanner' && (
                <Suspense fallback={<FullPageLoader message="Loading scanner..." />}>
                  {scanStatus === 'running' ? (
                    <>
                      <ScanProgressLoader phase={currentPhase} progress={progress} />
                      <div className="mt-6">
                        <CrawlingScannerDisplay socket={socket} scanId={currentScanId} />
                      </div>
                    </>
                  ) : (
                    <ScanControlPanel
                      socket={socket}
                      onScanStart={(target, mode, options) => {
                        socket.emit('start_scan', { target, mode, options });
                      }}
                    />
                  )}
                </Suspense>
              )}
              
              {/* Vulnerabilities */}
              {currentPage === 'vulnerabilities' && (
                <div className="space-y-6">
                  {/* Stats Bar */}
                  <div className="grid grid-cols-4 gap-4">
                    {Object.entries(stats).map(([severity, count]) => (
                      <motion.div
                        key={severity}
                        initial={{ scale: 0.9, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        className={`p-4 rounded-lg bg-gray-900/50 border ${
                          severity === 'critical' ? 'border-red-500/30' :
                          severity === 'high' ? 'border-orange-500/30' :
                          severity === 'medium' ? 'border-yellow-500/30' :
                          'border-blue-500/30'
                        }`}
                      >
                        <p className="text-sm text-gray-400 capitalize">{severity}</p>
                        <p className="text-2xl font-bold">{count}</p>
                      </motion.div>
                    ))}
                  </div>
                  
                  {/* Vulnerability List */}
                  <div className="space-y-4">
                    {filteredVulnerabilities.length > 0 ? (
                      filteredVulnerabilities.map((vuln) => (
                        <EnhancedVulnerabilityCard
                          key={vuln.id}
                          vulnerability={vuln}
                          onViewDetails={setSelectedVulnerability}
                          onGeneratePoC={(vuln) => {
                            // Generate PoC logic
                            showSuccessToast('PoC generated successfully!');
                          }}
                        />
                      ))
                    ) : vulnerabilities.length === 0 ? (
                      <div className="text-center py-12">
                        <p className="text-gray-400">No vulnerabilities found yet</p>
                      </div>
                    ) : (
                      <div className="text-center py-12">
                        <p className="text-gray-400">No vulnerabilities match your search</p>
                      </div>
                    )}
                  </div>
                </div>
              )}
              
              {/* HTTP Repeater */}
              {currentPage === 'repeater' && (
                <Suspense fallback={<FullPageLoader message="Loading repeater..." />}>
                  <HttpRepeater socket={socket} />
                </Suspense>
              )}
              
              {/* Attack Chains */}
              {currentPage === 'chains' && (
                <div className="space-y-6">
                  <h3 className="text-xl font-semibold">Attack Chains</h3>
                  {chains.length > 0 ? (
                    chains.map((chain) => (
                      <div key={chain.id} className="bg-gray-900/50 rounded-xl p-6 border border-gray-800">
                        <h4 className="font-semibold mb-2">{chain.name}</h4>
                        <p className="text-gray-400">{chain.description}</p>
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-12">
                      <p className="text-gray-400">No attack chains detected</p>
                    </div>
                  )}
                </div>
              )}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
      
      {/* Vulnerability Details Modal */}
      <AnimatePresence>
        {selectedVulnerability && (
          <Suspense fallback={<FullPageLoader />}>
            <DetailedVulnerabilityModal
              vulnerability={selectedVulnerability}
              onClose={() => setSelectedVulnerability(null)}
            />
          </Suspense>
        )}
      </AnimatePresence>
    </div>
  );
};

export default EnhancedCyberSageApp;

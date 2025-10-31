// frontend/src/components/Dashboard.jsx
import React, { useState, useEffect } from 'react';
import { useWebSocket } from '../hooks/useWebSocket';
import ScanControl from './ScanControl';
import VulnerabilityFeed from './VulnerabilityFeed';
import ChainAlerts from './ChainAlerts';
import ToolActivity from './ToolActivity';
import StatsCards from './StatsCards';
import ProgressBar from './ProgressBar';
import ScanHistory from './ScanHistory';
import BlueprintViewer from './BlueprintViewer';
import Repeater from './Repeater';
import ScannerIntegration from './ScannerIntegration';
import ScanStatistics from './ScanStatistics';
import SpiderProgress from './SpiderProgress';
import APIConfig from './APIConfig';
import AIInsights from './AIInsights';
import ImportScan from './ImportScan';
import ScanCharts from './ScanCharts';
import EnhancedVulnDetails from './EnhancedVulnDetails';
import ProfessionalFormAnalysisViewer from './ProfessionalFormAnalysisViewer';

const Dashboard = () => {
  const { socket, connected, connectionInfo, debugInfo } = useWebSocket();
  const [scanStatus, setScanStatus] = useState('idle');
  const [progress, setProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState('');
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [chains, setChains] = useState([]);
  const [toolActivity, setToolActivity] = useState([]);
  const [stats, setStats] = useState({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });
  const [currentScanId, setCurrentScanId] = useState(null);
  const [aiInsights, setAiInsights] = useState([]);
  const [selectedVulnId, setSelectedVulnId] = useState(null);

  useEffect(() => {
    if (!socket) return;

    socket.on('connected', (data) => {
      console.log('Backend ready:', data);
    });

    socket.on('scan_started', (data) => {
      console.log('Scan started:', data);
      setScanStatus('running');
      setProgress(0);
      setVulnerabilities([]);
      setChains([]);
      setToolActivity([]);
      setStats({ critical: 0, high: 0, medium: 0, low: 0 });
      setCurrentScanId(data.scan_id);
    });

    socket.on('scan_progress', (data) => {
      setProgress(data.progress);
      setCurrentPhase(data.phase);
    });

    socket.on('tool_started', (data) => {
      setToolActivity(prev => [{
        tool: data.tool,
        target: data.target,
        status: 'running',
        timestamp: data.timestamp
      }, ...prev].slice(0, 10));
    });

    socket.on('tool_completed', (data) => {
      setToolActivity(prev => 
        prev.map(item => 
          item.tool === data.tool 
            ? { ...item, status: 'completed', findings: data.findings_count }
            : item
        )
      );
    });

    socket.on('vulnerability_found', (data) => {
      // Use REAL database ID from backend (not fake temporary ID)
      const newVuln = {
        ...data
        // Don't generate fake ID - backend sends real database ID
      };
      
      setVulnerabilities(prev => [newVuln, ...prev]);
      
      setStats(prev => ({
        ...prev,
        [data.severity]: prev[data.severity] + 1
      }));
      
      showNotification(data);
    });

    socket.on('chain_detected', (data) => {
      const newChain = {
        ...data,
        id: Date.now() + Math.random()
      };

      setChains(prev => [newChain, ...prev]);
      showChainNotification(data);
    });

    socket.on('ai_insight', (data) => {
      setAiInsights(prev => [data, ...prev]);
    });

    socket.on('scan_cancelled', (data) => {
      console.log('Scan cancelled:', data);
      setScanStatus('idle');
      setProgress(0);
      alert('Scan has been cancelled');
    });

    socket.on('scan_completed', (data) => {
      console.log('Scan completed:', data);
      setScanStatus('completed');
      setProgress(100);
      showCompletionNotification(data);
    });

    socket.on('scan_error', (data) => {
      console.error('Scan error:', data);
      setScanStatus('error');
      alert(`Scan error: ${data.error}`);
    });

    return () => {
      socket.off('connected');
      socket.off('scan_started');
      socket.off('scan_progress');
      socket.off('tool_started');
      socket.off('tool_completed');
      socket.off('vulnerability_found');
      socket.off('chain_detected');
      socket.off('scan_completed');
      socket.off('scan_error');
      socket.off('ai_insight');
      socket.off('scan_cancelled');
    };
  }, [socket]);

  const showNotification = (vuln) => {
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification('🔍 Vulnerability Found', {
        body: `${vuln.severity.toUpperCase()}: ${vuln.title}`,
      });
    }
  };

  const showChainNotification = (chain) => {
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification('⚠️ Attack Chain Detected!', {
        body: chain.name,
        requireInteraction: true
      });
    }
  };

  const showCompletionNotification = (data) => {
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification('✅ Scan Complete', {
        body: `Found ${data.results_summary?.vulnerabilities_count || 0} vulnerabilities`,
      });
    }
  };

  const startScan = (target, mode, options = {}) => {
    if (socket && connected) {
      if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
      }

      setAiInsights([]);

      socket.emit('start_scan', {
        target: target,
        mode: mode,
        intensity: options.intensity || 'normal',
        auth: options.auth || {},
        policy: options.policy || {},
        spiderConfig: options.spiderConfig || {},
        tools: options.tools || {
          nmap: true,
          theHarvester: true,
          amass: true,
          whois: true,
          ffuf: true,
          gobuster: true,
          sqlmap: true,
          nikto: true,
          wpscan: true,
          nuclei: true,
          customScanner: true
        }
      });
    } else {
      alert('Not connected to backend. Please check the connection.');
    }
  };

  const cancelScan = async (scanId) => {
    if (window.confirm('Are you sure you want to cancel this scan?')) {
      try {
        const backendUrl = process.env.REACT_APP_BACKEND_URL || `${window.location.protocol}//${window.location.hostname}:5000`;
        const response = await fetch(`${backendUrl}/api/scan/${scanId}/cancel`, {
          method: 'POST'
        });
        const data = await response.json();
        if (data.status === 'success') {
          setScanStatus('idle');
          setProgress(0);
        }
      } catch (error) {
        console.error('Error cancelling scan:', error);
        alert('Failed to cancel scan');
      }
    }
  };

  const handleImportComplete = (scanId) => {
    setCurrentScanId(scanId);
    window.location.reload();
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900">
      {/* Animated Background */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-purple-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-pulse"></div>
        <div className="absolute top-1/3 right-1/4 w-96 h-96 bg-blue-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-pulse animation-delay-2000"></div>
        <div className="absolute bottom-1/4 left-1/3 w-96 h-96 bg-pink-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-pulse animation-delay-4000"></div>
      </div>

      <div className="relative z-10 container mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8 animate-fade-in">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-5xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-600 mb-2">
                CyberSage v2.0 Professional
              </h1>
              <p className="text-gray-400">Elite Vulnerability Intelligence Platform with Professional Tools</p>
            </div>
            <div className="flex items-center space-x-4">
              <div className={`flex items-center space-x-2 px-4 py-2 rounded-lg ${connected ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'}`}>
                <div className={`w-3 h-3 rounded-full ${connected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
                <span className="text-sm font-medium">{connected ? 'Connected' : 'Disconnected'}</span>
              </div>
            </div>
          </div>
        </div>

        {/* WebSocket Debug Panel */}
        <div className="mb-8 bg-gray-800/50 border border-gray-700 rounded-lg p-4">
          <h3 className="text-lg font-semibold text-gray-200 mb-3">🔧 WebSocket Debug Panel</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Connection Status */}
            <div className="bg-gray-900/50 rounded p-3">
              <h4 className="text-sm font-medium text-gray-300 mb-2">Connection Status</h4>
              <div className={`flex items-center space-x-2 mb-2 ${connected ? 'text-green-400' : 'text-red-400'}`}>
                <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`}></div>
                <span className="text-sm">{connected ? 'Connected' : 'Disconnected'}</span>
              </div>
              {connectionInfo && (
                <div className="text-xs text-gray-400 space-y-1">
                  <div>Backend URL: {connectionInfo.backendUrl}</div>
                  <div>Socket ID: {connectionInfo.id || 'None'}</div>
                  <div>Transport: {connectionInfo.transport || 'None'}</div>
                  <div>State: {connectionInfo.state || 'Unknown'}</div>
                </div>
              )}
            </div>

            {/* Debug Logs */}
            <div className="bg-gray-900/50 rounded p-3">
              <h4 className="text-sm font-medium text-gray-300 mb-2">Recent Events</h4>
              <div className="text-xs text-gray-400 space-y-1 max-h-32 overflow-y-auto">
                {debugInfo && debugInfo.length > 0 ? (
                  debugInfo.map((log, index) => (
                    <div key={index} className="flex">
                      <span className="text-gray-500 mr-2">[{log.type}]</span>
                      <span className="text-gray-300">{log.message}</span>
                    </div>
                  ))
                ) : (
                  <div className="text-gray-500">No events yet...</div>
                )}
              </div>
            </div>
          </div>

          {/* Debug Actions */}
          <div className="mt-3 pt-3 border-t border-gray-700">
            <div className="flex space-x-2">
              <button
                onClick={() => socket?.emit('ping')}
                className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded transition-colors"
              >
                Send Ping
              </button>
              <button
                onClick={() => socket?.emit('test_connection', { test: 'debug panel' })}
                className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded transition-colors"
              >
                Test Connection
              </button>
              <button
                onClick={() => {
                  console.log('Connection Info:', connectionInfo);
                  console.log('Debug Logs:', debugInfo);
                }}
                className="px-3 py-1 bg-gray-600 hover:bg-gray-700 text-white text-sm rounded transition-colors"
              >
                Log to Console
              </button>
            </div>
          </div>
        </div>
        <div className="mb-8">
          <ScanControl
            onStartScan={startScan}
            onCancelScan={cancelScan}
            scanStatus={scanStatus}
            connected={connected}
            currentScanId={currentScanId}
          />
        </div>

        {/* Progress Bar */}
        {scanStatus === 'running' && (
          <div className="mb-8 animate-slide-in">
            <ProgressBar progress={progress} phase={currentPhase} />
          </div>
        )}

        {/* Stats Cards */}
        <div className="mb-8">
          <StatsCards stats={stats} chains={chains.length} />
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Main Feed */}
          <div className="lg:col-span-2 space-y-6">
            <VulnerabilityFeed
              vulnerabilities={vulnerabilities}
              onViewDetails={(vulnId) => setSelectedVulnId(vulnId)}
            />

            {/* Chain Alerts */}
            {chains.length > 0 && (
              <ChainAlerts chains={chains} />
            )}

            {/* AI Insights */}
            {aiInsights.length > 0 && (
              <AIInsights insights={aiInsights} />
            )}

            {/* Charts */}
            {currentScanId && (
              <ScanCharts scanId={currentScanId} />
            )}

            {/* Form Analysis Viewer */}
            {currentScanId && (
              <ProfessionalFormAnalysisViewer scanId={currentScanId} />
            )}

            <ScanHistory />
          </div>

          {/* Right Column - Sidebar */}
          <div className="space-y-6">
            {/* API Configuration */}
            <APIConfig />

            {/* Import Scan */}
            <ImportScan onImportComplete={handleImportComplete} />

            {/* Tool Activity */}
            <ToolActivity activity={toolActivity} />

            {/* Blueprint Viewer */}
            <BlueprintViewer scanId={currentScanId} />

            {/* Spider Progress */}
            <SpiderProgress scanId={currentScanId} isActive={scanStatus === 'running'} />

            {/* Repeater */}
            <Repeater currentScanId={currentScanId} />

            {/* Scanner Integration */}
            <ScannerIntegration currentScanId={currentScanId} />

            {/* Scan Statistics */}
            <ScanStatistics scanId={currentScanId} />
          </div>
        </div>

        {/* Enhanced Vulnerability Details Modal */}
        {selectedVulnId && (
          <EnhancedVulnDetails
            vulnerabilityId={selectedVulnId}
            onClose={() => setSelectedVulnId(null)}
          />
        )}
      </div>
    </div>
  );
};

export default Dashboard;
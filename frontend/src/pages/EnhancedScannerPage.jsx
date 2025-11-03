// Enhanced Scanner Page with Modern Design
import React, { useState, useEffect } from 'react';
import { useScan } from '../context/EnhancedScanContext';
import { SCAN_STATUS } from '../utils/constants';
import { 
  Card, 
  Badge, 
  Button, 
  ProgressBar,
  StatusIndicator,
  PageTransition,
  LoadingSpinner,
  LoadingDots
} from '../components/ThemeComponents';
import { 
  ScannerSkeleton
} from '../components/EnhancedLoadingSkeletons';
import { 
  EnhancedModal, ConfirmationModal
} from '../components/ThemeComponents';

const EnhancedScannerPage = () => {
  const { 
    scanStatus, 
    progress, 
    currentPhase, 
    currentScanId,
    vulnerabilities,
    stats,
    connected 
  } = useScan();

  const [loading, setLoading] = useState(false);
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [showCancelModal, setShowCancelModal] = useState(false);
  const [scanConfig, setScanConfig] = useState({
    targetUrl: '',
    scanType: 'comprehensive',
    intensity: 'medium',
    includeSubdomains: true,
    includeDirectories: true,
    customHeaders: '',
    timeout: 30,
    retryAttempts: 3
  });

  // Simulate loading state
  useEffect(() => {
    if (scanStatus === SCAN_STATUS.IDLE) {
      setLoading(false);
    }
  }, [scanStatus]);

  // Scan configuration options
  const scanTypes = [
    { value: 'quick', label: 'Quick Scan', description: 'Fast scan of common vulnerabilities', duration: '5-10 min' },
    { value: 'comprehensive', label: 'Comprehensive Scan', description: 'Detailed analysis of all potential vulnerabilities', duration: '30-60 min' },
    { value: 'deep', label: 'Deep Scan', description: 'In-depth penetration testing and analysis', duration: '2-4 hours' },
    { value: 'custom', label: 'Custom Scan', description: 'Configure specific tests and parameters', duration: 'Variable' }
  ];

  const intensityLevels = [
    { value: 'low', label: 'Low', description: 'Minimal impact on target system' },
    { value: 'medium', label: 'Medium', description: 'Balanced scan speed and depth' },
    { value: 'high', label: 'High', description: 'Aggressive scanning for comprehensive coverage' },
    { value: 'stealth', label: 'Stealth', description: 'Slow and careful to avoid detection' }
  ];

  // Handle scan actions
  const handleStartScan = () => {
    setLoading(true);
    // Mock scan start
    setTimeout(() => {
      setLoading(false);
      setShowConfigModal(false);
    }, 2000);
  };

  const handleStopScan = () => {
    setShowCancelModal(true);
  };

  const handleConfirmStop = () => {
    setShowCancelModal(false);
    // Handle scan stopping logic
  };

  if (loading && scanStatus === SCAN_STATUS.IDLE) {
    return <ScannerSkeleton />;
  }

  return (
    <PageTransition>
      <div className="space-y-8">
        {/* Enhanced Header */}
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 animate-fade-in-down">
          <div>
            <h1 className="text-4xl font-bold text-gradient mb-2">
              Security Scanner
            </h1>
            <p className="text-gray-400">
              Configure and execute comprehensive security vulnerability scans
            </p>
          </div>
          
          <div className="flex items-center gap-4">
            {/* Connection Status */}
            <StatusIndicator 
              status={connected ? 'online' : 'offline'} 
              showText={true}
            />
            
            {/* Scan Status */}
            {scanStatus !== SCAN_STATUS.IDLE && (
              <Badge 
                variant={scanStatus === SCAN_STATUS.RUNNING ? 'primary' : 'success'} 
                pulse={scanStatus === SCAN_STATUS.RUNNING}
              >
                {scanStatus === SCAN_STATUS.RUNNING ? 'Scanning...' : 
                 scanStatus === SCAN_STATUS.COMPLETED ? 'Complete' : 'Stopped'}
              </Badge>
            )}
          </div>
        </div>

        {/* Active Scan Progress */}
        {scanStatus === SCAN_STATUS.RUNNING && (
          <Card className="hover-glow animate-fade-in-left">
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xl font-bold text-white mb-2">Active Scan in Progress</h3>
                  <p className="text-gray-400">Scan ID: {currentScanId || 'N/A'}</p>
                </div>
                <Button 
                  variant="danger" 
                  onClick={handleStopScan}
                  icon={
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  }
                >
                  Stop Scan
                </Button>
              </div>
              
              {/* Progress Information */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Progress</span>
                    <span className="text-white font-medium">{Math.round(progress)}%</span>
                  </div>
                  <ProgressBar 
                    value={progress} 
                    max={100}
                    size="lg"
                    animated={true}
                    color="primary"
                  />
                </div>
                
                <div className="text-center">
                  <div className="text-2xl font-bold text-purple-400">{vulnerabilities.length}</div>
                  <div className="text-sm text-gray-400">Vulnerabilities Found</div>
                </div>
                
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-400">{currentPhase}</div>
                  <div className="text-sm text-gray-400">Current Phase</div>
                </div>
              </div>
              
              {/* Scan Stats */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t border-gray-700">
                <div className="text-center">
                  <div className="text-lg font-bold text-red-400">{stats.critical}</div>
                  <div className="text-xs text-gray-400">Critical</div>
                </div>
                <div className="text-center">
                  <div className="text-lg font-bold text-orange-400">{stats.high}</div>
                  <div className="text-xs text-gray-400">High</div>
                </div>
                <div className="text-center">
                  <div className="text-lg font-bold text-yellow-400">{stats.medium}</div>
                  <div className="text-xs text-gray-400">Medium</div>
                </div>
                <div className="text-center">
                  <div className="text-lg font-bold text-blue-400">{stats.low}</div>
                  <div className="text-xs text-gray-400">Low</div>
                </div>
              </div>
            </div>
          </Card>
        )}

        {/* Main Scanner Interface */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Scanner Configuration */}
          <div className="lg:col-span-2 space-y-6">
            {/* Quick Start Card */}
            <Card className="hover-glow">
              <div className="text-center space-y-6">
                <div className="w-20 h-20 mx-auto p-5 bg-gradient-to-r from-purple-500 to-pink-500 rounded-full">
                  <svg className="w-10 h-10 text-white mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM13 10H7" />
                  </svg>
                </div>
                <div>
                  <h3 className="text-2xl font-bold text-white mb-2">Start New Security Scan</h3>
                  <p className="text-gray-400">Choose your scan type and configure parameters</p>
                </div>
                <Button 
                  variant="primary" 
                  size="lg"
                  onClick={() => setShowConfigModal(true)}
                  icon={
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                    </svg>
                  }
                >
                  Configure Scan
                </Button>
              </div>
            </Card>

            {/* Recent Scans */}
            <Card className="hover-glow">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-bold text-white">Recent Scans</h3>
                <Button variant="ghost" size="sm">
                  View All
                </Button>
              </div>
              
              <div className="space-y-3">
                {[
                  { id: '1', target: 'example.com', status: 'completed', date: '2024-06-15', vulnerabilities: 23 },
                  { id: '2', target: 'test-site.org', status: 'completed', date: '2024-06-14', vulnerabilities: 8 },
                  { id: '3', target: 'demo-app.net', status: 'failed', date: '2024-06-13', error: 'Connection timeout' }
                ].map((scan) => (
                  <div key={scan.id} className="p-4 bg-gray-800/50 rounded-lg border border-gray-700 hover:border-purple-500/50 transition-all duration-200">
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-medium text-white">{scan.target}</span>
                          <Badge 
                            variant={scan.status === 'completed' ? 'success' : 'error'} 
                            size="sm"
                          >
                            {scan.status}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-4 text-sm text-gray-400">
                          <span>{scan.date}</span>
                          {scan.vulnerabilities && (
                            <span>{scan.vulnerabilities} vulnerabilities</span>
                          )}
                          {scan.error && (
                            <span className="text-red-400">{scan.error}</span>
                          )}
                        </div>
                      </div>
                      <Button variant="ghost" size="sm">
                        View
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>

          {/* Scanner Stats & Tools */}
          <div className="space-y-6">
            {/* Scanner Capabilities */}
            <Card className="hover-glow">
              <h3 className="text-lg font-bold text-white mb-4">Scanner Capabilities</h3>
              
              <div className="space-y-4">
                {[
                  { name: 'Port Scanning', status: 'active', description: 'Detect open ports and services' },
                  { name: 'SSL/TLS Analysis', status: 'active', description: 'Certificate and protocol analysis' },
                  { name: 'Web Application Testing', status: 'active', description: 'OWASP Top 10 vulnerabilities' },
                  { name: 'Network Discovery', status: 'active', description: 'Device and service enumeration' },
                  { name: 'Directory Bruteforcing', status: 'active', description: 'Hidden file and directory discovery' },
                  { name: 'SQL Injection Testing', status: 'active', description: 'Database vulnerability assessment' }
                ].map((capability) => (
                  <div key={capability.name} className="flex items-start gap-3">
                    <div className="w-2 h-2 rounded-full bg-green-500 mt-2 flex-shrink-0" />
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-sm font-medium text-white">{capability.name}</span>
                        <Badge variant="success" size="sm">
                          {capability.status}
                        </Badge>
                      </div>
                      <p className="text-xs text-gray-400">{capability.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </Card>

            {/* Scan Statistics */}
            <Card className="hover-glow">
              <h3 className="text-lg font-bold text-white mb-4">Statistics</h3>
              
              <div className="space-y-4">
                <div className="flex justify-between">
                  <span className="text-gray-400">Total Scans</span>
                  <span className="text-white font-medium">127</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Successful Scans</span>
                  <span className="text-green-400 font-medium">119</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Failed Scans</span>
                  <span className="text-red-400 font-medium">8</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Avg Scan Time</span>
                  <span className="text-blue-400 font-medium">24 min</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Vulnerabilities Found</span>
                  <span className="text-purple-400 font-medium">1,247</span>
                </div>
              </div>
            </Card>
          </div>
        </div>

        {/* Scan Configuration Modal */}
        <EnhancedModal
          isOpen={showConfigModal}
          onClose={() => setShowConfigModal(false)}
          title="Configure Security Scan"
          size="xl"
          footer={
            <>
              <Button variant="ghost" onClick={() => setShowConfigModal(false)}>
                Cancel
              </Button>
              <Button variant="primary" onClick={handleStartScan} loading={loading}>
                Start Scan
              </Button>
            </>
          }
        >
          <div className="space-y-6">
            {/* Target Configuration */}
            <div className="space-y-4">
              <h4 className="text-lg font-semibold text-white">Target Configuration</h4>
              
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Target URL or IP Address
                </label>
                <input
                  type="text"
                  value={scanConfig.targetUrl}
                  onChange={(e) => setScanConfig({...scanConfig, targetUrl: e.target.value})}
                  placeholder="https://example.com or 192.168.1.1"
                  className="input"
                />
              </div>
            </div>

            {/* Scan Type Selection */}
            <div className="space-y-4">
              <h4 className="text-lg font-semibold text-white">Scan Type</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {scanTypes.map((type) => (
                  <div
                    key={type.value}
                    className={`p-4 border rounded-lg cursor-pointer transition-all duration-200 ${
                      scanConfig.scanType === type.value 
                        ? 'border-purple-500 bg-purple-500/10' 
                        : 'border-gray-700 hover:border-gray-600'
                    }`}
                    onClick={() => setScanConfig({...scanConfig, scanType: type.value})}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-white">{type.label}</span>
                      {scanConfig.scanType === type.value && (
                        <div className="w-4 h-4 bg-purple-500 rounded-full flex items-center justify-center">
                          <div className="w-2 h-2 bg-white rounded-full" />
                        </div>
                      )}
                    </div>
                    <p className="text-sm text-gray-400 mb-2">{type.description}</p>
                    <div className="text-xs text-gray-500">
                      Estimated duration: {type.duration}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Intensity Selection */}
            <div className="space-y-4">
              <h4 className="text-lg font-semibold text-white">Scan Intensity</h4>
              <div className="space-y-3">
                {intensityLevels.map((level) => (
                  <div
                    key={level.value}
                    className={`p-3 border rounded-lg cursor-pointer transition-all duration-200 ${
                      scanConfig.intensity === level.value 
                        ? 'border-purple-500 bg-purple-500/10' 
                        : 'border-gray-700 hover:border-gray-600'
                    }`}
                    onClick={() => setScanConfig({...scanConfig, intensity: level.value})}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`w-4 h-4 rounded-full border-2 ${
                        scanConfig.intensity === level.value 
                          ? 'border-purple-500 bg-purple-500' 
                          : 'border-gray-600'
                      }`}>
                        {scanConfig.intensity === level.value && (
                          <div className="w-full h-full bg-white rounded-full scale-50" />
                        )}
                      </div>
                      <div className="flex-1">
                        <span className="font-medium text-white">{level.label}</span>
                        <p className="text-sm text-gray-400">{level.description}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Advanced Options */}
            <div className="space-y-4">
              <h4 className="text-lg font-semibold text-white">Advanced Options</h4>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-3">
                  <label className="flex items-center gap-3">
                    <input
                      type="checkbox"
                      checked={scanConfig.includeSubdomains}
                      onChange={(e) => setScanConfig({...scanConfig, includeSubdomains: e.target.checked})}
                      className="w-4 h-4 text-purple-600 bg-gray-800 border-gray-600 rounded focus:ring-purple-500"
                    />
                    <span className="text-white">Include Subdomains</span>
                  </label>
                  
                  <label className="flex items-center gap-3">
                    <input
                      type="checkbox"
                      checked={scanConfig.includeDirectories}
                      onChange={(e) => setScanConfig({...scanConfig, includeDirectories: e.target.checked})}
                      className="w-4 h-4 text-purple-600 bg-gray-800 border-gray-600 rounded focus:ring-purple-500"
                    />
                    <span className="text-white">Directory Bruteforcing</span>
                  </label>
                </div>
                
                <div className="space-y-3">
                  <div>
                    <label className="block text-sm text-gray-300 mb-1">Timeout (seconds)</label>
                    <input
                      type="number"
                      value={scanConfig.timeout}
                      onChange={(e) => setScanConfig({...scanConfig, timeout: parseInt(e.target.value)})}
                      className="input"
                      min="10"
                      max="300"
                    />
                  </div>
                  
                  <div>
                    <label className="block text-sm text-gray-300 mb-1">Retry Attempts</label>
                    <select
                      value={scanConfig.retryAttempts}
                      onChange={(e) => setScanConfig({...scanConfig, retryAttempts: parseInt(e.target.value)})}
                      className="input"
                    >
                      <option value={1}>1</option>
                      <option value={2}>2</option>
                      <option value={3}>3</option>
                      <option value={5}>5</option>
                    </select>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </EnhancedModal>

        {/* Cancel Scan Confirmation Modal */}
        <ConfirmationModal
          isOpen={showCancelModal}
          onClose={() => setShowCancelModal(false)}
          onConfirm={handleConfirmStop}
          title="Stop Active Scan"
          message="Are you sure you want to stop the current scan? All progress will be lost and you'll need to start over."
          confirmText="Stop Scan"
          cancelText="Continue Scanning"
          variant="danger"
        />
      </div>
    </PageTransition>
  );
};

export default EnhancedScannerPage;

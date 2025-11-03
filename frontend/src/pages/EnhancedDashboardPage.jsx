// Enhanced Dashboard Page with Modern Design
import React, { useState, useEffect } from 'react';
import { useScan } from '../context/EnhancedScanContext';
import { SCAN_STATUS } from '../utils/constants';
import { 
  Card, 
  Badge, 
  ProgressBar, 
  PageTransition,
  StaggeredList,
  Button,
  StatusIndicator
} from '../components/ThemeComponents';
import { 
  DashboardSkeleton
} from '../components/EnhancedLoadingSkeletons';
import { DetailModal } from '../components/ThemeComponents';
import EnhancedStatsCard from '../components/EnhancedStatsCard';

const EnhancedDashboardPage = () => {
  const { 
    stats, 
    vulnerabilities, 
    scanStatus, 
    progress, 
    currentPhase, 
    chains, 
    aiInsights, 
    toolActivity,
    connected
  } = useScan();

  const [selectedVulnerability, setSelectedVulnerability] = useState(null);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [loading, setLoading] = useState(false);

  // Simulate loading state
  useEffect(() => {
    if (vulnerabilities.length === 0 && scanStatus === SCAN_STATUS.IDLE) {
      setLoading(true);
      const timer = setTimeout(() => setLoading(false), 1500);
      return () => clearTimeout(timer);
    }
  }, [vulnerabilities.length, scanStatus]);

  // Handle vulnerability details
  const handleVulnerabilityClick = (vulnerability) => {
    setSelectedVulnerability(vulnerability);
    setShowDetailModal(true);
  };

  // Get recent vulnerabilities
  const recentVulnerabilities = vulnerabilities.slice(0, 5);
  
  // Get active tools
  const activeTools = toolActivity.slice(0, 6);

  if (loading && vulnerabilities.length === 0) {
    return <DashboardSkeleton />;
  }

  const vulnerabilityDetailFields = [
    { label: 'Title', key: 'title' },
    { label: 'Severity', key: 'severity', type: 'badge' },
    { label: 'Description', key: 'description' },
    { label: 'CVE ID', key: 'cve_id' },
    { label: 'CVSS Score', key: 'cvss_score' },
    { label: 'Solution', key: 'solution' },
    { label: 'References', key: 'references', type: 'array' }
  ];

  return (
    <PageTransition>
      <div className="space-y-8">
        {/* Enhanced Header */}
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 animate-fade-in-down">
          <div>
            <h1 className="text-4xl font-bold text-gradient mb-2">
              Security Dashboard
            </h1>
            <p className="text-gray-400">
              Real-time security monitoring and vulnerability analysis
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
              <div className="flex items-center gap-3">
                <Badge 
                  variant={
                    scanStatus === SCAN_STATUS.RUNNING ? 'primary' : 
                    scanStatus === SCAN_STATUS.COMPLETED ? 'success' : 'error'
                  }
                  pulse={scanStatus === SCAN_STATUS.RUNNING}
                >
                  {scanStatus === SCAN_STATUS.RUNNING ? 'Scanning...' :
                   scanStatus === SCAN_STATUS.COMPLETED ? 'Complete' :
                   'Failed'}
                </Badge>
                {scanStatus === SCAN_STATUS.RUNNING && (
                  <div className="text-sm text-gray-400">
                    {Math.round(progress)}% • {currentPhase}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Scan Progress Section */}
        {scanStatus === SCAN_STATUS.RUNNING && (
          <Card className="animate-fade-in-left">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-white">Active Scan Progress</h3>
                <Badge variant="primary" pulse>
                  {currentPhase}
                </Badge>
              </div>
              
              <ProgressBar 
                value={progress} 
                max={100}
                size="lg"
                showLabel={true}
                label="Progress"
                animated={true}
              />
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
                <div className="text-center">
                  <div className="text-2xl font-bold text-purple-400">{Math.round(progress)}%</div>
                  <div className="text-sm text-gray-400">Complete</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-400">{activeTools.length}</div>
                  <div className="text-sm text-gray-400">Active Tools</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-400">{vulnerabilities.length}</div>
                  <div className="text-sm text-gray-400">Found Issues</div>
                </div>
              </div>
            </div>
          </Card>
        )}

        {/* Enhanced Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <StaggeredList>
            <EnhancedStatsCard
              title="Critical Vulnerabilities"
              value={stats.critical}
              icon={<svg className="w-8 h-8" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>}
              color="red"
              description="Immediate attention required"
              trend={-2}
              onClick={() => handleVulnerabilityClick({ severity: 'critical' })}
            />
            
            <EnhancedStatsCard
              title="High Priority"
              value={stats.high}
              icon={<svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>}
              color="orange"
              description="Significant security risk"
              trend={stats.high > 0 ? 1 : 0}
            />
            
            <EnhancedStatsCard
              title="Medium Priority"
              value={stats.medium}
              icon={<svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>}
              color="yellow"
              description="Moderate security concern"
              trend={stats.medium > 5 ? 2 : -1}
            />
            
            <EnhancedStatsCard
              title="Low Priority"
              value={stats.low}
              icon={<svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>}
              color="blue"
              description="Minor security notices"
              trend={-3}
            />
          </StaggeredList>
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Recent Vulnerabilities */}
          <Card className="hover-glow">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-bold text-white">Recent Vulnerabilities</h3>
              <Button variant="ghost" size="sm">
                View All
              </Button>
            </div>
            
            {recentVulnerabilities.length > 0 ? (
              <StaggeredList className="space-y-4">
                {recentVulnerabilities.map((vuln, index) => (
                  <div 
                    key={index}
                    className="p-4 bg-gray-800/50 rounded-xl border border-gray-700 hover:border-purple-500/50 transition-all duration-200 cursor-pointer group"
                    onClick={() => handleVulnerabilityClick(vuln)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <Badge variant={vuln.severity} size="sm">
                            {vuln.severity}
                          </Badge>
                          {vuln.cve_id && (
                            <span className="text-xs text-gray-400 font-mono">
                              {vuln.cve_id}
                            </span>
                          )}
                        </div>
                        <h4 className="font-semibold text-white group-hover:text-purple-400 transition-colors">
                          {vuln.title}
                        </h4>
                        <p className="text-sm text-gray-400 mt-1 line-clamp-2">
                          {vuln.description}
                        </p>
                      </div>
                      <div className="ml-4 text-right">
                        <div className="text-xs text-gray-500">
                          {new Date(vuln.timestamp).toLocaleTimeString()}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </StaggeredList>
            ) : (
              <div className="text-center py-12">
                <div className="w-16 h-16 mx-auto mb-4 p-4 bg-gray-800 rounded-full">
                  <svg className="w-8 h-8 text-gray-400 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <p className="text-gray-400">No vulnerabilities detected</p>
                <p className="text-sm text-gray-500 mt-1">Start a scan to analyze your targets</p>
              </div>
            )}
          </Card>

          {/* Active Tools & AI Insights */}
          <div className="space-y-8">
            {/* Active Tools */}
            <Card className="hover-glow">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-bold text-white">Active Security Tools</h3>
                <Badge variant="primary" size="sm">
                  {activeTools.length} Running
                </Badge>
              </div>
              
              {activeTools.length > 0 ? (
                <StaggeredList className="space-y-3">
                  {activeTools.map((tool, index) => (
                    <div key={index} className="flex items-center gap-3 p-3 bg-gray-800/30 rounded-lg border border-gray-700">
                      <div className="w-3 h-3 rounded-full bg-green-500 animate-pulse" />
                      <div className="flex-1">
                        <div className="font-medium text-white">{tool.tool}</div>
                        <div className="text-sm text-gray-400">{tool.target}</div>
                      </div>
                      <Badge variant={tool.status === 'running' ? 'success' : 'warning'} size="sm">
                        {tool.status}
                      </Badge>
                    </div>
                  ))}
                </StaggeredList>
              ) : (
                <div className="text-center py-8">
                  <p className="text-gray-400">No active tools</p>
                  <p className="text-sm text-gray-500">Tools will appear here when scanning begins</p>
                </div>
              )}
            </Card>

            {/* AI Insights */}
            <Card className="hover-glow">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-bold text-white">AI Security Insights</h3>
                <div className="w-8 h-8 bg-gradient-to-r from-purple-500 to-pink-500 rounded-full flex items-center justify-center">
                  <svg className="w-4 h-4 text-white" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M12 2L2 7v10c0 5.55 3.84 9.739 9 11 5.16-1.261 9-5.45 9-11V7l-10-5z" />
                  </svg>
                </div>
              </div>
              
              {aiInsights.length > 0 ? (
                <StaggeredList className="space-y-3">
                  {aiInsights.slice(0, 3).map((insight, index) => (
                    <div key={index} className="p-3 bg-gradient-to-r from-purple-500/10 to-pink-500/10 rounded-lg border border-purple-500/30">
                      <div className="flex items-start gap-3">
                        <div className="w-2 h-2 rounded-full bg-purple-400 mt-2 animate-pulse" />
                        <div className="flex-1">
                          <p className="text-sm text-white font-medium">{insight.title}</p>
                          <p className="text-xs text-gray-400 mt-1">{insight.description}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </StaggeredList>
              ) : (
                <div className="text-center py-8">
                  <div className="w-12 h-12 mx-auto mb-3 p-3 bg-gray-800 rounded-full">
                    <svg className="w-6 h-6 text-gray-400 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                    </svg>
                  </div>
                  <p className="text-gray-400">AI insights will appear here</p>
                  <p className="text-sm text-gray-500 mt-1">Based on scan results and patterns</p>
                </div>
              )}
            </Card>
          </div>
        </div>

        {/* Attack Chains Section */}
        {chains.length > 0 && (
          <Card className="hover-glow">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-bold text-white">Detected Attack Chains</h3>
              <Badge variant="error" size="sm">
                {chains.length} Active
              </Badge>
            </div>
            
            <StaggeredList className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {chains.slice(0, 4).map((chain, index) => (
                <div key={index} className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl">
                  <div className="flex items-center gap-2 mb-2">
                    <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                    <span className="text-sm font-medium text-red-400">Attack Chain {index + 1}</span>
                  </div>
                  <p className="text-sm text-gray-300">{chain.description}</p>
                  <div className="mt-2 flex items-center gap-2">
                    <Badge variant="error" size="sm">
                      {chain.steps?.length || 0} Steps
                    </Badge>
                    <Badge variant="warning" size="sm">
                      Critical
                    </Badge>
                  </div>
                </div>
              ))}
            </StaggeredList>
          </Card>
        )}
      </div>

      {/* Vulnerability Detail Modal */}
      <DetailModal
        isOpen={showDetailModal}
        onClose={() => setShowDetailModal(false)}
        title="Vulnerability Details"
        data={selectedVulnerability}
        fields={vulnerabilityDetailFields}
      />
    </PageTransition>
  );
};

export default EnhancedDashboardPage;

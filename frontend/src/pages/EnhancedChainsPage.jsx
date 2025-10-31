// Enhanced Attack Chains Page
import React, { useState, useEffect } from 'react';
import { useScan } from '../context/EnhancedScanContext';
import { 
  Card, 
  Badge, 
  Button, 
  StatusIndicator,
  PageTransition,
  StaggeredList
} from '../components/ThemeComponents';
import { 
  SectionLoading
} from '../components/EnhancedLoadingSkeletons';
import { 
  EnhancedModal, DetailModal
} from '../components/ThemeComponents';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer 
} from 'recharts';

const EnhancedChainsPage = () => {
  const { 
    chains, 
    connected 
  } = useScan();

  const [loading, setLoading] = useState(false);
  const [selectedChain, setSelectedChain] = useState(null);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState('all');

  // Mock chain data for enhanced display
  const mockChains = [
    {
      id: '1',
      name: 'SQL Injection to Data Exfiltration',
      severity: 'critical',
      steps: 5,
      description: 'Chain starting with SQL injection vulnerability leading to sensitive data extraction',
      riskScore: 95,
      mitigationComplexity: 'Medium',
      status: 'active',
      discoveredAt: '2024-06-15T10:30:00Z',
      affectedAssets: ['Web Application', 'Database Server', 'Internal Network'],
      tools: ['SQLMap', 'Metasploit', 'Nmap'],
      impact: 'High',
      likelihood: 'High',
      timeline: [
        { step: 1, tool: 'Nmap', action: 'Port scanning and service detection', duration: '5 min' },
        { step: 2, tool: 'SQLMap', action: 'SQL injection detection and exploitation', duration: '15 min' },
        { step: 3, tool: 'Database Access', action: 'Data enumeration and extraction', duration: '30 min' },
        { step: 4, tool: 'Privilege Escalation', action: 'Lateral movement through network', duration: '45 min' },
        { step: 5, tool: 'Data Exfiltration', action: 'Sensitive data extraction and storage', duration: '20 min' }
      ]
    },
    {
      id: '2', 
      name: 'XSS to Session Hijacking',
      severity: 'high',
      steps: 3,
      description: 'Cross-site scripting vulnerability exploited for session token theft',
      riskScore: 78,
      mitigationComplexity: 'Low',
      status: 'detected',
      discoveredAt: '2024-06-14T14:20:00Z',
      affectedAssets: ['Web Browser', 'Authentication Server'],
      tools: ['Burp Suite', 'Custom XSS Payload'],
      impact: 'Medium',
      likelihood: 'High',
      timeline: [
        { step: 1, tool: 'XSS Detection', action: 'Identify reflected XSS vulnerability', duration: '10 min' },
        { step: 2, tool: 'Payload Injection', action: 'Inject malicious script to steal session', duration: '5 min' },
        { step: 3, tool: 'Session Hijacking', action: 'Use stolen token for unauthorized access', duration: 'Immediate' }
      ]
    },
    {
      id: '3',
      name: 'Directory Traversal to System Access',
      severity: 'medium',
      steps: 4,
      description: 'Path traversal vulnerability leading to system file access and potential code execution',
      riskScore: 65,
      mitigationComplexity: 'Low',
      status: 'mitigated',
      discoveredAt: '2024-06-13T09:45:00Z',
      affectedAssets: ['Web Server', 'File System'],
      tools: ['Directory Bruteforcer', 'File Reader'],
      impact: 'Low',
      likelihood: 'Medium',
      timeline: [
        { step: 1, tool: 'Directory Scan', action: 'Enumerate directory structure', duration: '20 min' },
        { step: 2, tool: 'Traversal Attack', action: 'Access restricted directories', duration: '10 min' },
        { step: 3, tool: 'File Enumeration', action: 'Read configuration files', duration: '5 min' },
        { step: 4, tool: 'System Access', action: 'Attempt code execution via uploads', duration: '15 min' }
      ]
    }
  ];

  // Filter chains by severity
  const filteredChains = mockChains.filter(chain => 
    filterSeverity === 'all' || chain.severity === filterSeverity
  );

  const handleChainClick = (chain) => {
    setSelectedChain(chain);
    setShowDetailModal(true);
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return { bg: 'bg-red-500/20', border: 'border-red-500/30', text: 'text-red-400' };
      case 'high': return { bg: 'bg-orange-500/20', border: 'border-orange-500/30', text: 'text-orange-400' };
      case 'medium': return { bg: 'bg-yellow-500/20', border: 'border-yellow-500/30', text: 'text-yellow-400' };
      default: return { bg: 'bg-blue-500/20', border: 'border-blue-500/30', text: 'text-blue-400' };
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'active': return { variant: 'error', label: 'Active' };
      case 'detected': return { variant: 'warning', label: 'Detected' };
      case 'mitigated': return { variant: 'success', label: 'Mitigated' };
      default: return { variant: 'primary', label: 'Unknown' };
    }
  };

  // Risk timeline data
  const riskTimeline = [
    { date: 'Week 1', risk: 45, mitigated: 30 },
    { date: 'Week 2', risk: 52, mitigated: 40 },
    { date: 'Week 3', risk: 38, mitigated: 55 },
    { date: 'Week 4', risk: 25, mitigated: 70 },
    { date: 'Week 5', risk: 18, mitigated: 80 },
    { date: 'Week 6', risk: 12, mitigated: 85 }
  ];

  return (
    <PageTransition>
      <div className="space-y-8">
        {/* Enhanced Header */}
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 animate-fade-in-down">
          <div>
            <h1 className="text-4xl font-bold text-gradient mb-2">
              Attack Chain Analysis
            </h1>
            <p className="text-gray-400">
              Detect and analyze potential attack vectors and security chain vulnerabilities
            </p>
          </div>
          
          <div className="flex items-center gap-4">
            {/* Connection Status */}
            <StatusIndicator 
              status={connected ? 'online' : 'offline'} 
              showText={true}
            />
            
            {/* Chain Statistics */}
            <div className="flex gap-3">
              <div className="text-center">
                <div className="text-2xl font-bold text-red-400">{mockChains.filter(c => c.severity === 'critical').length}</div>
                <div className="text-xs text-gray-400">Critical</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-orange-400">{mockChains.filter(c => c.severity === 'high').length}</div>
                <div className="text-xs text-gray-400">High</div>
              </div>
            </div>
          </div>
        </div>

        {/* Risk Timeline Chart */}
        <Card className="hover-glow" padding="xl">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-xl font-bold text-white">Attack Chain Risk Trends</h3>
            <Badge variant="primary" size="sm">
              6 Weeks
            </Badge>
          </div>
          
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={riskTimeline}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="date" stroke="#9ca3af" />
                <YAxis stroke="#9ca3af" />
                <Tooltip 
                  contentStyle={{
                    background: '#1f2937',
                    border: '1px solid #374151',
                    borderRadius: '8px',
                    color: '#f9fafb'
                  }}
                />
                <Line 
                  type="monotone" 
                  dataKey="risk" 
                  stroke="#ef4444" 
                  strokeWidth={3} 
                  name="Risk Score"
                  dot={{ fill: '#ef4444', strokeWidth: 2, r: 6 }}
                />
                <Line 
                  type="monotone" 
                  dataKey="mitigated" 
                  stroke="#10b981" 
                  strokeWidth={3} 
                  name="Mitigation Rate"
                  dot={{ fill: '#10b981', strokeWidth: 2, r: 6 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Card>

        {/* Filter Controls */}
        <Card className="hover-glow">
          <div className="flex items-center gap-4">
            <span className="text-sm font-medium text-gray-300">Filter by Severity:</span>
            <div className="flex gap-2">
              {['all', 'critical', 'high', 'medium'].map((severity) => (
                <Button
                  key={severity}
                  variant={filterSeverity === severity ? 'primary' : 'ghost'}
                  size="sm"
                  onClick={() => setFilterSeverity(severity)}
                >
                  {severity === 'all' ? 'All' : severity.charAt(0).toUpperCase() + severity.slice(1)}
                </Button>
              ))}
            </div>
          </div>
        </Card>

        {/* Attack Chains List */}
        <StaggeredList className="space-y-6">
          {filteredChains.map((chain) => {
            const severityStyle = getSeverityColor(chain.severity);
            const statusConfig = getStatusColor(chain.status);
            
            return (
              <Card 
                key={chain.id}
                className="hover-glow cursor-pointer group"
                onClick={() => handleChainClick(chain)}
              >
                <div className="space-y-6">
                  {/* Chain Header */}
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-3">
                        <div className={`p-2 rounded-lg ${severityStyle.bg} ${severityStyle.border} border`}>
                          <svg className="w-6 h-6 text-current" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                          </svg>
                        </div>
                        <div>
                          <h3 className="text-xl font-bold text-white group-hover:text-purple-400 transition-colors">
                            {chain.name}
                          </h3>
                          <p className="text-sm text-gray-400 mt-1">
                            {chain.description}
                          </p>
                        </div>
                      </div>
                    </div>
                    
                    <div className="flex flex-col gap-2 items-end">
                      <Badge variant={severityStyle.text.replace('text-', '').replace('-400', '')} size="md">
                        {chain.severity.toUpperCase()}
                      </Badge>
                      <Badge variant={statusConfig.variant} size="sm">
                        {statusConfig.label}
                      </Badge>
                    </div>
                  </div>

                  {/* Chain Metrics */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="text-center p-3 bg-gray-800/50 rounded-lg">
                      <div className="text-2xl font-bold text-white">{chain.steps}</div>
                      <div className="text-xs text-gray-400">Steps</div>
                    </div>
                    <div className="text-center p-3 bg-gray-800/50 rounded-lg">
                      <div className="text-2xl font-bold text-purple-400">{chain.riskScore}</div>
                      <div className="text-xs text-gray-400">Risk Score</div>
                    </div>
                    <div className="text-center p-3 bg-gray-800/50 rounded-lg">
                      <div className="text-lg font-bold text-yellow-400">{chain.impact}</div>
                      <div className="text-xs text-gray-400">Impact</div>
                    </div>
                    <div className="text-center p-3 bg-gray-800/50 rounded-lg">
                      <div className="text-lg font-bold text-blue-400">{chain.likelihood}</div>
                      <div className="text-xs text-gray-400">Likelihood</div>
                    </div>
                  </div>

                  {/* Affected Assets & Tools */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-2 uppercase tracking-wide">
                        Affected Assets
                      </h4>
                      <div className="flex flex-wrap gap-2">
                        {chain.affectedAssets.map((asset, index) => (
                          <Badge key={index} variant="primary" size="sm">
                            {asset}
                          </Badge>
                        ))}
                      </div>
                    </div>
                    
                    <div>
                      <h4 className="text-sm font-medium text-gray-400 mb-2 uppercase tracking-wide">
                        Required Tools
                      </h4>
                      <div className="flex flex-wrap gap-2">
                        {chain.tools.map((tool, index) => (
                          <Badge key={index} variant="secondary" size="sm">
                            {tool}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Timeline Preview */}
                  <div className="space-y-2">
                    <h4 className="text-sm font-medium text-gray-400 uppercase tracking-wide">
                      Attack Timeline
                    </h4>
                    <div className="space-y-2">
                      {chain.timeline.slice(0, 3).map((step, index) => (
                        <div key={index} className="flex items-center gap-3 text-sm">
                          <div className="w-6 h-6 bg-purple-500/20 rounded-full flex items-center justify-center text-xs font-medium text-purple-400">
                            {step.step}
                          </div>
                          <div className="flex-1 text-gray-300">
                            <span className="font-medium">{step.tool}:</span> {step.action}
                          </div>
                          <div className="text-gray-500">{step.duration}</div>
                        </div>
                      ))}
                      {chain.timeline.length > 3 && (
                        <div className="text-xs text-gray-500 text-center py-2">
                          +{chain.timeline.length - 3} more steps
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </Card>
            );
          })}
        </StaggeredList>

        {/* No Chains State */}
        {filteredChains.length === 0 && (
          <Card>
            <div className="text-center py-16">
              <div className="w-20 h-20 mx-auto mb-6 p-5 bg-gray-800 rounded-full">
                <svg className="w-10 h-10 text-gray-400 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                </svg>
              </div>
              <h3 className="text-xl font-semibold text-gray-300 mb-2">No Attack Chains Detected</h3>
              <p className="text-gray-400 mb-6">
                Your security assessment has not identified any attack chain vulnerabilities.
              </p>
              <Button variant="primary">
                Run New Assessment
              </Button>
            </div>
          </Card>
        )}

        {/* Chain Detail Modal */}
        <EnhancedModal
          isOpen={showDetailModal}
          onClose={() => setShowDetailModal(false)}
          title={selectedChain?.name || 'Attack Chain Details'}
          size="xl"
          footer={
            <>
              <Button variant="ghost" onClick={() => setShowDetailModal(false)}>
                Close
              </Button>
              <Button variant="danger">
                Mitigate Chain
              </Button>
            </>
          }
        >
          {selectedChain && (
            <div className="space-y-6">
              {/* Detailed Timeline */}
              <div>
                <h4 className="text-lg font-semibold text-white mb-4">Complete Attack Timeline</h4>
                <div className="space-y-4">
                  {selectedChain.timeline.map((step, index) => (
                    <div key={index} className="flex items-start gap-4 p-4 bg-gray-800/50 rounded-lg">
                      <div className="w-8 h-8 bg-purple-500/20 rounded-full flex items-center justify-center text-sm font-medium text-purple-400">
                        {step.step}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <span className="font-medium text-white">{step.tool}</span>
                          <span className="text-gray-400">•</span>
                          <span className="text-gray-500 text-sm">{step.duration}</span>
                        </div>
                        <p className="text-gray-300">{step.action}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Risk Assessment */}
              <div className="grid grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-semibold text-white mb-3">Risk Assessment</h4>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Overall Risk Score</span>
                      <span className="text-red-400 font-bold">{selectedChain.riskScore}/100</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Impact Level</span>
                      <span className="text-yellow-400 font-medium">{selectedChain.impact}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Likelihood</span>
                      <span className="text-blue-400 font-medium">{selectedChain.likelihood}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Mitigation Complexity</span>
                      <span className="text-green-400 font-medium">{selectedChain.mitigationComplexity}</span>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold text-white mb-3">Discovery Information</h4>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Discovered</span>
                      <span className="text-white">{new Date(selectedChain.discoveredAt).toLocaleDateString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Status</span>
                      <Badge variant={getStatusColor(selectedChain.status).variant}>
                        {getStatusColor(selectedChain.status).label}
                      </Badge>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Steps Required</span>
                      <span className="text-white">{selectedChain.steps}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </EnhancedModal>
      </div>
    </PageTransition>
  );
};

export default EnhancedChainsPage;

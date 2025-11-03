import React from 'react';
import { useScan } from '../context/EnhancedScanContext';

const ToolsPage = () => {
  const { toolActivity } = useScan();

  // Enhanced tools configuration with detailed information
  const enhancedTools = [
    {
      name: 'Enhanced Vulnerability Scanner',
      desc: 'Advanced vulnerability detection with multiple databases',
      icon: '🔍',
      category: 'scanner',
      status: toolActivity.find(t => t.tool === 'Enhanced Vulnerability Scanner')?.status || 'idle',
      features: ['CVE Database Integration', 'OWASP Top 10', 'Custom Signatures', 'False Positive Reduction'],
      progress: toolActivity.find(t => t.tool === 'Enhanced Vulnerability Scanner')?.progress || 0,
      findings: toolActivity.find(t => t.tool === 'Enhanced Vulnerability Scanner')?.findings || 0,
    },
    {
      name: 'Professional Form Analyzer',
      desc: 'Deep analysis of web forms and input validation',
      icon: '📝',
      category: 'analysis',
      status: toolActivity.find(t => t.tool === 'Professional Form Analyzer')?.status || 'idle',
      features: ['Input Validation Testing', 'XSS Detection', 'CSRF Protection', 'Rate Limiting Analysis'],
      progress: toolActivity.find(t => t.tool === 'Professional Form Analyzer')?.progress || 0,
      findings: toolActivity.find(t => t.tool === 'Professional Form Analyzer')?.findings || 0,
    },
    {
      name: 'Advanced Chain Detector',
      desc: 'Sophisticated attack chain identification and correlation',
      icon: '⛓️',
      category: 'detection',
      status: toolActivity.find(t => t.tool === 'Advanced Chain Detector')?.status || 'idle',
      features: ['Vulnerability Correlation', 'Attack Path Analysis', 'Risk Assessment', 'Impact Modeling'],
      progress: toolActivity.find(t => t.tool === 'Advanced Chain Detector')?.progress || 0,
      findings: toolActivity.find(t => t.tool === 'Advanced Chain Detector')?.findings || 0,
    },
    {
      name: 'Business Logic Analyzer',
      desc: 'Analysis of business logic flaws and workflow vulnerabilities',
      icon: '🧠',
      category: 'analysis',
      status: toolActivity.find(t => t.tool === 'Business Logic Analyzer')?.status || 'idle',
      features: ['Workflow Analysis', 'Privilege Escalation', 'Race Conditions', 'Business Rule Violations'],
      progress: toolActivity.find(t => t.tool === 'Business Logic Analyzer')?.progress || 0,
      findings: toolActivity.find(t => t.tool === 'Business Logic Analyzer')?.findings || 0,
    },
    {
      name: 'API Security Scanner',
      desc: 'Comprehensive API security testing and analysis',
      icon: '🔗',
      category: 'api',
      status: toolActivity.find(t => t.tool === 'API Security Scanner')?.status || 'idle',
      features: ['REST API Testing', 'GraphQL Analysis', 'Authentication Bypass', 'Rate Limiting'],
      progress: toolActivity.find(t => t.tool === 'API Security Scanner')?.progress || 0,
      findings: toolActivity.find(t => t.tool === 'API Security Scanner')?.findings || 0,
    },
    {
      name: 'AI-Powered Analyzer',
      desc: 'Machine learning enhanced vulnerability detection',
      icon: '🤖',
      category: 'ai',
      status: toolActivity.find(t => t.tool === 'AI-Powered Analyzer')?.status || 'idle',
      features: ['Pattern Recognition', 'Anomaly Detection', 'Behavioral Analysis', 'Adaptive Scanning'],
      progress: toolActivity.find(t => t.tool === 'AI-Powered Analyzer')?.progress || 0,
      findings: toolActivity.find(t => t.tool === 'AI-Powered Analyzer')?.findings || 0,
    },
    {
      name: 'Professional Directory Brute Force',
      desc: 'Advanced directory and file discovery with multiple wordlists',
      icon: '🗂️',
      category: 'discovery',
      status: toolActivity.find(t => t.tool === 'Professional Directory Brute Force')?.status || 'idle',
      features: ['Multiple Wordlists', 'Custom Dictionaries', 'Recursive Discovery', 'Status Code Analysis'],
      progress: toolActivity.find(t => t.tool === 'Professional Directory Brute Force')?.progress || 0,
      findings: toolActivity.find(t => t.tool === 'Professional Directory Brute Force')?.findings || 0,
    },
    {
      name: 'Advanced Nmap Integration',
      desc: 'Professional network scanning and service enumeration',
      icon: '🌐',
      category: 'network',
      status: toolActivity.find(t => t.tool === 'Advanced Nmap Integration')?.status || 'idle',
      features: ['Port Scanning', 'Service Detection', 'OS Fingerprinting', 'Vulnerability Detection'],
      progress: toolActivity.find(t => t.tool === 'Advanced Nmap Integration')?.progress || 0,
      findings: toolActivity.find(t => t.tool === 'Advanced Nmap Integration')?.findings || 0,
    },
  ];

  const toolsByCategory = enhancedTools.reduce((acc, tool) => {
    if (!acc[tool.category]) {
      acc[tool.category] = [];
    }
    acc[tool.category].push(tool);
    return acc;
  }, {});

  const categories = [
    { id: 'scanner', name: 'Scanners', icon: '🔍', color: 'purple' },
    { id: 'analysis', name: 'Analyzers', icon: '📊', color: 'blue' },
    { id: 'detection', name: 'Detectors', icon: '🎯', color: 'green' },
    { id: 'api', name: 'API Tools', icon: '🔗', color: 'orange' },
    { id: 'ai', name: 'AI Tools', icon: '🤖', color: 'pink' },
    { id: 'discovery', name: 'Discovery', icon: '🗺️', color: 'cyan' },
    { id: 'network', name: 'Network', icon: '🌐', color: 'red' },
  ];

  const getStatusIcon = (status) => {
    switch (status) {
      case 'running': return '▶️';
      case 'completed': return '✅';
      case 'failed': return '❌';
      default: return '⏸️';
    }
  };

  const activeTools = enhancedTools.filter(tool => tool.status === 'running').length;
  const completedTools = enhancedTools.filter(tool => tool.status === 'completed').length;
  const totalFindings = toolActivity.reduce((sum, tool) => sum + (tool.findings || 0), 0);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold">Professional Tools</h2>
        <div className="flex items-center space-x-4 text-sm">
          <span className="text-gray-400">Active Tools:</span>
          <span className="px-2 py-1 bg-green-600 rounded text-white font-bold">{activeTools}</span>
        </div>
      </div>

      {/* Tool Statistics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 text-center">
          <div className="text-2xl font-bold text-white">{enhancedTools.length}</div>
          <div className="text-sm text-gray-400">Available Tools</div>
        </div>
        <div className="bg-green-900/20 rounded-lg border border-green-500/50 p-4 text-center">
          <div className="text-2xl font-bold text-green-400">{activeTools}</div>
          <div className="text-sm text-gray-400">Running</div>
        </div>
        <div className="bg-blue-900/20 rounded-lg border border-blue-500/50 p-4 text-center">
          <div className="text-2xl font-bold text-blue-400">{completedTools}</div>
          <div className="text-sm text-gray-400">Completed</div>
        </div>
        <div className="bg-purple-900/20 rounded-lg border border-purple-500/50 p-4 text-center">
          <div className="text-2xl font-bold text-purple-400">{totalFindings}</div>
          <div className="text-sm text-gray-400">Total Findings</div>
        </div>
      </div>

      {/* Tools by Category */}
      {Object.entries(toolsByCategory).map(([categoryId, tools]) => {
        const category = categories.find(c => c.id === categoryId);
        return (
          <div key={categoryId} className="bg-gray-900 rounded-xl border border-gray-800 p-6">
            <div className="flex items-center space-x-3 mb-6">
              <span className="text-3xl">{category?.icon}</span>
              <div>
                <h3 className="text-xl font-bold">{category?.name}</h3>
                <p className="text-sm text-gray-400">{tools.length} tools in this category</p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {tools.map((tool, index) => {
                const activity = toolActivity.find(t => t.tool === tool.name);
                return (
                  <div 
                    key={index}
                    className={`p-6 rounded-xl border-2 transition-all hover:border-purple-500/50 ${
                      tool.status === 'running' ? 'border-green-500/50 bg-green-900/10' :
                      tool.status === 'completed' ? 'border-blue-500/50 bg-blue-900/10' :
                      tool.status === 'failed' ? 'border-red-500/50 bg-red-900/10' :
                      'border-gray-700 bg-gray-800/30'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-4">
                      <span className="text-4xl">{tool.icon}</span>
                      <div className="flex items-center space-x-2">
                        <span className="text-lg">{getStatusIcon(tool.status)}</span>
                        <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                          tool.status === 'running' ? 'bg-green-600 text-white' :
                          tool.status === 'completed' ? 'bg-blue-600 text-white' :
                          tool.status === 'failed' ? 'bg-red-600 text-white' :
                          'bg-gray-600 text-white'
                        }`}>
                          {tool.status.toUpperCase()}
                        </span>
                      </div>
                    </div>
                    
                    <h4 className="font-bold text-lg mb-2">{tool.name}</h4>
                    <p className="text-sm text-gray-400 mb-4">{tool.desc}</p>

                    {/* Features */}
                    <div className="space-y-2 mb-4">
                      <div className="text-xs font-medium text-gray-500">FEATURES</div>
                      <div className="space-y-1">
                        {tool.features.slice(0, 3).map((feature, featureIndex) => (
                          <div key={featureIndex} className="flex items-center space-x-2 text-sm">
                            <div className="w-1.5 h-1.5 bg-purple-400 rounded-full"></div>
                            <span className="text-gray-300">{feature}</span>
                          </div>
                        ))}
                        {tool.features.length > 3 && (
                          <div className="text-xs text-gray-500">+{tool.features.length - 3} more features</div>
                        )}
                      </div>
                    </div>

                    {/* Progress Bar */}
                    {tool.status === 'running' && tool.progress > 0 && (
                      <div className="mb-4">
                        <div className="flex justify-between text-sm mb-1">
                          <span className="text-gray-400">Progress</span>
                          <span className="text-gray-400">{Math.round(tool.progress)}%</span>
                        </div>
                        <div className="w-full bg-gray-700 rounded-full h-2">
                          <div 
                            className="bg-green-500 h-2 rounded-full transition-all duration-300"
                            style={{ width: `${tool.progress}%` }}
                          ></div>
                        </div>
                      </div>
                    )}

                    {/* Findings Counter */}
                    {(tool.findings > 0 || activity?.findings > 0) && (
                      <div className="flex items-center justify-between p-3 bg-purple-900/20 rounded-lg">
                        <div className="text-sm">
                          <div className="text-gray-400">Findings</div>
                          <div className="text-lg font-bold text-purple-400">
                            {tool.findings || activity?.findings || 0}
                          </div>
                        </div>
                        <div className="text-2xl">🔍</div>
                      </div>
                    )}

                    {/* Target Information */}
                    {activity?.target && (
                      <div className="mt-3 text-xs text-gray-500">
                        Target: {activity.target}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}

      {/* Recent Activity */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
        <h3 className="text-xl font-bold mb-4">Recent Tool Activity</h3>
        <div className="space-y-3">
          {toolActivity.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              <div className="text-4xl mb-4">🛠️</div>
              <p>No tool activity yet</p>
              <p className="text-sm">Start a scan to see tool activity here</p>
            </div>
          ) : (
            toolActivity.slice(0, 10).map((activity, index) => (
              <div key={index} className="flex items-center p-4 bg-gray-800/50 rounded-lg">
                <div className={`w-3 h-3 rounded-full mr-4 ${
                  activity.status === 'running' ? 'bg-green-500 animate-pulse' : 
                  activity.status === 'completed' ? 'bg-blue-500' : 'bg-red-500'
                }`} />
                <div className="flex-1">
                  <div className="font-medium">{activity.tool}</div>
                  <div className="text-sm text-gray-400">{activity.target}</div>
                </div>
                <div className="text-right">
                  <span className={`px-2 py-1 rounded text-xs font-bold ${
                    activity.status === 'running' ? 'bg-green-600 text-white' :
                    activity.status === 'completed' ? 'bg-blue-600 text-white' :
                    'bg-red-600 text-white'
                  }`}>
                    {activity.status}
                  </span>
                  {activity.findings !== undefined && (
                    <div className="text-xs text-gray-400 mt-1">
                      {activity.findings} findings
                    </div>
                  )}
                </div>
                <div className="text-xs text-gray-500 ml-4">
                  {new Date(activity.timestamp).toLocaleTimeString()}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

export default ToolsPage;
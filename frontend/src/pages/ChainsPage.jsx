import React, { useState } from 'react';
import { useScan } from '../context/EnhancedScanContext';

const ChainsPage = () => {
  const { chains } = useScan();
  const [selectedChain, setSelectedChain] = useState(null);

  const getRiskLevelIcon = (riskLevel) => {
    switch (riskLevel?.toLowerCase()) {
      case 'critical': return '🔴';
      case 'high': return '🟠';
      case 'medium': return '🟡';
      case 'low': return '🟢';
      default: return '⚪';
    }
  };

  const chainCategories = [
    { id: 'injection', name: 'Injection Attacks', icon: '💉', color: 'red' },
    { id: 'broken_auth', name: 'Broken Authentication', icon: '🔓', color: 'orange' },
    { id: 'sensitive_data', name: 'Sensitive Data Exposure', icon: '📋', color: 'yellow' },
    { id: 'xxe', name: 'XML External Entities', icon: '📄', color: 'blue' },
    { id: 'broken_access', name: 'Broken Access Control', icon: '🚫', color: 'purple' },
    { id: 'security_config', name: 'Security Misconfiguration', icon: '⚙️', color: 'gray' },
    { id: 'xss', name: 'Cross-Site Scripting', icon: '⚡', color: 'green' },
    { id: 'insecure_deserialization', name: 'Insecure Deserialization', icon: '📦', color: 'pink' },
  ];

  const getChainCategory = (chain) => {
    const title = (chain.title || '').toLowerCase();
    const desc = (chain.description || '').toLowerCase();
    
    for (const category of chainCategories) {
      if (title.includes(category.id) || desc.includes(category.id) || 
          title.includes(category.name.toLowerCase().split(' ')[0])) {
        return category;
      }
    }
    
    return { id: 'other', name: 'Other', icon: '🔗', color: 'gray' };
  };

  const groupedChains = chains.reduce((groups, chain) => {
    const category = getChainCategory(chain);
    if (!groups[category.id]) {
      groups[category.id] = {
        category,
        chains: []
      };
    }
    groups[category.id].chains.push(chain);
    return groups;
  }, {});

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold">Attack Chains</h2>
        <div className="text-sm text-gray-400">
          {chains.length} chains detected
        </div>
      </div>

      {chains.length === 0 ? (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-12 text-center">
          <div className="text-4xl mb-4">⛓️</div>
          <h3 className="text-xl font-semibold mb-2">No Attack Chains Detected</h3>
          <p className="text-gray-400">
            Attack chains will appear here when multiple vulnerabilities are linked together
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Attack Chain Statistics */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 text-center">
              <div className="text-2xl font-bold text-white">{chains.length}</div>
              <div className="text-sm text-gray-400">Total Chains</div>
            </div>
            <div className="bg-red-900/20 rounded-lg border border-red-500/50 p-4 text-center">
              <div className="text-2xl font-bold text-red-400">
                {chains.filter(chain => chain.risk_level === 'critical').length}
              </div>
              <div className="text-sm text-gray-400">Critical Risk</div>
            </div>
            <div className="bg-orange-900/20 rounded-lg border border-orange-500/50 p-4 text-center">
              <div className="text-2xl font-bold text-orange-400">
                {chains.filter(chain => chain.risk_level === 'high').length}
              </div>
              <div className="text-sm text-gray-400">High Risk</div>
            </div>
            <div className="bg-yellow-900/20 rounded-lg border border-yellow-500/50 p-4 text-center">
              <div className="text-2xl font-bold text-yellow-400">
                {chains.filter(chain => chain.steps && chain.steps.length).reduce((acc, chain) => acc + chain.steps.length, 0)}
              </div>
              <div className="text-sm text-gray-400">Total Steps</div>
            </div>
          </div>

          {/* Attack Chains by Category */}
          {Object.values(groupedChains).map(({ category, chains: categoryChains }) => (
            <div key={category.id} className="bg-gray-900 rounded-xl border border-gray-800 p-6">
              <div className="flex items-center space-x-3 mb-4">
                <span className="text-2xl">{category.icon}</span>
                <h3 className="text-xl font-bold">{category.name}</h3>
                <span className="px-2 py-1 bg-gray-700 rounded text-sm">
                  {categoryChains.length} chains
                </span>
              </div>

              <div className="space-y-4">
                {categoryChains.map((chain, index) => (
                  <div
                    key={index}
                    className={`p-4 rounded-lg border-l-4 cursor-pointer transition-all hover:bg-gray-800/50 ${
                      chain.risk_level === 'critical' ? 'border-red-500 bg-red-900/10' :
                      chain.risk_level === 'high' ? 'border-orange-500 bg-orange-900/10' :
                      chain.risk_level === 'medium' ? 'border-yellow-500 bg-yellow-900/10' :
                      'border-blue-500 bg-blue-900/10'
                    }`}
                    onClick={() => setSelectedChain(chain)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-2">
                          <span className="text-lg">{getRiskLevelIcon(chain.risk_level)}</span>
                          <h4 className="text-lg font-semibold">
                            Chain {categoryChains.indexOf(chain) + 1}
                          </h4>
                          {chain.risk_level && (
                            <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                              chain.risk_level === 'critical' ? 'bg-red-600 text-white' :
                              chain.risk_level === 'high' ? 'bg-orange-600 text-white' :
                              chain.risk_level === 'medium' ? 'bg-yellow-600 text-black' :
                              'bg-blue-600 text-white'
                            }`}>
                              {chain.risk_level.toUpperCase()} RISK
                            </span>
                          )}
                        </div>

                        <p className="text-gray-300 mb-3">{chain.description}</p>

                        {/* Chain Steps */}
                        {chain.steps && chain.steps.length > 0 && (
                          <div className="space-y-2">
                            <div className="text-sm font-medium text-gray-400">Attack Steps:</div>
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                              {chain.steps.slice(0, 6).map((step, stepIndex) => (
                                <div
                                  key={stepIndex}
                                  className="p-2 bg-gray-800 rounded text-sm flex items-center space-x-2"
                                >
                                  <div className="w-6 h-6 bg-purple-600 rounded-full flex items-center justify-center text-xs font-bold">
                                    {stepIndex + 1}
                                  </div>
                                  <span className="text-gray-300">{step}</span>
                                </div>
                              ))}
                              {chain.steps.length > 6 && (
                                <div className="p-2 bg-gray-800 rounded text-sm text-gray-400 flex items-center">
                                  +{chain.steps.length - 6} more steps
                                </div>
                              )}
                            </div>
                          </div>
                        )}

                        {/* Vulnerability Count */}
                        {chain.vulnerabilities && chain.vulnerabilities.length > 0 && (
                          <div className="mt-3 flex items-center space-x-4 text-sm text-gray-400">
                            <div className="flex items-center space-x-1">
                              <span>🔗</span>
                              <span>{chain.vulnerabilities.length} vulnerabilities linked</span>
                            </div>
                          </div>
                        )}

                        {/* Confidence and Impact */}
                        <div className="mt-3 flex items-center space-x-4 text-sm">
                          {chain.confidence && (
                            <div className="flex items-center space-x-1">
                              <span>🎯</span>
                              <span>Confidence: {Math.round(chain.confidence * 100)}%</span>
                            </div>
                          )}
                          {chain.impact && (
                            <div className="flex items-center space-x-1">
                              <span>📊</span>
                              <span>Impact: {chain.impact}</span>
                            </div>
                          )}
                        </div>
                      </div>

                      <div className="ml-4">
                        <button
                          className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg text-sm transition-colors"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedChain(chain);
                          }}
                        >
                          View Details
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Detailed Chain Modal */}
      {selectedChain && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 rounded-xl border border-gray-800 max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-2xl font-bold">Attack Chain Details</h3>
                <button
                  onClick={() => setSelectedChain(null)}
                  className="text-gray-400 hover:text-white text-2xl"
                >
                  ×
                </button>
              </div>

              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <h4 className="font-semibold mb-2">Risk Level</h4>
                    <span className={`px-3 py-1 rounded-full text-sm font-bold ${
                      selectedChain.risk_level === 'critical' ? 'bg-red-600 text-white' :
                      selectedChain.risk_level === 'high' ? 'bg-orange-600 text-white' :
                      selectedChain.risk_level === 'medium' ? 'bg-yellow-600 text-black' :
                      'bg-blue-600 text-white'
                    }`}>
                      {getRiskLevelIcon(selectedChain.risk_level)} {selectedChain.risk_level?.toUpperCase()}
                    </span>
                  </div>
                  
                  {selectedChain.confidence && (
                    <div>
                      <h4 className="font-semibold mb-2">Confidence</h4>
                      <div className="text-lg">{Math.round(selectedChain.confidence * 100)}%</div>
                    </div>
                  )}
                </div>

                <div>
                  <h4 className="font-semibold mb-2">Description</h4>
                  <p className="text-gray-300">{selectedChain.description}</p>
                </div>

                {selectedChain.steps && selectedChain.steps.length > 0 && (
                  <div>
                    <h4 className="font-semibold mb-2">Attack Steps</h4>
                    <div className="space-y-2">
                      {selectedChain.steps.map((step, index) => (
                        <div key={index} className="flex items-start space-x-3 p-3 bg-gray-800 rounded">
                          <div className="w-8 h-8 bg-purple-600 rounded-full flex items-center justify-center text-sm font-bold mt-0.5">
                            {index + 1}
                          </div>
                          <div className="flex-1">
                            <p className="text-gray-300">{step}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {selectedChain.vulnerabilities && selectedChain.vulnerabilities.length > 0 && (
                  <div>
                    <h4 className="font-semibold mb-2">Linked Vulnerabilities</h4>
                    <div className="space-y-2">
                      {selectedChain.vulnerabilities.map((vuln, index) => (
                        <div key={index} className="p-3 bg-gray-800 rounded">
                          <div className="font-medium">{vuln.title}</div>
                          <div className="text-sm text-gray-400">{vuln.severity} • {vuln.category}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {selectedChain.mitigation && (
                  <div>
                    <h4 className="font-semibold mb-2">Mitigation Strategies</h4>
                    <p className="text-gray-300">{selectedChain.mitigation}</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ChainsPage;
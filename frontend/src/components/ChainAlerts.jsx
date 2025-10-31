import React from 'react';

const ChainAlerts = ({ chains }) => {
  return (
    <div className="bg-gradient-to-br from-red-900/50 to-pink-900/50 rounded-lg border-2 border-red-500 p-6 animate-pulse-glow">
      <h2 className="text-xl font-bold text-white mb-4 flex items-center">
        <span className="mr-2">⚠️</span>
        Attack Chains Detected
      </h2>
      <div className="space-y-3">
        {chains.map((chain, index) => (
          <div key={chain.id || index} className="bg-black/30 rounded-lg p-4">
            <div className="flex items-start justify-between mb-2">
              <h3 className="text-white font-bold text-lg">{chain.name}</h3>
              <span className="px-2 py-1 bg-red-600 text-white text-xs rounded-full font-bold">
                CRITICAL
              </span>
            </div>
            <p className="text-red-300 text-sm mb-3">{chain.impact}</p>
            <div className="space-y-2">
              <p className="text-xs text-gray-400 font-semibold">Exploitation Steps:</p>
              {chain.steps && chain.steps.map((step, si) => (
                <div key={si} className="flex items-start text-xs text-gray-300">
                  <span className="mr-2 text-red-400">→</span>
                  <span>{step[1]}</span>
                </div>
              ))}
            </div>
            <div className="mt-3 pt-3 border-t border-red-800/50">
              <span className="text-xs text-gray-400">
                Confidence: {chain.confidence}%
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ChainAlerts;
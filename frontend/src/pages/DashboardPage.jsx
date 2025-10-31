import React from 'react';
import { useScan } from '../context/EnhancedScanContext';
import { SCAN_STATUS } from '../utils/constants';
import StatsCard from '../components/StatsCard';
import ScanControlPanel from '../components/ScanControlPanel';

const DashboardPage = () => {
  const { 
    stats, 
    vulnerabilities, 
    scanStatus, 
    progress, 
    currentPhase, 
    chains, 
    currentScanId, 
    aiInsights, 
    toolActivity, 
    actions 
  } = useScan();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold">Security Dashboard</h2>
        {scanStatus !== SCAN_STATUS.IDLE && (
          <div className="flex items-center space-x-3">
            <div className={`px-4 py-2 rounded-lg font-semibold ${
              scanStatus === SCAN_STATUS.RUNNING ? 'bg-green-500/20 text-green-400' :
              scanStatus === SCAN_STATUS.COMPLETED ? 'bg-blue-500/20 text-blue-400' :
              'bg-red-500/20 text-red-400'
            }`}>
              {scanStatus === SCAN_STATUS.RUNNING ? '🔄 Scanning...' :
               scanStatus === SCAN_STATUS.COMPLETED ? '✅ Scan Complete' :
               '⚠️ Scan Failed'}
            </div>
            {scanStatus === SCAN_STATUS.RUNNING && (
              <div className="text-gray-400 text-sm">
                {Math.round(progress)}% • {currentPhase}
              </div>
            )}
          </div>
        )}
      </div>
      
      {/* Scan Control Panel */}
      {scanStatus === SCAN_STATUS.RUNNING && (
        <ScanControlPanel
          scanId={currentScanId}
          scanStatus={scanStatus}
          progress={progress}
          currentPhase={currentPhase}
          actions={actions}
        />
      )}

      {/* Beautiful Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatsCard 
          title="Critical Vulnerabilities"
          value={stats.critical}
          icon="🔴"
          color="red"
          subtitle="Immediate attention required"
        />
        <StatsCard 
          title="High Severity"
          value={stats.high}
          icon="🟠"
          color="orange"
          subtitle="Fix within 24-48 hours"
        />
        <StatsCard 
          title="Medium Risk"
          value={stats.medium}
          icon="🟡"
          color="yellow"
          subtitle="Address soon"
        />
        <StatsCard 
          title="Low Priority"
          value={stats.low}
          icon="🟢"
          color="blue"
          subtitle="Minor issues"
        />
      </div>

      {/* Detailed Scan Summary */}
      {(vulnerabilities.length > 0 || toolActivity.length > 0) && (
        <div className="bg-gradient-to-br from-purple-900/30 to-blue-900/30 rounded-xl border-2 border-purple-500/50 p-6">
          <h3 className="text-xl font-bold mb-4 flex items-center">
            <span className="mr-2">📊</span>
            Scan Summary
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-black/30 rounded-lg p-4">
              <div className="text-gray-400 text-sm">Total Vulnerabilities</div>
              <div className="text-3xl font-bold text-purple-400">{vulnerabilities.length}</div>
            </div>
            <div className="bg-black/30 rounded-lg p-4">
              <div className="text-gray-400 text-sm">Tools Executed</div>
              <div className="text-3xl font-bold text-blue-400">{toolActivity.length}</div>
            </div>
            <div className="bg-black/30 rounded-lg p-4">
              <div className="text-gray-400 text-sm">Critical + High</div>
              <div className="text-3xl font-bold text-red-400">{stats.critical + stats.high}</div>
            </div>
            <div className="bg-black/30 rounded-lg p-4">
              <div className="text-gray-400 text-sm">Scan Progress</div>
              <div className="text-3xl font-bold text-green-400">{Math.round(progress)}%</div>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Enhanced Vulnerabilities List */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold">Detected Vulnerabilities</h3>
            <span className="text-sm text-gray-400">
              {vulnerabilities.length} total
            </span>
          </div>
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {vulnerabilities.length === 0 ? (
              <div className="text-center py-8 text-gray-500">
                No vulnerabilities detected yet
              </div>
            ) : (
              vulnerabilities.slice(0, 10).map((vulnerability, i) => (
                <div 
                  key={i}
                  className={`p-4 rounded-lg border-l-4 bg-gray-800/50 ${
                    vulnerability.severity === 'critical' ? 'border-red-500' :
                    vulnerability.severity === 'high' ? 'border-orange-500' :
                    vulnerability.severity === 'medium' ? 'border-yellow-500' :
                    'border-blue-500'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <h4 className="font-semibold text-sm">{vulnerability.title}</h4>
                      <p className="text-xs text-gray-400 mt-1">{vulnerability.description}</p>
                      {vulnerability.url && (
                        <p className="text-xs text-blue-400 mt-1">{vulnerability.url}</p>
                      )}
                    </div>
                    <span className={`px-2 py-1 rounded text-xs font-bold ${
                      vulnerability.severity === 'critical' ? 'bg-red-600' :
                      vulnerability.severity === 'high' ? 'bg-orange-600' :
                      vulnerability.severity === 'medium' ? 'bg-yellow-600' :
                      'bg-blue-600'
                    }`}>
                      {vulnerability.severity.toUpperCase()}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Tool Activity */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold">Tool Activity</h3>
            <span className="text-sm text-gray-400">
              {toolActivity.length} tools
            </span>
          </div>
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {toolActivity.length === 0 ? (
              <div className="text-center py-8 text-gray-500">
                No tool activity yet
              </div>
            ) : (
              toolActivity.map((item, i) => (
                <div key={i} className="flex items-center p-3 bg-gray-800/50 rounded-lg">
                  <div className={`w-2 h-2 rounded-full mr-3 ${
                    item.status === 'running' ? 'bg-green-500 animate-pulse' : 
                    item.status === 'completed' ? 'bg-blue-500' : 'bg-red-500'
                  }`} />
                  <div className="flex-1">
                    <div className="font-medium text-sm">{item.tool}</div>
                    <div className="text-xs text-gray-400">{item.target}</div>
                  </div>
                  {item.findings !== undefined && (
                    <span className="text-xs bg-purple-600 px-2 py-1 rounded">
                      {item.findings} found
                    </span>
                  )}
                  <span className={`px-2 py-1 rounded text-xs font-bold ml-2 ${
                    item.status === 'running' ? 'bg-green-600' :
                    item.status === 'completed' ? 'bg-blue-600' :
                    'bg-red-600'
                  }`}>
                    {item.status}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Attack Chains */}
      {chains.length > 0 && (
        <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold">Detected Attack Chains</h3>
            <span className="text-sm text-gray-400">
              {chains.length} chains
            </span>
          </div>
          <div className="space-y-3">
            {chains.slice(0, 5).map((chain, i) => (
              <div key={i} className="p-4 bg-red-900/20 border border-red-500/50 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-semibold text-red-400">Chain {i + 1}</h4>
                  <span className="text-xs bg-red-600 px-2 py-1 rounded">
                    Risk: {chain.risk_level || 'High'}
                  </span>
                </div>
                <p className="text-sm text-gray-300">{chain.description}</p>
                {chain.steps && (
                  <div className="mt-2 text-xs text-gray-400">
                    Steps: {chain.steps.length}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* AI Insights */}
      {aiInsights.length > 0 && (
        <div className="bg-gradient-to-br from-purple-900/30 to-pink-900/30 rounded-xl border-2 border-purple-500/50 p-6">
          <h3 className="text-xl font-bold mb-4 flex items-center">
            <span className="mr-2">🤖</span>
            AI Insights
          </h3>
          <div className="space-y-3">
            {aiInsights.slice(0, 3).map((insight, i) => (
              <div key={i} className="p-4 bg-black/30 rounded-lg">
                <p className="text-sm text-gray-300">{insight.message}</p>
                <div className="mt-2 text-xs text-gray-500">
                  Confidence: {Math.round((insight.confidence || 0) * 100)}%
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default DashboardPage;
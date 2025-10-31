import React, { useState } from 'react';
import { useScan } from '../context/EnhancedScanContext';
import DetailedVulnerabilityModal from '../components/DetailedVulnerabilityModal';

const VulnerabilitiesPage = () => {
  const { vulnerabilities, currentScanId } = useScan();
  const [selectedVulnerability, setSelectedVulnerability] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [sortBy, setSortBy] = useState('severity');

  // Filter and sort vulnerabilities
  const filteredVulnerabilities = vulnerabilities.filter(vuln => {
    if (filterSeverity === 'all') return true;
    return vuln.severity === filterSeverity;
  });

  const sortedVulnerabilities = [...filteredVulnerabilities].sort((a, b) => {
    switch (sortBy) {
      case 'severity':
        const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        return severityOrder[b.severity] - severityOrder[a.severity];
      case 'title':
        return a.title.localeCompare(b.title);
      case 'url':
        return (a.url || '').localeCompare(b.url || '');
      default:
        return 0;
    }
  });

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical': return '🔴';
      case 'high': return '🟠';
      case 'medium': return '🟡';
      case 'low': return '🟢';
      default: return '⚪';
    }
  };

  const getStatistics = () => {
    const stats = vulnerabilities.reduce((acc, vuln) => {
      acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
      return acc;
    }, {});
    
    return {
      total: vulnerabilities.length,
      critical: stats.critical || 0,
      high: stats.high || 0,
      medium: stats.medium || 0,
      low: stats.low || 0,
    };
  };

  const statistics = getStatistics();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold">Vulnerabilities</h2>
        <div className="text-sm text-gray-400">
          Scan ID: {currentScanId || 'No active scan'}
        </div>
      </div>

      {/* Statistics Overview */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 text-center">
          <div className="text-2xl font-bold text-white">{statistics.total}</div>
          <div className="text-sm text-gray-400">Total</div>
        </div>
        <div className="bg-red-900/20 rounded-lg border border-red-500/50 p-4 text-center">
          <div className="text-2xl font-bold text-red-400">{statistics.critical}</div>
          <div className="text-sm text-gray-400">Critical</div>
        </div>
        <div className="bg-orange-900/20 rounded-lg border border-orange-500/50 p-4 text-center">
          <div className="text-2xl font-bold text-orange-400">{statistics.high}</div>
          <div className="text-sm text-gray-400">High</div>
        </div>
        <div className="bg-yellow-900/20 rounded-lg border border-yellow-500/50 p-4 text-center">
          <div className="text-2xl font-bold text-yellow-400">{statistics.medium}</div>
          <div className="text-sm text-gray-400">Medium</div>
        </div>
        <div className="bg-blue-900/20 rounded-lg border border-blue-500/50 p-4 text-center">
          <div className="text-2xl font-bold text-blue-400">{statistics.low}</div>
          <div className="text-sm text-gray-400">Low</div>
        </div>
      </div>

      {/* Filters and Controls */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center space-x-2">
            <label className="text-sm font-medium text-gray-300">Filter by severity:</label>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="px-3 py-1 bg-gray-800 border border-gray-700 rounded focus:ring-2 focus:ring-purple-500"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical Only</option>
              <option value="high">High Only</option>
              <option value="medium">Medium Only</option>
              <option value="low">Low Only</option>
            </select>
          </div>

          <div className="flex items-center space-x-2">
            <label className="text-sm font-medium text-gray-300">Sort by:</label>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="px-3 py-1 bg-gray-800 border border-gray-700 rounded focus:ring-2 focus:ring-purple-500"
            >
              <option value="severity">Severity</option>
              <option value="title">Title</option>
              <option value="url">URL</option>
            </select>
          </div>

          <div className="text-sm text-gray-400">
            Showing {sortedVulnerabilities.length} of {vulnerabilities.length} vulnerabilities
          </div>
        </div>
      </div>

      {/* Vulnerabilities List */}
      <div className="bg-gray-900 rounded-xl border border-gray-800">
        <div className="p-6">
          <h3 className="text-xl font-bold mb-4">Detected Vulnerabilities</h3>
          
          {vulnerabilities.length === 0 ? (
            <div className="text-center py-12 text-gray-500">
              <div className="text-4xl mb-4">🔍</div>
              <p className="text-lg">No vulnerabilities detected yet</p>
              <p className="text-sm mt-2">Start a scan to see results here</p>
            </div>
          ) : sortedVulnerabilities.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              <p>No vulnerabilities match the current filter</p>
            </div>
          ) : (
            <div className="space-y-4">
              {sortedVulnerabilities.map((vulnerability, index) => (
                <div
                  key={`${vulnerability.id}-${index}`}
                  className={`p-6 rounded-lg border-l-4 cursor-pointer transition-all hover:bg-gray-800/50 ${
                    vulnerability.severity === 'critical' ? 'border-red-500 bg-red-900/10' :
                    vulnerability.severity === 'high' ? 'border-orange-500 bg-orange-900/10' :
                    vulnerability.severity === 'medium' ? 'border-yellow-500 bg-yellow-900/10' :
                    'border-blue-500 bg-blue-900/10'
                  }`}
                  onClick={() => setSelectedVulnerability(vulnerability)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <span className="text-lg">{getSeverityIcon(vulnerability.severity)}</span>
                        <h4 className="text-lg font-semibold">{vulnerability.title}</h4>
                        <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                          vulnerability.severity === 'critical' ? 'bg-red-600 text-white' :
                          vulnerability.severity === 'high' ? 'bg-orange-600 text-white' :
                          vulnerability.severity === 'medium' ? 'bg-yellow-600 text-black' :
                          'bg-blue-600 text-white'
                        }`}>
                          {vulnerability.severity.toUpperCase()}
                        </span>
                      </div>
                      
                      <p className="text-gray-300 mb-3">{vulnerability.description}</p>
                      
                      <div className="flex flex-wrap items-center gap-4 text-sm text-gray-400">
                        {vulnerability.url && (
                          <div className="flex items-center space-x-1">
                            <span>🌐</span>
                            <span className="truncate max-w-md">{vulnerability.url}</span>
                          </div>
                        )}
                        
                        {vulnerability.cve_id && (
                          <div className="flex items-center space-x-1">
                            <span>🆔</span>
                            <span className="font-mono">{vulnerability.cve_id}</span>
                          </div>
                        )}
                        
                        {vulnerability.risk_score && (
                          <div className="flex items-center space-x-1">
                            <span>📊</span>
                            <span>Risk Score: {vulnerability.risk_score}/10</span>
                          </div>
                        )}
                        
                        {vulnerability.category && (
                          <div className="flex items-center space-x-1">
                            <span>📂</span>
                            <span>{vulnerability.category}</span>
                          </div>
                        )}
                      </div>
                      
                      {/* Severity-specific indicators */}
                      <div className="mt-3 flex items-center space-x-4">
                        {vulnerability.exploit_available && (
                          <span className="px-2 py-1 bg-red-600 text-white text-xs rounded">
                            ⚠️ Exploit Available
                          </span>
                        )}
                        
                        {vulnerability.false_positive && (
                          <span className="px-2 py-1 bg-gray-600 text-white text-xs rounded">
                            🏷️ Possible False Positive
                          </span>
                        )}
                        
                        {vulnerability.remediation_suggested && (
                          <span className="px-2 py-1 bg-blue-600 text-white text-xs rounded">
                            🛠️ Remediation Available
                          </span>
                        )}
                      </div>
                    </div>
                    
                    <div className="ml-4 text-right">
                      <button
                        className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg text-sm transition-colors"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedVulnerability(vulnerability);
                        }}
                      >
                        View Details
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Detailed Vulnerability Modal */}
      {selectedVulnerability && (
        <DetailedVulnerabilityModal
          vulnerability={selectedVulnerability}
          onClose={() => setSelectedVulnerability(null)}
        />
      )}
    </div>
  );
};

export default VulnerabilitiesPage;
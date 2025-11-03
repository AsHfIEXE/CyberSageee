import React, { useState, useEffect } from 'react';

const IndustryVulnerabilityModal = ({ vulnerabilityId, onClose }) => {
  const [vulnerability, setVulnerability] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  
  const backendUrl = process.env.REACT_APP_BACKEND_URL || `${window.location.protocol}//${window.location.hostname}:5000`;

  useEffect(() => {
    if (vulnerabilityId) {
      fetchVulnerabilityDetails();
    }
  }, [vulnerabilityId]);

  const fetchVulnerabilityDetails = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${backendUrl}/api/vulnerability/${vulnerabilityId}`);
      const data = await response.json();
      setVulnerability(data.vulnerability);
    } catch (error) {
      console.error('Error fetching vulnerability:', error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'bg-red-500',
      high: 'bg-orange-500',
      medium: 'bg-yellow-500',
      low: 'bg-blue-500'
    };
    return colors[severity] || 'bg-gray-500';
  };

  const getCVSSColor = (score) => {
    if (score >= 9.0) return 'text-red-500';
    if (score >= 7.0) return 'text-orange-500';
    if (score >= 4.0) return 'text-yellow-500';
    return 'text-blue-500';
  };

  if (loading) {
    return (
      <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50">
        <div className="bg-gray-900 rounded-xl p-8">
          <div className="animate-spin text-4xl mb-4">⚙️</div>
          <p className="text-white">Loading vulnerability details...</p>
        </div>
      </div>
    );
  }

  if (!vulnerability) {
    return (
      <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50">
        <div className="bg-gray-900 rounded-xl p-8">
          <p className="text-red-400">Vulnerability not found</p>
          <button onClick={onClose} className="mt-4 px-4 py-2 bg-gray-700 rounded">Close</button>
        </div>
      </div>
    );
  }

  const tabs = [
    { id: 'overview', label: 'Overview', icon: '📋' },
    { id: 'request', label: 'Request', icon: '📤' },
    { id: 'response', label: 'Response', icon: '📥' },
    { id: 'payload', label: 'Payload', icon: '💉' },
    { id: 'poc', label: 'Proof of Concept', icon: '🎯' },
    { id: 'remediation', label: 'Remediation', icon: '🛡️' },
    { id: 'references', label: 'References', icon: '📚' }
  ];

  return (
    <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4 overflow-y-auto">
      <div className="bg-gray-900 rounded-xl border border-gray-700 max-w-7xl w-full my-8">
        {/* Header */}
        <div className="flex justify-between items-center p-6 border-b border-gray-700 bg-gray-800">
          <div className="flex items-center space-x-4">
            <div className="text-3xl">🔍</div>
            <div>
              <h2 className="text-2xl font-bold text-white">{vulnerability.vuln_type || vulnerability.type}</h2>
              <p className="text-gray-400 text-sm">Vuln ID: #{vulnerability.id} | Detected: {new Date(vulnerability.detected_at).toLocaleString()}</p>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <span className={`px-4 py-2 ${getSeverityColor(vulnerability.severity)} text-white rounded-lg font-bold text-lg`}>
              {vulnerability.severity?.toUpperCase()}
            </span>
            <button onClick={onClose} className="text-gray-400 hover:text-white text-3xl">×</button>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-gray-700 bg-gray-800 overflow-x-auto">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-6 py-4 text-sm font-medium whitespace-nowrap ${
                activeTab === tab.id
                  ? 'text-purple-400 border-b-2 border-purple-400 bg-gray-900/50'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <span className="mr-2">{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="p-6 max-h-[70vh] overflow-y-auto">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Quick Info Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                  <div className="text-gray-400 text-xs mb-1">CVSS Score</div>
                  <div className={`text-3xl font-bold ${getCVSSColor(vulnerability.cvss_score || 0)}`}>
                    {vulnerability.cvss_score || 'N/A'}
                  </div>
                </div>
                <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                  <div className="text-gray-400 text-xs mb-1">CWE ID</div>
                  <div className="text-2xl font-bold text-white">
                    {vulnerability.cwe_id || 'N/A'}
                  </div>
                </div>
                <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                  <div className="text-gray-400 text-xs mb-1">Confidence</div>
                  <div className="text-3xl font-bold text-white">
                    {vulnerability.confidence_score || vulnerability.confidence || 0}%
                  </div>
                </div>
                <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                  <div className="text-gray-400 text-xs mb-1">Tool</div>
                  <div className="text-lg font-bold text-white truncate">
                    {vulnerability.detection_tool || vulnerability.tool || 'Unknown'}
                  </div>
                </div>
              </div>

              {/* Description */}
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h3 className="text-white font-bold text-lg mb-4">📝 Description</h3>
                <p className="text-gray-300 leading-relaxed">{vulnerability.description || vulnerability.title}</p>
              </div>

              {/* Affected Target */}
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h3 className="text-white font-bold text-lg mb-4">🎯 Affected Target</h3>
                <div className="space-y-3">
                  <div>
                    <div className="text-gray-400 text-sm mb-1">URL</div>
                    <div className="bg-gray-900 p-3 rounded font-mono text-sm text-purple-400 break-all">
                      {vulnerability.affected_url || vulnerability.url}
                    </div>
                  </div>
                  {vulnerability.affected_parameter && (
                    <div>
                      <div className="text-gray-400 text-sm mb-1">Parameter</div>
                      <div className="bg-gray-900 p-3 rounded font-mono text-sm text-green-400">
                        {vulnerability.affected_parameter}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'request' && (
            <div className="space-y-4">
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h3 className="text-white font-bold text-lg mb-4">📤 HTTP Request</h3>
                {vulnerability.http_history && vulnerability.http_history.length > 0 ? (
                  vulnerability.http_history.map((req, idx) => (
                    <div key={idx} className="mb-6 last:mb-0">
                      <div className="flex items-center justify-between mb-3">
                        <span className={`px-3 py-1 rounded font-bold text-sm ${
                          req.method === 'POST' ? 'bg-green-600' : 'bg-blue-600'
                        } text-white`}>
                          {req.method}
                        </span>
                        <span className="text-gray-400 text-sm">{req.response_time_ms}ms</span>
                      </div>
                      <div className="bg-gray-900 p-4 rounded-lg border border-gray-700">
                        <div className="text-purple-400 font-mono text-sm mb-2">{req.method} {req.url}</div>
                        <pre className="text-xs text-gray-300 overflow-x-auto whitespace-pre-wrap">
{req.request_headers}

{req.request_body || '[No Body]'}
                        </pre>
                      </div>
                    </div>
                  ))
                ) : vulnerability.request_raw ? (
                  <pre className="bg-gray-900 p-4 rounded text-sm text-gray-300 overflow-x-auto">
{vulnerability.request_raw}
                  </pre>
                ) : (
                  <div className="text-center py-8 text-gray-500">No request data available</div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'response' && (
            <div className="space-y-4">
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h3 className="text-white font-bold text-lg mb-4">📥 HTTP Response</h3>
                {vulnerability.http_history && vulnerability.http_history.length > 0 ? (
                  vulnerability.http_history.map((req, idx) => (
                    <div key={idx} className="mb-6 last:mb-0">
                      <div className="flex items-center justify-between mb-3">
                        <span className={`px-3 py-1 rounded font-bold text-sm ${
                          req.response_code < 300 ? 'bg-green-600' :
                          req.response_code < 400 ? 'bg-blue-600' :
                          req.response_code < 500 ? 'bg-yellow-600' : 'bg-red-600'
                        } text-white`}>
                          {req.response_code}
                        </span>
                        <span className="text-gray-400 text-sm">Response Time: {req.response_time_ms}ms</span>
                      </div>
                      <div className="bg-gray-900 p-4 rounded-lg border border-gray-700">
                        <div className="text-blue-400 font-mono text-sm mb-2">HTTP {req.response_code}</div>
                        <div className="mb-4">
                          <div className="text-gray-400 text-xs mb-2">Headers</div>
                          <pre className="text-xs text-gray-300 overflow-x-auto bg-gray-950 p-3 rounded max-h-40">
{req.response_headers}
                          </pre>
                        </div>
                        <div>
                          <div className="text-gray-400 text-xs mb-2">Body</div>
                          <pre className="text-xs text-gray-300 overflow-x-auto bg-gray-950 p-3 rounded max-h-96">
{req.response_body?.substring(0, 5000) || '[No Body]'}
{req.response_body?.length > 5000 && '\n\n... [Truncated]'}
                          </pre>
                        </div>
                      </div>
                    </div>
                  ))
                ) : vulnerability.response_raw ? (
                  <pre className="bg-gray-900 p-4 rounded text-sm text-gray-300 overflow-x-auto max-h-96">
{vulnerability.response_raw}
                  </pre>
                ) : (
                  <div className="text-center py-8 text-gray-500">No response data available</div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'payload' && (
            <div className="space-y-4">
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h3 className="text-white font-bold text-lg mb-4">💉 Exploit Payload</h3>
                {vulnerability.payload ? (
                  <>
                    <div className="bg-gray-900 p-4 rounded-lg border border-green-500/30 mb-4">
                      <code className="text-green-400 text-sm font-mono break-all">
                        {vulnerability.payload}
                      </code>
                    </div>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(vulnerability.payload);
                        alert('Payload copied to clipboard!');
                      }}
                      className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded"
                    >
                      📋 Copy Payload
                    </button>
                  </>
                ) : (
                  <div className="text-center py-8 text-gray-500">No payload data available</div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'poc' && (
            <div className="space-y-4">
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h3 className="text-white font-bold text-lg mb-4">🎯 Proof of Concept</h3>
                {vulnerability.proof_of_concept || vulnerability.poc ? (
                  <>
                    <pre className="bg-gray-900 p-4 rounded text-sm text-gray-300 whitespace-pre-wrap">
{vulnerability.proof_of_concept || vulnerability.poc}
                    </pre>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(vulnerability.proof_of_concept || vulnerability.poc);
                        alert('PoC copied to clipboard!');
                      }}
                      className="mt-4 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded"
                    >
                      📋 Copy PoC
                    </button>
                  </>
                ) : (
                  <div className="text-center py-8 text-gray-500">No proof of concept available</div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'remediation' && (
            <div className="space-y-4">
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h3 className="text-white font-bold text-lg mb-4">🛡️ Remediation Steps</h3>
                {vulnerability.remediation ? (
                  <pre className="text-gray-300 text-sm whitespace-pre-wrap leading-relaxed">
{vulnerability.remediation}
                  </pre>
                ) : (
                  <div className="text-gray-400">
                    <p className="mb-4">General remediation guidelines:</p>
                    <ul className="list-disc list-inside space-y-2 ml-4">
                      <li>Apply security patches and updates</li>
                      <li>Implement input validation and output encoding</li>
                      <li>Use security best practices for your framework</li>
                      <li>Conduct regular security testing</li>
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'references' && (
            <div className="space-y-4">
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h3 className="text-white font-bold text-lg mb-4">📚 References</h3>
                <div className="space-y-3">
                  {vulnerability.cwe_id && (
                    <a
                      href={`https://cwe.mitre.org/data/definitions/${vulnerability.cwe_id.replace('CWE-', '')}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block bg-gray-900 p-4 rounded hover:bg-gray-750 transition"
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="text-white font-semibold">MITRE CWE</div>
                          <div className="text-gray-400 text-sm">{vulnerability.cwe_id}</div>
                        </div>
                        <div className="text-blue-400">→</div>
                      </div>
                    </a>
                  )}
                  <a
                    href="https://owasp.org/www-project-top-ten/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block bg-gray-900 p-4 rounded hover:bg-gray-750 transition"
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-white font-semibold">OWASP Top 10</div>
                        <div className="text-gray-400 text-sm">Web Application Security Risks</div>
                      </div>
                      <div className="text-blue-400">→</div>
                    </div>
                  </a>
                  <a
                    href={`https://nvd.nist.gov/vuln/search`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block bg-gray-900 p-4 rounded hover:bg-gray-750 transition"
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-white font-semibold">NIST NVD</div>
                        <div className="text-gray-400 text-sm">National Vulnerability Database</div>
                      </div>
                      <div className="text-blue-400">→</div>
                    </div>
                  </a>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-between items-center p-6 border-t border-gray-700 bg-gray-800">
          <div className="text-gray-400 text-sm">
            Detected: {new Date(vulnerability.detected_at).toLocaleString()}
          </div>
          <div className="flex space-x-3">
            <button
              onClick={() => {
                const reportData = JSON.stringify(vulnerability, null, 2);
                const blob = new Blob([reportData], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `vulnerability-${vulnerability.id}.json`;
                a.click();
              }}
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded"
            >
              💾 Export JSON
            </button>
            <button onClick={onClose} className="px-6 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded">
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default IndustryVulnerabilityModal;
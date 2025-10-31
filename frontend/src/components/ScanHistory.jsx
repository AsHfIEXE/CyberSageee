import React, { useEffect, useState } from 'react';

const ScanHistory = () => {
  const [scans, setScans] = useState([]);
  const [selected, setSelected] = useState(null);
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [scanDetails, setScanDetails] = useState(null);
  const [loading, setLoading] = useState(false);
  const backendUrl = process.env.REACT_APP_BACKEND_URL || `${window.location.protocol}//${window.location.hostname}:5000`;

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${backendUrl}/api/scans`);
        const data = await res.json();
        setScans(data.scans || []);
      } catch (e) { /* ignore */ }
    })();
  }, [backendUrl]);

  const loadDetails = async (scanId) => {
    setSelected(scanId);
    setLoading(true);
    try {
      const [hRes, sRes, scanRes] = await Promise.all([
        fetch(`${backendUrl}/api/scan/${scanId}/history`),
        fetch(`${backendUrl}/api/scan/${scanId}/statistics`),
        fetch(`${backendUrl}/api/scan/${scanId}`)
      ]);
      const h = await hRes.json();
      const s = await sRes.json();
      const scanData = await scanRes.json();
      setHistory(h.history || []);
      setStats(s.statistics || {});
      setVulnerabilities(scanData.vulnerabilities || []);
      setScanDetails(scanData.scan);
    } catch (e) { /* ignore */ } finally {
      setLoading(false);
    }
  };

  const exportToPDF = async (scanId) => {
    try {
      // Export as PDF
      const response = await fetch(`${backendUrl}/api/scan/${scanId}/export/pdf`);
      if (response.ok) {
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cybersage-scan-${scanId}.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } else {
        // Fallback to JSON export
        const jsonResponse = await fetch(`${backendUrl}/api/scan/${scanId}/export`);
        const data = await jsonResponse.json();
        
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cybersage-scan-${scanId}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    } catch (error) {
      console.error('Error exporting scan:', error);
    }
  };

  const getSeverityCount = (severity) => {
    return vulnerabilities.filter(v => v.severity === severity).length;
  };

  const formatDate = (timestamp) => {
    return new Date(timestamp * 1000).toLocaleString();
  };

  const formatDuration = (seconds) => {
    if (!seconds) return 'N/A';
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
  };

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-bold text-white flex items-center">
          <span className="mr-2">🗂️</span>
          Scan History
        </h2>
        <button
          onClick={() => window.location.reload()}
          className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded"
        >
          Refresh
        </button>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-1">
          <div className="max-h-80 overflow-auto border border-gray-700 rounded">
            {scans.map(s => (
              <button key={s.scan_id}
                onClick={() => loadDetails(s.scan_id)}
                className={`w-full text-left px-3 py-3 border-b border-gray-700 hover:bg-gray-700/50 transition-colors ${selected===s.scan_id?'bg-gray-700':''}`}>
                <div className="text-white text-sm font-medium truncate">{s.target}</div>
                <div className="text-xs text-gray-400 capitalize">{s.scan_mode} scan</div>
                <div className="flex justify-between items-center mt-1">
                  <span className={`text-xs px-2 py-1 rounded ${
                    s.status === 'completed' ? 'bg-green-900/30 text-green-400' :
                    s.status === 'running' ? 'bg-blue-900/30 text-blue-400' :
                    s.status === 'failed' ? 'bg-red-900/30 text-red-400' :
                    'bg-yellow-900/30 text-yellow-400'
                  }`}>
                    {s.status.toUpperCase()}
                  </span>
                  <span className="text-xs text-gray-500">{formatDate(s.started_at)}</span>
                </div>
                {s.duration_seconds && (
                  <div className="text-xs text-gray-500 mt-1">
                    Duration: {formatDuration(s.duration_seconds)}
                  </div>
                )}
              </button>
            ))}
          </div>
        </div>
        
        <div className="lg:col-span-2 space-y-4">
          {loading && (
            <div className="text-center py-8 text-gray-500">
              Loading scan details...
            </div>
          )}
          
          {selected && scanDetails && (
            <>
              {/* Scan Overview */}
              <div className="bg-gray-900 border border-gray-700 rounded p-4">
                <div className="flex justify-between items-center mb-3">
                  <h3 className="text-white font-semibold">Scan Overview</h3>
                  <button
                    onClick={() => exportToPDF(selected)}
                    className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded"
                  >
                    Export Report
                  </button>
                </div>
                
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
                  <div className="bg-gray-800 p-2 rounded">
                    <div className="text-gray-400 text-xs">Target</div>
                    <div className="text-white font-semibold text-sm truncate">{scanDetails.target}</div>
                  </div>
                  <div className="bg-gray-800 p-2 rounded">
                    <div className="text-gray-400 text-xs">Mode</div>
                    <div className="text-white font-semibold text-sm capitalize">{scanDetails.scan_mode}</div>
                  </div>
                  <div className="bg-gray-800 p-2 rounded">
                    <div className="text-gray-400 text-xs">Duration</div>
                    <div className="text-white font-semibold text-sm">{formatDuration(scanDetails.duration_seconds)}</div>
                  </div>
                  <div className="bg-gray-800 p-2 rounded">
                    <div className="text-gray-400 text-xs">Status</div>
                    <div className={`font-semibold text-sm ${
                      scanDetails.status === 'completed' ? 'text-green-400' :
                      scanDetails.status === 'running' ? 'text-blue-400' :
                      scanDetails.status === 'failed' ? 'text-red-400' :
                      'text-yellow-400'
                    }`}>
                      {scanDetails.status.toUpperCase()}
                    </div>
                  </div>
                </div>
                
                <div className="text-sm text-gray-300 space-y-1">
                  <p><strong>Started:</strong> {formatDate(scanDetails.started_at)}</p>
                  {scanDetails.completed_at && (
                    <p><strong>Completed:</strong> {formatDate(scanDetails.completed_at)}</p>
                  )}
                  {scanDetails.error_message && (
                    <p className="text-red-400"><strong>Error:</strong> {scanDetails.error_message}</p>
                  )}
                </div>
              </div>

              {/* Vulnerability Summary */}
              {vulnerabilities.length > 0 && (
                <div className="bg-gray-900 border border-gray-700 rounded p-4">
                  <h3 className="text-white font-semibold mb-3">Vulnerability Summary</h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div className="bg-red-900/30 border border-red-500/50 p-3 rounded">
                      <div className="text-red-400 text-sm">Critical</div>
                      <div className="text-white font-bold text-xl">{getSeverityCount('critical')}</div>
                    </div>
                    <div className="bg-orange-900/30 border border-orange-500/50 p-3 rounded">
                      <div className="text-orange-400 text-sm">High</div>
                      <div className="text-white font-bold text-xl">{getSeverityCount('high')}</div>
                    </div>
                    <div className="bg-yellow-900/30 border border-yellow-500/50 p-3 rounded">
                      <div className="text-yellow-400 text-sm">Medium</div>
                      <div className="text-white font-bold text-xl">{getSeverityCount('medium')}</div>
                    </div>
                    <div className="bg-blue-900/30 border border-blue-500/50 p-3 rounded">
                      <div className="text-blue-400 text-sm">Low</div>
                      <div className="text-white font-bold text-xl">{getSeverityCount('low')}</div>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
          
          {stats && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {['endpoints_discovered','parameters_tested','payloads_sent','vulnerabilities_found'].map(k => (
                <div key={k} className="bg-gray-900 border border-gray-700 rounded p-3">
                  <div className="text-xs text-gray-400">{k.replace(/_/g,' ')}</div>
                  <div className="text-2xl text-white font-bold">{stats[k] ?? 0}</div>
                </div>
              ))}
            </div>
          )}
          
          <div className="bg-gray-900 border border-gray-700 rounded p-3">
            <div className="text-xs text-gray-400 mb-2">HTTP History ({history.length} requests)</div>
            <div className="max-h-80 overflow-auto">
              {history.length === 0 ? (
                <div className="text-center py-4 text-gray-500">No HTTP history available</div>
              ) : (
                history.map(h => (
                  <div key={h.id} className="border-b border-gray-800 py-2 hover:bg-gray-800/50 transition-colors">
                    <div className="flex justify-between text-xs text-gray-400">
                      <span className="font-mono">{h.method} {h.url}</span>
                      <span>{h.response_code} · {h.response_time_ms} ms</span>
                    </div>
                    {h.vulnerability_id && (
                      <div className="text-xs text-red-400 mt-1">⚠️ Associated with vulnerability</div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanHistory;



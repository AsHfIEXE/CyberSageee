import React, { useState, useEffect, useCallback } from 'react';

const ScanStatistics = ({ scanId }) => {
  const [statistics, setStatistics] = useState({});
  const [loading, setLoading] = useState(false);
  
  const backendUrl = process.env.REACT_APP_BACKEND_URL || `${window.location.protocol}//${window.location.hostname}:5000`;

  const fetchStatistics = useCallback(async () => {
    if (!scanId) return;
    setLoading(true);
    try {
      const response = await fetch(`${backendUrl}/api/scan/${scanId}/statistics`);
      const data = await response.json();
      setStatistics(data.statistics || {});
    } catch (error) {
      console.error('Error fetching statistics:', error);
    } finally {
      setLoading(false);
    }
  }, [backendUrl, scanId]);

  useEffect(() => {
    if (scanId) {
      fetchStatistics();
    }
  }, [scanId, fetchStatistics]);

  const formatNumber = (num) => {
    if (num === null || num === undefined) return '0';
    return num.toLocaleString();
  };

  if (!scanId) {
    return (
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
        <h2 className="text-xl font-bold text-white mb-4 flex items-center">
          <span className="mr-2">📊</span>
          Scan Statistics
        </h2>
        <div className="text-center py-8 text-gray-500">
          Start a scan to see detailed statistics
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-bold text-white flex items-center">
          <span className="mr-2">📊</span>
          Scan Statistics
        </h2>
        <button
          onClick={fetchStatistics}
          disabled={loading}
          className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded disabled:opacity-50"
        >
          {loading ? 'Loading...' : 'Refresh'}
        </button>
      </div>

      {loading ? (
        <div className="text-center py-8 text-gray-500">Loading statistics...</div>
      ) : (
        <div className="space-y-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
              <div className="flex items-center justify-between mb-2">
                <span className="text-gray-400 text-sm">Endpoints</span>
                <span className="text-blue-400">🌐</span>
              </div>
              <div className="text-2xl font-bold text-white">
                {formatNumber(statistics.endpoints_discovered)}
              </div>
              <div className="text-xs text-gray-500">discovered</div>
            </div>

            <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
              <div className="flex items-center justify-between mb-2">
                <span className="text-gray-400 text-sm">Parameters</span>
                <span className="text-green-400">🔍</span>
              </div>
              <div className="text-2xl font-bold text-white">
                {formatNumber(statistics.parameters_tested)}
              </div>
              <div className="text-xs text-gray-500">tested</div>
            </div>

            <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
              <div className="flex items-center justify-between mb-2">
                <span className="text-gray-400 text-sm">Payloads</span>
                <span className="text-yellow-400">⚡</span>
              </div>
              <div className="text-2xl font-bold text-white">
                {formatNumber(statistics.payloads_sent)}
              </div>
              <div className="text-xs text-gray-500">sent</div>
            </div>

            <div className="bg-gray-900 rounded-lg p-4 border border-gray-700">
              <div className="flex items-center justify-between mb-2">
                <span className="text-gray-400 text-sm">Vulnerabilities</span>
                <span className="text-red-400">🚨</span>
              </div>
              <div className="text-2xl font-bold text-white">
                {formatNumber(statistics.vulnerabilities_found)}
              </div>
              <div className="text-xs text-gray-500">found</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanStatistics;
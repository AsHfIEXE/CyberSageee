import React, { useState } from 'react';
import { useScan } from '../context/EnhancedScanContext';

const ScanControlPanel = ({ scanId, scanStatus, progress, currentPhase }) => {
  const { actions } = useScan();
  const [isPaused, setIsPaused] = useState(false);

  const handlePause = () => {
    setIsPaused(true);
    actions.pauseScan();
  };

  const handleResume = () => {
    setIsPaused(false);
    actions.resumeScan();
  };

  const handleStop = () => {
    actions.stopScan();
  };

  const getStatusColor = () => {
    if (isPaused) return 'text-yellow-400';
    if (scanStatus === 'running') return 'text-green-400';
    if (scanStatus === 'completed') return 'text-blue-400';
    if (scanStatus === 'failed') return 'text-red-400';
    return 'text-gray-400';
  };

  const getStatusIcon = () => {
    if (isPaused) return '⏸️';
    if (scanStatus === 'running') return '▶️';
    if (scanStatus === 'completed') return '✅';
    if (scanStatus === 'failed') return '❌';
    return '⏹️';
  };

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-800 p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <div className="text-3xl">{getStatusIcon()}</div>
          <div>
            <h3 className="text-white font-bold text-lg">Scan Control</h3>
            <p className={`text-sm font-medium ${getStatusColor()}`}>
              {isPaused ? 'Paused' : scanStatus === 'running' ? 'In Progress' : scanStatus.toUpperCase()}
            </p>
          </div>
        </div>
        
        {scanStatus === 'running' && (
          <div className="flex items-center space-x-2">
            {!isPaused ? (
              <button
                onClick={handlePause}
                className="px-4 py-2 bg-yellow-600 hover:bg-yellow-700 text-white rounded-lg font-medium transition"
              >
                ⏸️ Pause
              </button>
            ) : (
              <button
                onClick={handleResume}
                className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg font-medium transition"
              >
                ▶️ Resume
              </button>
            )}
            <button
              onClick={handleStop}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg font-medium transition"
            >
              ⏹️ Stop
            </button>
          </div>
        )}
      </div>

      {/* Progress Bar */}
      {scanStatus === 'running' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between text-sm">
            <span className="text-gray-400">{currentPhase || 'Initializing...'}</span>
            <span className="text-white font-bold">{progress}%</span>
          </div>
          <div className="h-3 bg-gray-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-purple-600 to-pink-600 transition-all duration-500 ease-out"
              style={{ width: `${progress}%` }}
            >
              <div className="h-full w-full bg-gradient-to-r from-transparent via-white to-transparent opacity-30 animate-pulse"></div>
            </div>
          </div>
        </div>
      )}

      {/* Scan Info */}
      {scanId && (
        <div className="mt-4 pt-4 border-t border-gray-800">
          <div className="text-xs text-gray-400">
            <div>Scan ID: <span className="text-gray-300 font-mono">{scanId}</span></div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanControlPanel;

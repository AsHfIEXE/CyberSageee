import React from 'react';

const ProgressBar = ({ progress, phase }) => {
  // Smooth tweening via CSS transition already present; add aria and min-progress visuals
  return (
    <div className="bg-gray-800 rounded-lg p-6 border border-purple-500/30">
      <div className="flex justify-between mb-3">
        <span className="text-gray-300 font-medium">{phase}</span>
        <span className="text-purple-400 font-bold text-lg">{progress}%</span>
      </div>
      <div className="w-full bg-gray-700 rounded-full h-4 overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-purple-500 via-pink-500 to-purple-500 transition-all duration-700 ease-in-out animate-gradient"
          style={{ width: `${Math.max(1, progress)}%` }}
          role="progressbar"
          aria-valuenow={progress}
          aria-valuemin={0}
          aria-valuemax={100}
        />
      </div>
      <div className="mt-3 flex items-center text-sm text-gray-400">
        <div className="w-2 h-2 bg-purple-500 rounded-full animate-pulse mr-2"></div>
        Analyzing security posture...
      </div>
    </div>
  );
};

export default ProgressBar;
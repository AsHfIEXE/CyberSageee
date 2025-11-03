import React from 'react';

const ToolActivity = ({ activity }) => {
  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
      <h2 className="text-xl font-bold text-white mb-4 flex items-center">
        <span className="mr-2">⚙️</span>
        Tool Activity
      </h2>
      <div className="space-y-2">
        {activity.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            No active tools
          </div>
        ) : (
          activity.map((item, index) => (
            <div
              key={index}
              className="flex items-center p-3 bg-gray-900/50 rounded-lg backdrop-blur-sm animate-fade-in"
            >
              <div className={`w-2 h-2 rounded-full mr-3 ${
                item.status === 'running' 
                  ? 'bg-green-500 animate-pulse' 
                  : 'bg-blue-500'
              }`}></div>
              <div className="flex-1">
                <p className="text-white text-sm font-medium">{item.tool}</p>
                <p className="text-gray-500 text-xs truncate">{item.target}</p>
              </div>
              {item.findings !== undefined && (
                <span className="text-xs bg-purple-600 text-white px-2 py-1 rounded-full">
                  {item.findings} found
                </span>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default ToolActivity;
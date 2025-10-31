import React from 'react';

function App() {
  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <div className="container mx-auto px-4 py-8">
        <div className="text-center">
          <h1 className="text-4xl font-bold mb-4 text-blue-400">
            🛡️ CyberSage v2.0
          </h1>
          <p className="text-xl mb-8 text-gray-300">
            Elite Vulnerability Intelligence Platform
          </p>
          <div className="bg-gray-800 rounded-lg p-6 max-w-2xl mx-auto">
            <h2 className="text-2xl font-semibold mb-4">System Status</h2>
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <span>Frontend</span>
                <span className="text-green-400">✅ Online</span>
              </div>
              <div className="flex justify-between items-center">
                <span>Backend</span>
                <span className="text-yellow-400">⏳ Connecting...</span>
              </div>
              <div className="flex justify-between items-center">
                <span>Database</span>
                <span className="text-yellow-400">⏳ Checking...</span>
              </div>
            </div>
          </div>
          <div className="mt-8">
            <p className="text-gray-400">
              🚀 Start scanning your targets with professional security tools
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
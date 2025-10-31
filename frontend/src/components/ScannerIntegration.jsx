import React, { useState } from 'react';

const ScannerIntegration = ({ currentScanId }) => {
  const [activeTab, setActiveTab] = useState('nmap');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState({});
  
  const backendUrl = process.env.REACT_APP_BACKEND_URL || `${window.location.protocol}//${window.location.hostname}:5000`;

  const scanners = [
    { id: 'nmap', name: 'Nmap', description: 'Network port scanner', icon: '🔍' },
    { id: 'nessus', name: 'Nessus', description: 'Vulnerability scanner', icon: '🛡️' },
    { id: 'owasp-zap', name: 'OWASP ZAP', description: 'Web application scanner', icon: '🕷️' },
    { id: 'burp', name: 'Burp Suite', description: 'Web security testing', icon: '🔧' },
    { id: 'custom', name: 'Custom Scanner', description: 'Upload custom results', icon: '⚙️' }
  ];

  const integrateResults = async (scannerType, data) => {
    setLoading(true);
    try {
      const endpoint = scannerType === 'custom' ? 'custom' : scannerType;
      const payload = {
        scan_id: currentScanId,
        ...data
      };

      const response = await fetch(`${backendUrl}/api/integration/${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const result = await response.json();
      setResults(prev => ({ ...prev, [scannerType]: result }));
      
      if (result.status === 'success') {
        alert(`✅ ${result.message}`);
      } else {
        alert(`❌ Error: ${result.error}`);
      }
    } catch (error) {
      alert(`❌ Integration failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleNmapIntegration = (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const nmapOutput = formData.get('nmap_output');
    
    if (!nmapOutput.trim()) {
      alert('Please enter Nmap output');
      return;
    }
    
    integrateResults('nmap', { nmap_output: nmapOutput });
  };

  const handleNessusIntegration = (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const nessusData = formData.get('nessus_data');
    
    if (!nessusData.trim()) {
      alert('Please enter Nessus data');
      return;
    }
    
    try {
      const parsedData = JSON.parse(nessusData);
      integrateResults('nessus', { nessus_data: parsedData });
    } catch (error) {
      alert('Invalid JSON format for Nessus data');
    }
  };

  const handleZapIntegration = (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const zapData = formData.get('zap_data');
    
    if (!zapData.trim()) {
      alert('Please enter OWASP ZAP data');
      return;
    }
    
    try {
      const parsedData = JSON.parse(zapData);
      integrateResults('owasp-zap', { zap_data: parsedData });
    } catch (error) {
      alert('Invalid JSON format for ZAP data');
    }
  };

  const handleBurpIntegration = (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const burpData = formData.get('burp_data');
    
    if (!burpData.trim()) {
      alert('Please enter Burp Suite data');
      return;
    }
    
    try {
      const parsedData = JSON.parse(burpData);
      integrateResults('burp', { burp_data: parsedData });
    } catch (error) {
      alert('Invalid JSON format for Burp data');
    }
  };

  const handleCustomIntegration = (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const scannerName = formData.get('scanner_name');
    const results = formData.get('results');
    
    if (!scannerName.trim() || !results.trim()) {
      alert('Please fill in all fields');
      return;
    }
    
    try {
      const parsedResults = JSON.parse(results);
      integrateResults('custom', { 
        scanner_name: scannerName,
        results: parsedResults 
      });
    } catch (error) {
      alert('Invalid JSON format for results');
    }
  };

  const renderNmapForm = () => (
    <form onSubmit={handleNmapIntegration} className="space-y-4">
      <div>
        <label className="block text-gray-400 text-sm mb-2">Nmap Output</label>
        <textarea
          name="nmap_output"
          className="w-full h-32 bg-gray-900 border border-gray-700 text-gray-200 rounded p-3 font-mono text-sm"
          placeholder="Paste Nmap output here..."
          required
        />
      </div>
      <button
        type="submit"
        disabled={loading}
        className="w-full bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded disabled:opacity-50"
      >
        {loading ? 'Integrating...' : 'Integrate Nmap Results'}
      </button>
    </form>
  );

  const renderNessusForm = () => (
    <form onSubmit={handleNessusIntegration} className="space-y-4">
      <div>
        <label className="block text-gray-400 text-sm mb-2">Nessus JSON Data</label>
        <textarea
          name="nessus_data"
          className="w-full h-32 bg-gray-900 border border-gray-700 text-gray-200 rounded p-3 font-mono text-sm"
          placeholder='{"vulnerabilities": [{"plugin_name": "SSH", "severity": "Medium", ...}]}'
          required
        />
      </div>
      <button
        type="submit"
        disabled={loading}
        className="w-full bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded disabled:opacity-50"
      >
        {loading ? 'Integrating...' : 'Integrate Nessus Results'}
      </button>
    </form>
  );

  const renderZapForm = () => (
    <form onSubmit={handleZapIntegration} className="space-y-4">
      <div>
        <label className="block text-gray-400 text-sm mb-2">OWASP ZAP JSON Data</label>
        <textarea
          name="zap_data"
          className="w-full h-32 bg-gray-900 border border-gray-700 text-gray-200 rounded p-3 font-mono text-sm"
          placeholder='{"alerts": [{"name": "XSS", "risk": "High", ...}]}'
          required
        />
      </div>
      <button
        type="submit"
        disabled={loading}
        className="w-full bg-orange-600 hover:bg-orange-700 text-white py-2 px-4 rounded disabled:opacity-50"
      >
        {loading ? 'Integrating...' : 'Integrate ZAP Results'}
      </button>
    </form>
  );

  const renderBurpForm = () => (
    <form onSubmit={handleBurpIntegration} className="space-y-4">
      <div>
        <label className="block text-gray-400 text-sm mb-2">Burp Suite JSON Data</label>
        <textarea
          name="burp_data"
          className="w-full h-32 bg-gray-900 border border-gray-700 text-gray-200 rounded p-3 font-mono text-sm"
          placeholder='{"issues": [{"name": "SQL Injection", "severity": "High", ...}]}'
          required
        />
      </div>
      <button
        type="submit"
        disabled={loading}
        className="w-full bg-purple-600 hover:bg-purple-700 text-white py-2 px-4 rounded disabled:opacity-50"
      >
        {loading ? 'Integrating...' : 'Integrate Burp Results'}
      </button>
    </form>
  );

  const renderCustomForm = () => (
    <form onSubmit={handleCustomIntegration} className="space-y-4">
      <div>
        <label className="block text-gray-400 text-sm mb-2">Scanner Name</label>
        <input
          name="scanner_name"
          type="text"
          className="w-full bg-gray-900 border border-gray-700 text-gray-200 rounded p-3"
          placeholder="e.g., Custom Scanner v1.0"
          required
        />
      </div>
      <div>
        <label className="block text-gray-400 text-sm mb-2">Results JSON</label>
        <textarea
          name="results"
          className="w-full h-32 bg-gray-900 border border-gray-700 text-gray-200 rounded p-3 font-mono text-sm"
          placeholder='{"findings": [{"type": "XSS", "severity": "high", ...}]}'
          required
        />
      </div>
      <button
        type="submit"
        disabled={loading}
        className="w-full bg-gray-600 hover:bg-gray-700 text-white py-2 px-4 rounded disabled:opacity-50"
      >
        {loading ? 'Integrating...' : 'Integrate Custom Results'}
      </button>
    </form>
  );

  if (!currentScanId) {
    return (
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
        <h2 className="text-xl font-bold text-white mb-4 flex items-center">
          <span className="mr-2">🔗</span>
          Scanner Integration
        </h2>
        <div className="text-center py-8 text-gray-500">
          Start a scan to integrate third-party scanner results
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
      <h2 className="text-xl font-bold text-white mb-4 flex items-center">
        <span className="mr-2">🔗</span>
        Scanner Integration
      </h2>
      
      <div className="mb-4">
        <p className="text-gray-400 text-sm mb-4">
          Integrate results from third-party vulnerability scanners into your current scan.
        </p>
        
        {/* Scanner Tabs */}
        <div className="flex flex-wrap gap-2 mb-4">
          {scanners.map(scanner => (
            <button
              key={scanner.id}
              onClick={() => setActiveTab(scanner.id)}
              className={`px-3 py-2 rounded text-sm ${
                activeTab === scanner.id 
                  ? 'bg-purple-600 text-white' 
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              <span className="mr-1">{scanner.icon}</span>
              {scanner.name}
            </button>
          ))}
        </div>
      </div>

      {/* Active Scanner Form */}
      <div className="bg-gray-900 rounded-lg p-4">
        <div className="mb-4">
          <h3 className="text-white font-semibold mb-2">
            {scanners.find(s => s.id === activeTab)?.icon} {scanners.find(s => s.id === activeTab)?.name}
          </h3>
          <p className="text-gray-400 text-sm">
            {scanners.find(s => s.id === activeTab)?.description}
          </p>
        </div>

        {activeTab === 'nmap' && renderNmapForm()}
        {activeTab === 'nessus' && renderNessusForm()}
        {activeTab === 'owasp-zap' && renderZapForm()}
        {activeTab === 'burp' && renderBurpForm()}
        {activeTab === 'custom' && renderCustomForm()}
      </div>

      {/* Integration Results */}
      {Object.keys(results).length > 0 && (
        <div className="mt-6 bg-gray-900 rounded-lg p-4">
          <h3 className="text-white font-semibold mb-3">Integration Results</h3>
          <div className="space-y-2">
            {Object.entries(results).map(([scanner, result]) => (
              <div key={scanner} className="bg-gray-800 p-3 rounded">
                <div className="flex justify-between items-center">
                  <span className="text-white font-medium capitalize">{scanner}</span>
                  <span className={`px-2 py-1 rounded text-xs ${
                    result.status === 'success' ? 'bg-green-600 text-white' : 'bg-red-600 text-white'
                  }`}>
                    {result.status}
                  </span>
                </div>
                <div className="text-gray-400 text-sm mt-1">
                  {result.message}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Integration Help */}
      <div className="mt-6 bg-blue-900/30 border border-blue-500/50 rounded-lg p-4">
        <h3 className="text-blue-400 font-semibold mb-2">💡 Integration Tips</h3>
        <ul className="text-blue-300 text-sm space-y-1">
          <li>• <strong>Nmap:</strong> Paste raw Nmap output (nmap -sV target)</li>
          <li>• <strong>Nessus:</strong> Export as JSON from Nessus interface</li>
          <li>• <strong>OWASP ZAP:</strong> Use ZAP API or export JSON report</li>
          <li>• <strong>Burp Suite:</strong> Export issues as JSON from Burp</li>
          <li>• <strong>Custom:</strong> Use standard JSON format with findings array</li>
        </ul>
      </div>
    </div>
  );
};

export default ScannerIntegration;


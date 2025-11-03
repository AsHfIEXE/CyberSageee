import React, { useState } from 'react';

const defaultHeaders = `{
  "User-Agent": "CyberSage/2.0",
  "Accept": "*/*"
}`;

const Repeater = ({ currentScanId }) => {
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('');
  const [headers, setHeaders] = useState(defaultHeaders);
  const [body, setBody] = useState('');
  const [loading, setLoading] = useState(false);
  const [tabs, setTabs] = useState([]);
  const [activeTab, setActiveTab] = useState(null);

  const backendUrl = process.env.REACT_APP_BACKEND_URL || `${window.location.protocol}//${window.location.hostname}:5000`;

  const sendRequest = async () => {
    if (!url) return;
    setLoading(true);
    try {
      let parsedHeaders = {};
      try { parsedHeaders = headers ? JSON.parse(headers) : {}; } catch (e) { parsedHeaders = {}; }

      const res = await fetch(`${backendUrl}/api/repeater/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method,
          url,
          headers: parsedHeaders,
          body,
          timeout: 20,
          scan_id: currentScanId || undefined
        })
      });
      const data = await res.json();

      const tab = {
        id: Date.now(),
        name: `${method} ${url}`,
        req: { method, url, headers: parsedHeaders, body },
        res: data.response || { code: 0, headers: {}, body: '', time_ms: 0 }
      };
      setTabs(prev => [tab, ...prev].slice(0, 10));
      setActiveTab(tab.id);
    } catch (e) {
      const tab = {
        id: Date.now(),
        name: `${method} ${url}`,
        req: { method, url },
        res: { code: 0, headers: {}, body: String(e), time_ms: 0 }
      };
      setTabs(prev => [tab, ...prev].slice(0, 10));
      setActiveTab(tab.id);
    } finally {
      setLoading(false);
    }
  };

  const active = tabs.find(t => t.id === activeTab);

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
      <h2 className="text-xl font-bold text-white mb-4 flex items-center">
        <span className="mr-2">🛰️</span>
        Repeater
      </h2>
      <div className="grid grid-cols-1 gap-3 mb-4">
        <div className="flex space-x-2">
          <select className="bg-gray-900 border border-gray-700 text-gray-200 rounded px-2 py-2"
                  value={method} onChange={e => setMethod(e.target.value)}>
            {['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'].map(m => <option key={m}>{m}</option>)}
          </select>
          <input className="flex-1 bg-gray-900 border border-gray-700 text-gray-200 rounded px-3 py-2"
                 placeholder="https://target/path" value={url} onChange={e => setUrl(e.target.value)} />
          <button onClick={sendRequest} disabled={loading}
                  className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded disabled:opacity-50">
            {loading ? 'Sending...' : 'Send'}
          </button>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div>
            <label className="text-gray-400 text-sm">Headers (JSON)</label>
            <textarea className="w-full h-28 bg-gray-900 border border-gray-700 text-gray-200 rounded p-2"
                      value={headers} onChange={e => setHeaders(e.target.value)} />
          </div>
          <div>
            <label className="text-gray-400 text-sm">Body</label>
            <textarea className="w-full h-28 bg-gray-900 border border-gray-700 text-gray-200 rounded p-2"
                      value={body} onChange={e => setBody(e.target.value)} />
          </div>
        </div>
      </div>

      {tabs.length > 0 && (
        <div>
          <div className="flex overflow-x-auto space-x-2 mb-3">
            {tabs.map(t => (
              <button key={t.id}
                      onClick={() => setActiveTab(t.id)}
                      className={`px-3 py-1 rounded text-xs ${activeTab === t.id ? 'bg-purple-700 text-white' : 'bg-gray-700 text-gray-200'}`}>
                {t.name.slice(0, 40)}
              </button>
            ))}
          </div>
          {active && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
              <div className="bg-gray-900 border border-gray-700 rounded p-3">
                <p className="text-gray-400 text-xs mb-2">Request</p>
                <pre className="text-xs text-gray-300 overflow-auto">
{`${active.req.method} ${active.req.url}
${Object.entries(active.req.headers || {}).map(([k,v]) => k+': '+v).join('\n')}

${active.req.body || ''}`}
                </pre>
              </div>
              <div className="bg-gray-900 border border-gray-700 rounded p-3">
                <div className="flex justify-between text-xs text-gray-400 mb-2">
                  <span>Response {active.res.code}</span>
                  <span>{active.res.time_ms} ms</span>
                </div>
                <pre className="text-xs text-gray-300 overflow-auto h-64">
{`${Object.entries(active.res.headers || {}).map(([k,v]) => k+': '+v).join('\n')}

${active.res.body || ''}`}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Repeater;



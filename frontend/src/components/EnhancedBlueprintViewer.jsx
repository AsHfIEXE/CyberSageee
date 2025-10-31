import React, { useState, useEffect, useCallback } from 'react';

const EnhancedBlueprintViewer = ({ scanId }) => {
  const [blueprint, setBlueprint] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeView, setActiveView] = useState('visual');
  const [selectedEndpoint, setSelectedEndpoint] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  
  const backendUrl = process.env.REACT_APP_BACKEND_URL || `${window.location.protocol}//${window.location.hostname}:5000`;

  const loadBlueprint = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch(`${backendUrl}/api/scan/${scanId}/blueprint`);
      const data = await response.json();
      setBlueprint(data);
    } catch (error) {
      console.error('Error loading blueprint:', error);
    } finally {
      setLoading(false);
    }
  }, [backendUrl, scanId]);

  useEffect(() => {
    if (scanId) {
      loadBlueprint();
    }
  }, [scanId, loadBlueprint]);

  if (!scanId) {
    return (
      <div className="bg-gray-900 rounded-xl border border-gray-700 p-8">
        <div className="text-center">
          <div className="text-6xl mb-4">🗺️</div>
          <h3 className="text-white text-xl font-bold mb-2">Application Blueprint</h3>
          <p className="text-gray-400">Start a scan to see the complete application map</p>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="bg-gray-900 rounded-xl border border-gray-700 p-8">
        <div className="text-center">
          <div className="animate-spin text-4xl mb-4">⚙️</div>
          <p className="text-gray-400">Loading blueprint...</p>
        </div>
      </div>
    );
  }

  const views = [
    { id: 'visual', label: 'Visual Map', icon: '🗺️' },
    { id: 'endpoints', label: 'Endpoints', icon: '🔗' },
    { id: 'forms', label: 'Forms & Inputs', icon: '📝' },
    { id: 'tech', label: 'Technology Stack', icon: '⚙️' },
    { id: 'files', label: 'Discovered Files', icon: '📁' }
  ];

  // Extract all endpoints from blueprint
  const getAllEndpoints = () => {
    const endpoints = new Set();
    
    // From robots.txt
    if (blueprint?.blueprint?.robots) {
      blueprint.blueprint.robots.forEach(path => endpoints.add(path));
    }
    
    // From sitemap
    if (blueprint?.blueprint?.sitemap) {
      blueprint.blueprint.sitemap.forEach(url => endpoints.add(url));
    }
    
    // From tree structure
    const extractFromTree = (tree, path = '') => {
      if (!tree) return;
      Object.keys(tree).forEach(key => {
        const newPath = path + '/' + key;
        endpoints.add(newPath);
        if (typeof tree[key] === 'object') {
          extractFromTree(tree[key], newPath);
        }
      });
    };
    
    if (blueprint?.blueprint?.tree) {
      extractFromTree(blueprint.blueprint.tree);
    }
    
    return Array.from(endpoints).filter(e => e.length > 1);
  };

  const endpoints = getAllEndpoints();
  const filteredEndpoints = endpoints.filter(e => 
    e.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-700">
      {/* Header */}
      <div className="p-6 border-b border-gray-700">
        <div className="flex justify-between items-center mb-4">
          <div className="flex items-center space-x-3">
            <div className="text-3xl">🗺️</div>
            <div>
              <h3 className="text-white text-xl font-bold">Application Blueprint</h3>
              <p className="text-gray-400 text-sm">Complete application structure and discovered assets</p>
            </div>
          </div>
          <button
            onClick={loadBlueprint}
            className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg text-sm"
          >
            🔄 Refresh
          </button>
        </div>

        {/* View Tabs */}
        <div className="flex space-x-2 overflow-x-auto">
          {views.map(view => (
            <button
              key={view.id}
              onClick={() => setActiveView(view.id)}
              className={`px-4 py-2 rounded-lg whitespace-nowrap text-sm font-medium transition ${
                activeView === view.id
                  ? 'bg-purple-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              <span className="mr-2">{view.icon}</span>
              {view.label}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="p-6">
        {activeView === 'visual' && (
          <div className="space-y-6">
            {/* Statistics Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-gray-800 rounded-lg p-4 border border-blue-500/30">
                <div className="text-blue-400 text-2xl mb-2">🌐</div>
                <div className="text-2xl font-bold text-white">
                  {blueprint?.osint?.subdomains?.length || 0}
                </div>
                <div className="text-gray-400 text-sm">Subdomains</div>
              </div>
              
              <div className="bg-gray-800 rounded-lg p-4 border border-green-500/30">
                <div className="text-green-400 text-2xl mb-2">🖥️</div>
                <div className="text-2xl font-bold text-white">
                  {blueprint?.osint?.live_hosts?.length || 0}
                </div>
                <div className="text-gray-400 text-sm">Live Hosts</div>
              </div>
              
              <div className="bg-gray-800 rounded-lg p-4 border border-purple-500/30">
                <div className="text-purple-400 text-2xl mb-2">⚙️</div>
                <div className="text-2xl font-bold text-white">
                  {blueprint?.osint?.technologies?.length || 0}
                </div>
                <div className="text-gray-400 text-sm">Technologies</div>
              </div>
              
              <div className="bg-gray-800 rounded-lg p-4 border border-yellow-500/30">
                <div className="text-yellow-400 text-2xl mb-2">🔗</div>
                <div className="text-2xl font-bold text-white">
                  {endpoints.length}
                </div>
                <div className="text-gray-400 text-sm">Endpoints</div>
              </div>
            </div>

            {/* Visual Site Tree */}
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h4 className="text-white font-bold mb-4 flex items-center">
                <span className="mr-2">🌳</span>
                Site Structure Tree
              </h4>
              <div className="bg-gray-950 p-4 rounded-lg max-h-96 overflow-auto">
                <SiteTreeView tree={blueprint?.blueprint?.tree} />
              </div>
            </div>
          </div>
        )}

        {activeView === 'endpoints' && (
          <div className="space-y-4">
            {/* Search */}
            <div className="relative">
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search endpoints..."
                className="w-full bg-gray-800 text-white px-4 py-3 pl-10 rounded-lg border border-gray-700 focus:border-purple-500 focus:outline-none"
              />
              <div className="absolute left-3 top-3.5 text-gray-400">🔍</div>
            </div>

            {/* Endpoints List */}
            <div className="bg-gray-800 rounded-lg border border-gray-700 divide-y divide-gray-700 max-h-96 overflow-y-auto">
              {filteredEndpoints.length === 0 ? (
                <div className="p-8 text-center text-gray-500">
                  <div className="text-4xl mb-2">🔍</div>
                  <div>No endpoints found</div>
                </div>
              ) : (
                filteredEndpoints.map((endpoint, index) => (
                  <div
                    key={index}
                    onClick={() => setSelectedEndpoint(endpoint)}
                    className={`p-4 hover:bg-gray-700 cursor-pointer transition ${
                      selectedEndpoint === endpoint ? 'bg-gray-700' : ''
                    }`}
                  >
                    <div className="flex items-center space-x-3">
                      <div className="text-2xl">
                        {endpoint.includes('api') ? '🔌' :
                         endpoint.includes('admin') ? '🔐' :
                         endpoint.endsWith('.php') ? '🐘' :
                         endpoint.endsWith('.js') ? '📜' :
                         endpoint.endsWith('.css') ? '🎨' : '📄'}
                      </div>
                      <div className="flex-1">
                        <div className="text-white font-mono text-sm">{endpoint}</div>
                        <div className="text-gray-400 text-xs mt-1">
                          {endpoint.includes('api') && <span className="px-2 py-1 bg-blue-600 rounded text-white text-xs mr-2">API</span>}
                          {endpoint.includes('admin') && <span className="px-2 py-1 bg-red-600 rounded text-white text-xs mr-2">Admin</span>}
                          {endpoint.includes('login') && <span className="px-2 py-1 bg-yellow-600 rounded text-white text-xs mr-2">Auth</span>}
                          {endpoint.includes('upload') && <span className="px-2 py-1 bg-green-600 rounded text-white text-xs mr-2">Upload</span>}
                        </div>
                      </div>
                      <div className="text-purple-400">→</div>
                    </div>
                  </div>
                ))
              )}
            </div>

            {/* Endpoint Details */}
            {selectedEndpoint && (
              <div className="bg-gray-800 rounded-lg p-6 border border-purple-500/50">
                <h4 className="text-white font-bold mb-4">Endpoint Details</h4>
                <div className="space-y-3">
                  <div>
                    <div className="text-gray-400 text-sm mb-1">Path</div>
                    <div className="bg-gray-900 p-3 rounded font-mono text-sm text-purple-400 break-all">
                      {selectedEndpoint}
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-400 text-sm mb-1">Type</div>
                    <div className="text-white">
                      {selectedEndpoint.includes('api') ? 'API Endpoint' :
                       selectedEndpoint.includes('admin') ? 'Admin Panel' :
                       selectedEndpoint.endsWith('.php') ? 'PHP Script' :
                       selectedEndpoint.endsWith('.js') ? 'JavaScript File' :
                       'Static Resource'}
                    </div>
                  </div>
                  <button
                    onClick={() => window.open(selectedEndpoint, '_blank')}
                    className="w-full px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg"
                  >
                    🌐 Open in Browser
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {activeView === 'forms' && (
          <div className="space-y-4">
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h4 className="text-white font-bold mb-4 flex items-center">
                <span className="mr-2">📝</span>
                Discovered Forms
              </h4>
              <div className="text-gray-400 text-center py-8">
                <div className="text-4xl mb-2">🔍</div>
                <div>Form discovery data will appear here</div>
                <div className="text-sm mt-2">Start a scan with form interaction enabled</div>
              </div>
            </div>
          </div>
        )}

        {activeView === 'tech' && (
          <div className="space-y-4">
            {/* Technology Stack */}
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h4 className="text-white font-bold mb-4 flex items-center">
                <span className="mr-2">⚙️</span>
                Technology Stack
              </h4>
              
              {blueprint?.osint?.technologies?.length > 0 ? (
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                  {blueprint.osint.technologies.map((tech, index) => (
                    <div
                      key={index}
                      className="bg-gray-900 p-4 rounded-lg border border-gray-700 flex items-center space-x-3"
                    >
                      <div className="text-3xl">
                        {tech.includes('WordPress') ? '📝' :
                         tech.includes('React') ? '⚛️' :
                         tech.includes('Vue') ? '💚' :
                         tech.includes('Angular') ? '🅰️' :
                         tech.includes('PHP') ? '🐘' :
                         tech.includes('Node') ? '🟢' :
                         tech.includes('Python') ? '🐍' :
                         tech.includes('Nginx') ? '🔧' :
                         tech.includes('Apache') ? '🪶' : '⚙️'}
                      </div>
                      <div>
                        <div className="text-white font-semibold">{tech}</div>
                        <div className="text-gray-400 text-xs">Detected</div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center text-gray-500 py-8">
                  <div className="text-4xl mb-2">🔍</div>
                  <div>No technologies detected</div>
                </div>
              )}
            </div>

            {/* Live Hosts */}
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h4 className="text-white font-bold mb-4 flex items-center">
                <span className="mr-2">🖥️</span>
                Live Hosts
              </h4>
              
              {blueprint?.osint?.live_hosts?.length > 0 ? (
                <div className="space-y-2">
                  {blueprint.osint.live_hosts.map((host, index) => (
                    <div key={index} className="bg-gray-900 p-4 rounded-lg border border-gray-700">
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="text-white font-mono text-sm">{host.url || host}</div>
                          {host.server && (
                            <div className="text-gray-400 text-xs mt-1">
                              Server: {host.server}
                            </div>
                          )}
                        </div>
                        {host.status_code && (
                          <span className={`px-2 py-1 rounded text-xs ${
                            host.status_code < 300 ? 'bg-green-600' :
                            host.status_code < 400 ? 'bg-blue-600' : 'bg-yellow-600'
                          } text-white`}>
                            {host.status_code}
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center text-gray-500 py-8">
                  <div className="text-4xl mb-2">🔍</div>
                  <div>No live hosts detected</div>
                </div>
              )}
            </div>
          </div>
        )}

        {activeView === 'files' && (
          <div className="space-y-4">
            {/* Robots.txt */}
            {blueprint?.blueprint?.robots?.length > 0 && (
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h4 className="text-white font-bold mb-4 flex items-center">
                  <span className="mr-2">🤖</span>
                  robots.txt Disallowed Paths
                </h4>
                <div className="bg-gray-900 p-4 rounded-lg max-h-64 overflow-y-auto">
                  {blueprint.blueprint.robots.map((path, index) => (
                    <div key={index} className="text-green-400 font-mono text-sm py-1">
                      Disallow: {path}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Sitemap */}
            {blueprint?.blueprint?.sitemap?.length > 0 && (
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h4 className="text-white font-bold mb-4 flex items-center">
                  <span className="mr-2">🗺️</span>
                  sitemap.xml URLs
                </h4>
                <div className="bg-gray-900 p-4 rounded-lg max-h-64 overflow-y-auto space-y-1">
                  {blueprint.blueprint.sitemap.slice(0, 20).map((url, index) => (
                    <div key={index} className="text-blue-400 font-mono text-sm hover:text-blue-300 cursor-pointer">
                      {url}
                    </div>
                  ))}
                  {blueprint.blueprint.sitemap.length > 20 && (
                    <div className="text-gray-500 text-sm text-center pt-2">
                      ... and {blueprint.blueprint.sitemap.length - 20} more
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* API Definitions */}
            {blueprint?.osint?.api_definitions?.length > 0 && (
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h4 className="text-white font-bold mb-4 flex items-center">
                  <span className="mr-2">📄</span>
                  API Documentation
                </h4>
                <div className="space-y-2">
                  {blueprint.osint.api_definitions.map((api, index) => (
                    <a
                      key={index}
                      href={api}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block bg-gray-900 p-4 rounded-lg border border-gray-700 hover:border-purple-500 transition"
                    >
                      <div className="flex items-center justify-between">
                        <div className="text-purple-400 font-mono text-sm">{api}</div>
                        <div className="text-gray-400">→</div>
                      </div>
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

// Site Tree Component
const SiteTreeView = ({ tree, depth = 0 }) => {
  const [expanded, setExpanded] = useState({});

  if (!tree || typeof tree !== 'object') return null;

  const toggleExpand = (key) => {
    setExpanded(prev => ({ ...prev, [key]: !prev[key] }));
  };

  return (
    <div className="space-y-1">
      {Object.entries(tree).map(([key, value]) => {
        const hasChildren = typeof value === 'object' && Object.keys(value).length > 0;
        const isExpanded = expanded[key];

        return (
          <div key={key} style={{ marginLeft: `${depth * 20}px` }}>
            <div
              onClick={() => hasChildren && toggleExpand(key)}
              className={`flex items-center space-x-2 p-2 rounded hover:bg-gray-800 ${
                hasChildren ? 'cursor-pointer' : ''
              }`}
            >
              {hasChildren && (
                <span className="text-gray-400">
                  {isExpanded ? '📂' : '📁'}
                </span>
              )}
              {!hasChildren && <span className="text-gray-400">📄</span>}
              <span className="text-gray-300 font-mono text-sm">{key}</span>
            </div>
            
            {hasChildren && isExpanded && (
              <SiteTreeView tree={value} depth={depth + 1} />
            )}
          </div>
        );
      })}
    </div>
  );
};

export default EnhancedBlueprintViewer;
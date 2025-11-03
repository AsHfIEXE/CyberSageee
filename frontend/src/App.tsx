import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import { 
  Play, 
  Shield, 
  Zap, 
  History, 
  Settings, 
  Monitor,
  AlertTriangle,
  Code,
  Globe,
  Download,
  Upload,
  Search,
  Filter
} from 'lucide-react';
import './App.css';

// Import our security testing components
import HttpRepeater from './components/HttpRepeater';
import SecurityTester from './components/SecurityTester';
import PayloadManager from './components/PayloadManager';
import VulnerabilityScanner from './components/VulnerabilityScanner';
import ResultsHistory from './components/ResultsHistory';
import ProxySettings from './components/ProxySettings';

interface NavigationItem {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  path: string;
  color: string;
}

const navigationItems: NavigationItem[] = [
  { id: 'repeater', label: 'HTTP Repeater', icon: Play, path: '/repeater', color: 'bg-blue-500' },
  { id: 'security-tester', label: 'Security Tester', icon: Shield, path: '/security', color: 'bg-red-500' },
  { id: 'payloads', label: 'Payload Manager', icon: Zap, path: '/payloads', color: 'bg-yellow-500' },
  { id: 'scanner', label: 'Vulnerability Scanner', icon: Search, path: '/scanner', color: 'bg-green-500' },
  { id: 'results', label: 'Results History', icon: History, path: '/results', color: 'bg-purple-500' },
  { id: 'proxy', label: 'Proxy Settings', icon: Globe, path: '/proxy', color: 'bg-indigo-500' },
];

const Header: React.FC = () => {
  const [isDarkMode, setIsDarkMode] = useState(true);
  const [showExportModal, setShowExportModal] = useState(false);

  return (
    <header className={`${isDarkMode ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'} border-b transition-colors duration-200`}>
      <div className="px-6 py-4">
        <div className="flex items-center justify-between">
          {/* Logo and Title */}
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-gradient-to-br from-red-500 to-blue-500 rounded-lg flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className={`text-2xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                  Security Testing Suite
                </h1>
                <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                  Professional Burp Suite-like security testing platform
                </p>
              </div>
            </div>
          </div>

          {/* Header Actions */}
          <div className="flex items-center space-x-4">
            {/* Export/Import */}
            <button
              onClick={() => setShowExportModal(true)}
              className={`flex items-center space-x-2 px-4 py-2 rounded-lg border transition-colors duration-200 ${
                isDarkMode 
                  ? 'border-gray-600 hover:bg-gray-800 text-gray-300 hover:text-white' 
                  : 'border-gray-300 hover:bg-gray-50 text-gray-700 hover:text-gray-900'
              }`}
            >
              <Download className="w-4 h-4" />
              <span>Export</span>
            </button>

            <button className={`flex items-center space-x-2 px-4 py-2 rounded-lg border transition-colors duration-200 ${
              isDarkMode 
                ? 'border-gray-600 hover:bg-gray-800 text-gray-300 hover:text-white' 
                : 'border-gray-300 hover:bg-gray-50 text-gray-700 hover:text-gray-900'
            }`}>
              <Upload className="w-4 h-4" />
              <span>Import</span>
            </button>

            {/* Dark Mode Toggle */}
            <button
              onClick={() => setIsDarkMode(!isDarkMode)}
              className={`p-2 rounded-lg transition-colors duration-200 ${
                isDarkMode 
                  ? 'bg-gray-800 hover:bg-gray-700 text-gray-300 hover:text-white' 
                  : 'bg-gray-100 hover:bg-gray-200 text-gray-600 hover:text-gray-900'
              }`}
            >
              <Monitor className="w-5 h-5" />
            </button>

            {/* Status Indicator */}
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
              <span className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                Ready
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Export Modal */}
      {showExportModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-lg p-6 max-w-md w-full mx-4`}>
            <h3 className={`text-lg font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-4`}>
              Export Test Results
            </h3>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className={`${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>Format:</span>
                <select className={`px-3 py-2 rounded border ${
                  isDarkMode ? 'bg-gray-700 border-gray-600 text-white' : 'bg-white border-gray-300 text-gray-900'
                }`}>
                  <option value="json">JSON</option>
                  <option value="csv">CSV</option>
                  <option value="pdf">PDF Report</option>
                  <option value="har">HTTP Archive (HAR)</option>
                </select>
              </div>
              <div className="flex space-x-3 pt-4">
                <button
                  onClick={() => setShowExportModal(false)}
                  className={`flex-1 px-4 py-2 rounded-lg border transition-colors duration-200 ${
                    isDarkMode 
                      ? 'border-gray-600 hover:bg-gray-700 text-gray-300' 
                      : 'border-gray-300 hover:bg-gray-50 text-gray-700'
                  }`}
                >
                  Cancel
                </button>
                <button className="flex-1 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors duration-200">
                  Export
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </header>
  );
};

const Sidebar: React.FC = () => {
  const location = useLocation();
  const [isDarkMode] = useState(true);

  return (
    <aside className={`w-64 ${isDarkMode ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'} border-r h-full overflow-y-auto`}>
      <nav className="p-4">
        <div className="space-y-2">
          {navigationItems.map((item) => {
            const isActive = location.pathname === item.path;
            const IconComponent = item.icon;
            
            return (
              <Link
                key={item.id}
                to={item.path}
                className={`flex items-center space-x-3 px-4 py-3 rounded-lg transition-all duration-200 group ${
                  isActive
                    ? 'bg-blue-500 text-white shadow-lg'
                    : isDarkMode
                    ? 'text-gray-300 hover:bg-gray-800 hover:text-white'
                    : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900'
                }`}
              >
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                  isActive ? 'bg-white bg-opacity-20' : `${item.color} bg-opacity-20 group-hover:bg-opacity-30`
                }`}>
                  <IconComponent className={`w-4 h-4 ${isActive ? 'text-white' : isDarkMode ? 'text-gray-300' : 'text-gray-700'}`} />
                </div>
                <span className="font-medium">{item.label}</span>
                {isActive && (
                  <div className="ml-auto w-2 h-2 bg-white rounded-full"></div>
                )}
              </Link>
            );
          })}
        </div>

        {/* Quick Stats */}
        <div className={`mt-8 p-4 rounded-lg ${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-gray-50 border-gray-200'} border`}>
          <h4 className={`text-sm font-semibold ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-3`}>
            Quick Stats
          </h4>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className={`text-xs ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Requests Sent:</span>
              <span className={`text-xs font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>1,247</span>
            </div>
            <div className="flex justify-between">
              <span className={`text-xs ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Vulnerabilities Found:</span>
              <span className="text-xs font-medium text-red-400">23</span>
            </div>
            <div className="flex justify-between">
              <span className={`text-xs ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Tests Passed:</span>
              <span className="text-xs font-medium text-green-400">1,192</span>
            </div>
          </div>
        </div>

        {/* Active Targets */}
        <div className={`mt-6 p-4 rounded-lg ${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-gray-50 border-gray-200'} border`}>
          <h4 className={`text-sm font-semibold ${isDarkMode ? 'text-gray-300' : 'text-gray-700'} mb-3`}>
            Active Targets
          </h4>
          <div className="space-y-2">
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-green-500 rounded-full"></div>
              <span className={`text-xs ${isDarkMode ? 'text-gray-400' : 'text-gray-600'} truncate`}>
                example.com
              </span>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-yellow-500 rounded-full"></div>
              <span className={`text-xs ${isDarkMode ? 'text-gray-400' : 'text-gray-600'} truncate`}>
                test-app.local
              </span>
            </div>
          </div>
        </div>
      </nav>
    </aside>
  );
};

const HomePage: React.FC = () => {
  const [isDarkMode] = useState(true);
  const [recentScans] = useState([
    { id: 1, target: 'https://example.com', status: 'completed', findings: 5, duration: '2m 34s' },
    { id: 2, target: 'https://test-app.local', status: 'running', findings: 2, duration: '5m 12s' },
    { id: 3, target: 'https://vulnerable-site.com', status: 'completed', findings: 12, duration: '8m 45s' },
  ]);

  return (
    <div className="p-6 space-y-6">
      {/* Welcome Section */}
      <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-xl p-6`}>
        <div className="flex items-center justify-between">
          <div>
            <h2 className={`text-2xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-2`}>
              Welcome to Security Testing Suite
            </h2>
            <p className={`${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
              Professional-grade security testing tools for vulnerability assessment and penetration testing
            </p>
          </div>
          <div className="flex space-x-3">
            <Link
              to="/repeater"
              className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors duration-200 flex items-center space-x-2"
            >
              <Play className="w-4 h-4" />
              <span>Start Testing</span>
            </Link>
            <Link
              to="/scanner"
              className="px-4 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg transition-colors duration-200 flex items-center space-x-2"
            >
              <Search className="w-4 h-4" />
              <span>Run Scan</span>
            </Link>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-xl p-6`}>
        <h3 className={`text-lg font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-4`}>
          Recent Scans
        </h3>
        <div className="space-y-3">
          {recentScans.map((scan) => (
            <div key={scan.id} className={`flex items-center justify-between p-3 rounded-lg ${
              isDarkMode ? 'bg-gray-700 hover:bg-gray-650' : 'bg-gray-50 hover:bg-gray-100'
            } transition-colors duration-200`}>
              <div className="flex items-center space-x-3">
                <div className={`w-3 h-3 rounded-full ${
                  scan.status === 'completed' ? 'bg-green-500' : 
                  scan.status === 'running' ? 'bg-yellow-500 animate-pulse' : 'bg-gray-500'
                }`}></div>
                <div>
                  <p className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                    {scan.target}
                  </p>
                  <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                    Duration: {scan.duration}
                  </p>
                </div>
              </div>
              <div className="flex items-center space-x-4">
                <span className={`text-sm ${
                  scan.findings > 0 ? 'text-red-400' : 'text-green-400'
                }`}>
                  {scan.findings} findings
                </span>
                <span className={`text-xs px-2 py-1 rounded ${
                  scan.status === 'completed' ? 'bg-green-100 text-green-800' :
                  scan.status === 'running' ? 'bg-yellow-100 text-yellow-800' :
                  'bg-gray-100 text-gray-800'
                }`}>
                  {scan.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {navigationItems.map((item) => {
          const IconComponent = item.icon;
          return (
            <Link
              key={item.id}
              to={item.path}
              className={`${isDarkMode ? 'bg-gray-800 border-gray-700 hover:bg-gray-750' : 'bg-white border-gray-200 hover:bg-gray-50'} border rounded-xl p-6 transition-all duration-200 hover:scale-105 hover:shadow-lg group`}
            >
              <div className="flex items-center space-x-4">
                <div className={`w-12 h-12 ${item.color} rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform duration-200`}>
                  <IconComponent className="w-6 h-6 text-white" />
                </div>
                <div>
                  <h3 className={`font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-1`}>
                    {item.label}
                  </h3>
                  <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                    {item.id === 'repeater' && 'Build and send HTTP requests with payload injection'}
                    {item.id === 'security-tester' && 'Test for common vulnerabilities and security flaws'}
                    {item.id === 'payloads' && 'Manage and organize security testing payloads'}
                    {item.id === 'scanner' && 'Automated vulnerability scanning and assessment'}
                    {item.id === 'results' && 'View and export test results and reports'}
                    {item.id === 'proxy' && 'Configure proxy settings and network options'}
                  </p>
                </div>
              </div>
            </Link>
          );
        })}
      </div>
    </div>
  );
};

function App() {
  const [isDarkMode] = useState(true);

  return (
    <Router>
      <div className={`min-h-screen ${isDarkMode ? 'bg-gray-950 text-white' : 'bg-gray-50 text-gray-900'}`}>
        <Header />
        <div className="flex">
          <Sidebar />
          <main className="flex-1 overflow-y-auto">
            <Routes>
              <Route path="/" element={<HomePage />} />
              <Route path="/repeater" element={<HttpRepeater />} />
              <Route path="/security" element={<SecurityTester />} />
              <Route path="/payloads" element={<PayloadManager />} />
              <Route path="/scanner" element={<VulnerabilityScanner />} />
              <Route path="/results" element={<ResultsHistory />} />
              <Route path="/proxy" element={<ProxySettings />} />
            </Routes>
          </main>
        </div>
      </div>
    </Router>
  );
}

export default App;
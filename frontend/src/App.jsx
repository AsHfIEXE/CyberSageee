import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Target, 
  Search, 
  BarChart3, 
  Settings, 
  Wifi,
  AlertTriangle,
  CheckCircle,
  Activity,
  Zap,
  Globe,
  Scan,
  FileText,
  History,
  Users
} from 'lucide-react';
import './App.css';

// Mock components for demonstration
const Dashboard = () => (
  <div className="p-6">
    <h2 className="text-2xl font-bold text-white mb-4">Dashboard</h2>
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
      <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-gray-400">Active Scans</p>
            <p className="text-2xl font-bold text-green-400">3</p>
          </div>
          <Activity className="text-green-400" size={32} />
        </div>
      </div>
      <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-gray-400">Vulnerabilities Found</p>
            <p className="text-2xl font-bold text-red-400">24</p>
          </div>
          <AlertTriangle className="text-red-400" size={32} />
        </div>
      </div>
      <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-gray-400">Targets Scanned</p>
            <p className="text-2xl font-bold text-blue-400">156</p>
          </div>
          <Target className="text-blue-400" size={32} />
        </div>
      </div>
      <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-gray-400">Critical Issues</p>
            <p className="text-2xl font-bold text-red-500">7</p>
          </div>
          <AlertTriangle className="text-red-500" size={32} />
        </div>
      </div>
      <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-gray-400">Systems Monitored</p>
            <p className="text-2xl font-bold text-cyan-400">89</p>
          </div>
          <Globe className="text-cyan-400" size={32} />
        </div>
      </div>
      <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-gray-400">Success Rate</p>
            <p className="text-2xl font-bold text-green-400">94%</p>
          </div>
          <CheckCircle className="text-green-400" size={32} />
        </div>
      </div>
    </div>
  </div>
);

const Scanner = () => (
  <div className="p-6">
    <h2 className="text-2xl font-bold text-white mb-4">Network Scanner</h2>
    <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
      <div className="mb-4">
        <label className="block text-sm font-medium text-gray-300 mb-2">
          Target IP/Range
        </label>
        <input
          type="text"
          placeholder="192.168.1.0/24"
          className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-green-500"
        />
      </div>
      <div className="mb-4">
        <label className="block text-sm font-medium text-gray-300 mb-2">
          Scan Type
        </label>
        <select className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-green-500">
          <option>Quick Scan</option>
          <option>Comprehensive Scan</option>
          <option>Stealth Scan</option>
          <option>Aggressive Scan</option>
        </select>
      </div>
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Port Range
          </label>
          <input
            type="text"
            placeholder="1-1000"
            className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-green-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Timeout (seconds)
          </label>
          <input
            type="number"
            placeholder="30"
            className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-green-500"
          />
        </div>
      </div>
      <button className="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded transition duration-200">
        <Zap className="inline mr-2" size={16} />
        Start Scan
      </button>
    </div>
  </div>
);

const Vulnerabilities = () => (
  <div className="p-6">
    <h2 className="text-2xl font-bold text-white mb-4">Vulnerabilities</h2>
    <div className="space-y-4">
      <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-white">SQL Injection</h3>
            <p className="text-gray-400">Target: 192.168.1.100</p>
            <p className="text-sm text-red-400">Critical - CVSS: 9.8</p>
          </div>
          <div className="text-red-500">
            <AlertTriangle size={24} />
          </div>
        </div>
      </div>
      <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-white">XSS Vulnerability</h3>
            <p className="text-gray-400">Target: 192.168.1.105</p>
            <p className="text-sm text-yellow-400">High - CVSS: 7.2</p>
          </div>
          <div className="text-yellow-500">
            <AlertTriangle size={24} />
          </div>
        </div>
      </div>
      <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-white">Open Port 22</h3>
            <p className="text-gray-400">Target: 192.168.1.200</p>
            <p className="text-sm text-green-400">Info - CVSS: 0.0</p>
          </div>
          <div className="text-green-500">
            <CheckCircle size={24} />
          </div>
        </div>
      </div>
    </div>
  </div>
);

const Targets = () => (
  <div className="p-6">
    <h2 className="text-2xl font-bold text-white mb-4">Targets</h2>
    <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-700">
        <div className="flex justify-between items-center">
          <h3 className="text-lg font-semibold text-white">Discovered Targets</h3>
          <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded">
            + Add Target
          </button>
        </div>
      </div>
      <div className="divide-y divide-gray-700">
        <div className="px-6 py-4 hover:bg-gray-750">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-white font-medium">192.168.1.100</p>
              <p className="text-gray-400 text-sm">Ubuntu Server 20.04</p>
            </div>
            <div className="text-green-400">
              <CheckCircle size={20} />
            </div>
          </div>
        </div>
        <div className="px-6 py-4 hover:bg-gray-750">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-white font-medium">192.168.1.105</p>
              <p className="text-gray-400 text-sm">Windows Server 2019</p>
            </div>
            <div className="text-yellow-400">
              <AlertTriangle size={20} />
            </div>
          </div>
        </div>
        <div className="px-6 py-4 hover:bg-gray-750">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-white font-medium">192.168.1.200</p>
              <p className="text-gray-400 text-sm">Router - TP-Link Archer</p>
            </div>
            <div className="text-red-400">
              <AlertTriangle size={20} />
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
);

const History = () => (
  <div className="p-6">
    <h2 className="text-2xl font-bold text-white mb-4">Scan History</h2>
    <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-700">
        <div className="flex justify-between items-center">
          <h3 className="text-lg font-semibold text-white">Recent Scans</h3>
          <div className="flex space-x-2">
            <button className="bg-gray-600 hover:bg-gray-700 text-white px-3 py-1 rounded text-sm">
              All
            </button>
            <button className="bg-gray-600 hover:bg-gray-700 text-white px-3 py-1 rounded text-sm">
              Critical
            </button>
            <button className="bg-gray-600 hover:bg-gray-700 text-white px-3 py-1 rounded text-sm">
              High
            </button>
          </div>
        </div>
      </div>
      <div className="divide-y divide-gray-700">
        <div className="px-6 py-4 hover:bg-gray-750">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-white font-medium">Network Discovery Scan</p>
              <p className="text-gray-400 text-sm">192.168.1.0/24 • Completed 2 hours ago</p>
            </div>
            <div className="text-green-400">
              <CheckCircle size={20} />
            </div>
          </div>
        </div>
        <div className="px-6 py-4 hover:bg-gray-750">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-white font-medium">Vulnerability Assessment</p>
              <p className="text-gray-400 text-sm">192.168.1.100 • Completed 5 hours ago</p>
            </div>
            <div className="text-red-400">
              <AlertTriangle size={20} />
            </div>
          </div>
        </div>
        <div className="px-6 py-4 hover:bg-gray-750">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-white font-medium">Web Application Scan</p>
              <p className="text-gray-400 text-sm">192.168.1.105 • Completed 1 day ago</p>
            </div>
            <div className="text-yellow-400">
              <AlertTriangle size={20} />
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
);

const App = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [connectionStatus, setConnectionStatus] = useState('connected');
  const [scanProgress, setScanProgress] = useState(0);

  useEffect(() => {
    // Simulate connection status check
    const checkConnection = () => {
      setConnectionStatus(Math.random() > 0.1 ? 'connected' : 'disconnected');
    };
    
    checkConnection();
    const interval = setInterval(checkConnection, 10000);
    return () => clearInterval(interval);
  }, []);

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
    { id: 'scanner', label: 'Scanner', icon: Search },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: Shield },
    { id: 'targets', label: 'Targets', icon: Target },
    { id: 'history', label: 'History', icon: FileText },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <Shield className="text-green-400 mr-3" size={32} />
              <div>
                <h1 className="text-xl font-bold">CyberSage 2.0</h1>
                <p className="text-sm text-gray-400">Elite Vulnerability Intelligence</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className={`flex items-center ${connectionStatus === 'connected' ? 'text-green-400' : 'text-red-400'}`}>
                <div className={`w-2 h-2 rounded-full mr-2 ${connectionStatus === 'connected' ? 'bg-green-400' : 'bg-red-400'}`}></div>
                {connectionStatus === 'connected' ? 'Connected' : 'Disconnected'}
              </div>
              <Wifi className="text-gray-400" size={20} />
              <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded flex items-center">
                <Scan className="mr-2" size={16} />
                Quick Scan
              </button>
            </div>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <nav className="w-64 bg-gray-800 min-h-screen">
          <div className="p-4">
            <ul className="space-y-2">
              {navItems.map((item) => {
                const Icon = item.icon;
                return (
                  <li key={item.id}>
                    <button
                      onClick={() => setActiveTab(item.id)}
                      className={`w-full flex items-center px-4 py-3 rounded-lg transition duration-200 ${
                        activeTab === item.id
                          ? 'bg-green-600 text-white'
                          : 'text-gray-300 hover:bg-gray-700 hover:text-white'
                      }`}
                    >
                      <Icon className="mr-3" size={20} />
                      {item.label}
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        </nav>

        {/* Main Content */}
        <main className="flex-1">
          {activeTab === 'dashboard' && <Dashboard />}
          {activeTab === 'scanner' && <Scanner />}
          {activeTab === 'vulnerabilities' && <Vulnerabilities />}
          {activeTab === 'targets' && <Targets />}
          {activeTab === 'history' && <History />}
          {activeTab === 'settings' && (
            <div className="p-6">
              <h2 className="text-2xl font-bold text-white mb-4">Settings</h2>
              <div className="bg-gray-800 p-6 rounded-lg border border-gray-700">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Scan Timeout (seconds)
                    </label>
                    <input
                      type="number"
                      defaultValue="30"
                      className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-green-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Max Concurrent Scans
                    </label>
                    <input
                      type="number"
                      defaultValue="5"
                      className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-green-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Notification Email
                    </label>
                    <input
                      type="email"
                      placeholder="admin@example.com"
                      className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-green-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Auto Scan Schedule
                    </label>
                    <select className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-green-500">
                      <option>Daily</option>
                      <option>Weekly</option>
                      <option>Monthly</option>
                      <option>Disabled</option>
                    </select>
                  </div>
                </div>
                <div className="mt-6">
                  <button className="bg-green-600 hover:bg-green-700 text-white px-6 py-2 rounded">
                    Save Settings
                  </button>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
};

export default App;
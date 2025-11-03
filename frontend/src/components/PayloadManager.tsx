import React, { useState, useEffect } from 'react';
import { 
  Zap, 
  Plus, 
  Edit, 
  Trash2, 
  Copy, 
  Download, 
  Upload,
  Search,
  Filter,
  Tag,
  Code,
  Eye,
  EyeOff,
  Save,
  FolderOpen,
  Star,
  Clock,
  AlertTriangle,
  TrendingUp
} from 'lucide-react';

// Types
interface Payload {
  id: string;
  name: string;
  category: string;
  type: 'xss' | 'sqli' | 'command' | 'path-traversal' | 'lfi' | 'rfi' | 'ssrf' | 'xxe' | 'ldap' | 'custom';
  content: string;
  encoding: 'raw' | 'url' | 'base64' | 'html' | 'double-url';
  description: string;
  tags: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  createdAt: Date;
  lastUsed?: Date;
  usageCount: number;
  isFavorite: boolean;
}

interface PayloadCategory {
  id: string;
  name: string;
  description: string;
  icon: string;
  color: string;
  payloadCount: number;
}

const PayloadManager: React.FC = () => {
  const [isDarkMode] = useState(true);
  const [payloads, setPayloads] = useState<Payload[]>([]);
  const [categories, setCategories] = useState<PayloadCategory[]>([]);
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedRiskLevel, setSelectedRiskLevel] = useState('all');
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingPayload, setEditingPayload] = useState<Payload | null>(null);
  const [showDetails, setShowDetails] = useState<string | null>(null);
  const [selectedPayloads, setSelectedPayloads] = useState<string[]>([]);

  // Predefined payload categories
  const defaultCategories: PayloadCategory[] = [
    { id: 'xss', name: 'Cross-Site Scripting', description: 'XSS payloads for testing web application security', icon: '🔍', color: 'bg-red-500', payloadCount: 0 },
    { id: 'sqli', name: 'SQL Injection', description: 'SQL injection payloads for database testing', icon: '🗄️', color: 'bg-orange-500', payloadCount: 0 },
    { id: 'command', name: 'Command Injection', description: 'OS command injection payloads', icon: '💻', color: 'bg-yellow-500', payloadCount: 0 },
    { id: 'path-traversal', name: 'Path Traversal', description: 'Local and remote file inclusion payloads', icon: '📁', color: 'bg-green-500', payloadCount: 0 },
    { id: 'ssrf', name: 'Server-Side Request Forgery', description: 'SSRF testing payloads', icon: '🌐', color: 'bg-blue-500', payloadCount: 0 },
    { id: 'xxe', name: 'XML External Entity', description: 'XXE injection payloads', icon: '📄', color: 'bg-indigo-500', payloadCount: 0 },
    { id: 'ldap', name: 'LDAP Injection', description: 'LDAP injection testing payloads', icon: '🔗', color: 'bg-purple-500', payloadCount: 0 },
    { id: 'custom', name: 'Custom Payloads', description: 'User-defined and custom payloads', icon: '⭐', color: 'bg-gray-500', payloadCount: 0 }
  ];

  // Default payloads
  const defaultPayloads: Payload[] = [
    // XSS Payloads
    {
      id: 'xss_1',
      name: 'Basic Script Alert',
      category: 'xss',
      type: 'xss',
      content: '<script>alert(1)</script>',
      encoding: 'raw',
      description: 'Basic XSS payload that executes JavaScript alert',
      tags: ['basic', 'alert', 'script'],
      riskLevel: 'high',
      createdAt: new Date('2024-01-01'),
      lastUsed: new Date('2024-01-15'),
      usageCount: 25,
      isFavorite: true
    },
    {
      id: 'xss_2',
      name: 'Image Error Handler',
      category: 'xss',
      type: 'xss',
      content: '<img src=x onerror=alert(1)>',
      encoding: 'raw',
      description: 'XSS payload using image error event handler',
      tags: ['image', 'onerror', 'handler'],
      riskLevel: 'high',
      createdAt: new Date('2024-01-01'),
      usageCount: 18,
      isFavorite: false
    },
    {
      id: 'xss_3',
      name: 'SVG Onload',
      category: 'xss',
      type: 'xss',
      content: '<svg/onload=alert(1)>',
      encoding: 'raw',
      description: 'SVG-based XSS payload with onload event',
      tags: ['svg', 'onload', 'vector'],
      riskLevel: 'high',
      createdAt: new Date('2024-01-01'),
      usageCount: 12,
      isFavorite: false
    },

    // SQL Injection Payloads
    {
      id: 'sqli_1',
      name: 'Basic Quote',
      category: 'sqli',
      type: 'sqli',
      content: "'",
      encoding: 'raw',
      description: 'Basic SQL injection payload to test for SQL syntax errors',
      tags: ['basic', 'quote', 'syntax'],
      riskLevel: 'medium',
      createdAt: new Date('2024-01-01'),
      usageCount: 30,
      isFavorite: true
    },
    {
      id: 'sqli_2',
      name: 'OR 1=1 Union',
      category: 'sqli',
      type: 'sqli',
      content: "' OR '1'='1",
      encoding: 'raw',
      description: 'Classic SQL injection payload using OR logic',
      tags: ['or', 'union', 'classic'],
      riskLevel: 'high',
      createdAt: new Date('2024-01-01'),
      usageCount: 22,
      isFavorite: true
    },
    {
      id: 'sqli_3',
      name: 'Union Select Null',
      category: 'sqli',
      type: 'sqli',
      content: "' UNION SELECT NULL--",
      encoding: 'raw',
      description: 'UNION-based SQL injection payload',
      tags: ['union', 'select', 'null'],
      riskLevel: 'high',
      createdAt: new Date('2024-01-01'),
      usageCount: 15,
      isFavorite: false
    },

    // Command Injection Payloads
    {
      id: 'cmd_1',
      name: 'Semicolon Command',
      category: 'command',
      type: 'command',
      content: '; ls -la',
      encoding: 'raw',
      description: 'Command injection using semicolon separator',
      tags: ['semicolon', 'linux', 'list'],
      riskLevel: 'critical',
      createdAt: new Date('2024-01-01'),
      usageCount: 20,
      isFavorite: true
    },
    {
      id: 'cmd_2',
      name: 'WhoAmI Execution',
      category: 'command',
      type: 'command',
      content: '; whoami',
      encoding: 'raw',
      description: 'Command injection to execute whoami command',
      tags: ['whoami', 'identity', 'execution'],
      riskLevel: 'critical',
      createdAt: new Date('2024-01-01'),
      usageCount: 16,
      isFavorite: false
    },

    // Path Traversal Payloads
    {
      id: 'pt_1',
      name: 'Unix Passwd',
      category: 'path-traversal',
      type: 'path-traversal',
      content: '../../../etc/passwd',
      encoding: 'raw',
      description: 'Path traversal to access Unix password file',
      tags: ['unix', 'passwd', 'system'],
      riskLevel: 'critical',
      createdAt: new Date('2024-01-01'),
      usageCount: 28,
      isFavorite: true
    },
    {
      id: 'pt_2',
      name: 'Windows System',
      category: 'path-traversal',
      type: 'path-traversal',
      content: '..\\..\\..\\windows\\win.ini',
      encoding: 'raw',
      description: 'Path traversal for Windows system files',
      tags: ['windows', 'system', 'ini'],
      riskLevel: 'critical',
      createdAt: new Date('2024-01-01'),
      usageCount: 14,
      isFavorite: false
    },

    // SSRF Payloads
    {
      id: 'ssrf_1',
      name: 'AWS Metadata',
      category: 'ssrf',
      type: 'ssrf',
      content: 'http://169.254.169.254/latest/meta-data/',
      encoding: 'raw',
      description: 'SSRF payload targeting AWS instance metadata',
      tags: ['aws', 'metadata', 'cloud'],
      riskLevel: 'critical',
      createdAt: new Date('2024-01-01'),
      usageCount: 10,
      isFavorite: true
    },
    {
      id: 'ssrf_2',
      name: 'Localhost Probe',
      category: 'ssrf',
      type: 'ssrf',
      content: 'http://127.0.0.1:80',
      encoding: 'raw',
      description: 'SSRF payload to probe localhost services',
      tags: ['localhost', 'probe', 'internal'],
      riskLevel: 'high',
      createdAt: new Date('2024-01-01'),
      usageCount: 8,
      isFavorite: false
    }
  ];

  // Initialize data
  useEffect(() => {
    const savedPayloads = localStorage.getItem('payloadManager_payloads');
    const savedCategories = localStorage.getItem('payloadManager_categories');

    if (savedPayloads) {
      try {
        const parsed = JSON.parse(savedPayloads);
        // Convert date strings back to Date objects
        const payloadsWithDates = parsed.map((p: any) => ({
          ...p,
          createdAt: new Date(p.createdAt),
          lastUsed: p.lastUsed ? new Date(p.lastUsed) : undefined
        }));
        setPayloads(payloadsWithDates);
      } catch (e) {
        console.error('Failed to load saved payloads:', e);
        setPayloads(defaultPayloads);
      }
    } else {
      setPayloads(defaultPayloads);
    }

    if (savedCategories) {
      try {
        setCategories(JSON.parse(savedCategories));
      } catch (e) {
        setCategories(defaultCategories);
      }
    } else {
      setCategories(defaultCategories);
    }
  }, []);

  // Save to localStorage
  useEffect(() => {
    localStorage.setItem('payloadManager_payloads', JSON.stringify(payloads));
  }, [payloads]);

  useEffect(() => {
    localStorage.setItem('payloadManager_categories', JSON.stringify(categories));
  }, [categories]);

  // Update category payload counts
  useEffect(() => {
    const updatedCategories = categories.map(category => ({
      ...category,
      payloadCount: payloads.filter(p => p.category === category.id).length
    }));
    setCategories(updatedCategories);
  }, [payloads]);

  // Filter payloads
  const filteredPayloads = payloads.filter(payload => {
    const matchesCategory = selectedCategory === 'all' || payload.category === selectedCategory;
    const matchesSearch = payload.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         payload.content.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         payload.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         payload.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesRisk = selectedRiskLevel === 'all' || payload.riskLevel === selectedRiskLevel;
    return matchesCategory && matchesSearch && matchesRisk;
  });

  // Generate encoded versions of payload
  const encodePayload = (content: string, encoding: string): string => {
    switch (encoding) {
      case 'url':
        return encodeURIComponent(content);
      case 'double-url':
        return encodeURIComponent(encodeURIComponent(content));
      case 'base64':
        return btoa(content);
      case 'html':
        return content.replace(/</g, '&lt;').replace(/>/g, '&gt;');
      default:
        return content;
    }
  };

  // Copy payload to clipboard
  const copyToClipboard = async (content: string) => {
    try {
      await navigator.clipboard.writeText(content);
      // Show success feedback
    } catch (e) {
      console.error('Failed to copy payload:', e);
    }
  };

  // Toggle favorite
  const toggleFavorite = (id: string) => {
    setPayloads(prev => prev.map(p => p.id === id ? { ...p, isFavorite: !p.isFavorite } : p));
  };

  // Delete payload
  const deletePayload = (id: string) => {
    setPayloads(prev => prev.filter(p => p.id !== id));
  };

  // Update usage count
  const incrementUsage = (id: string) => {
    setPayloads(prev => prev.map(p => 
      p.id === id 
        ? { ...p, usageCount: p.usageCount + 1, lastUsed: new Date() }
        : p
    ));
  };

  // Bulk operations
  const deleteSelected = () => {
    setPayloads(prev => prev.filter(p => !selectedPayloads.includes(p.id)));
    setSelectedPayloads([]);
  };

  const exportSelected = () => {
    const selected = payloads.filter(p => selectedPayloads.includes(p.id));
    const dataStr = JSON.stringify(selected, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    
    const exportFileDefaultName = 'security_payloads.json';
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical': return 'text-red-400 bg-red-500/20';
      case 'high': return 'text-orange-400 bg-orange-500/20';
      case 'medium': return 'text-yellow-400 bg-yellow-500/20';
      case 'low': return 'text-blue-400 bg-blue-500/20';
      default: return 'text-gray-400 bg-gray-500/20';
    }
  };

  const getCategoryIcon = (categoryId: string) => {
    const category = categories.find(c => c.id === categoryId);
    return category?.icon || '📁';
  };

  return (
    <div className={`min-h-screen ${isDarkMode ? 'bg-gray-950' : 'bg-gray-50'}`}>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className={`text-3xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-2`}>
              Payload Manager
            </h1>
            <p className={`${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
              Organize and manage security testing payloads with encoding options
            </p>
          </div>
          <div className="flex items-center space-x-3">
            {selectedPayloads.length > 0 && (
              <>
                <button
                  onClick={exportSelected}
                  className="px-4 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg flex items-center space-x-2"
                >
                  <Download className="w-4 h-4" />
                  <span>Export ({selectedPayloads.length})</span>
                </button>
                <button
                  onClick={deleteSelected}
                  className="px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg flex items-center space-x-2"
                >
                  <Trash2 className="w-4 h-4" />
                  <span>Delete ({selectedPayloads.length})</span>
                </button>
              </>
            )}
            <button
              onClick={() => setShowAddModal(true)}
              className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg flex items-center space-x-2"
            >
              <Plus className="w-4 h-4" />
              <span>Add Payload</span>
            </button>
          </div>
        </div>

        {/* Categories Overview */}
        <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-xl p-6`}>
          <h2 className={`text-xl font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'} mb-4`}>
            Payload Categories
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {categories.map((category) => (
              <div
                key={category.id}
                className={`p-4 rounded-lg border cursor-pointer transition-colors ${
                  selectedCategory === category.id
                    ? `${category.color} text-white border-transparent`
                    : isDarkMode
                    ? 'bg-gray-700 border-gray-600 text-gray-300 hover:bg-gray-650'
                    : 'bg-gray-50 border-gray-200 text-gray-700 hover:bg-gray-100'
                }`}
                onClick={() => setSelectedCategory(selectedCategory === category.id ? 'all' : category.id)}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-2xl">{category.icon}</span>
                  <span className={`text-xs px-2 py-1 rounded ${
                    selectedCategory === category.id
                      ? 'bg-white bg-opacity-20'
                      : isDarkMode
                      ? 'bg-gray-600 text-gray-300'
                      : 'bg-gray-200 text-gray-600'
                  }`}>
                    {category.payloadCount}
                  </span>
                </div>
                <h3 className="font-medium text-sm">{category.name}</h3>
                <p className={`text-xs mt-1 ${
                  selectedCategory === category.id
                    ? 'text-white text-opacity-80'
                    : isDarkMode
                    ? 'text-gray-400'
                    : 'text-gray-600'
                }`}>
                  {category.description}
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* Search and Filters */}
        <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-xl p-6`}>
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div className="flex-1 relative">
              <Search className={`absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 ${
                isDarkMode ? 'text-gray-400' : 'text-gray-500'
              }`} />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search payloads by name, content, description, or tags..."
                className={`w-full pl-10 pr-4 py-2 rounded-lg border ${
                  isDarkMode
                    ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400'
                    : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'
                }`}
              />
            </div>
            <select
              value={selectedRiskLevel}
              onChange={(e) => setSelectedRiskLevel(e.target.value)}
              className={`px-4 py-2 rounded-lg border ${
                isDarkMode
                  ? 'bg-gray-700 border-gray-600 text-white'
                  : 'bg-white border-gray-300 text-gray-900'
              }`}
            >
              <option value="all">All Risk Levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>

        {/* Payloads List */}
        <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-xl overflow-hidden`}>
          <div className={`p-4 border-b ${isDarkMode ? 'border-gray-700' : 'border-gray-200'}`}>
            <div className="flex items-center justify-between">
              <h2 className={`text-xl font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                Security Payloads ({filteredPayloads.length})
              </h2>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setSelectedPayloads(payloads.map(p => p.id))}
                  className={`px-3 py-1 rounded text-sm ${
                    isDarkMode
                      ? 'bg-gray-600 hover:bg-gray-500 text-gray-300'
                      : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
                  }`}
                >
                  Select All
                </button>
                <button
                  onClick={() => setSelectedPayloads([])}
                  className={`px-3 py-1 rounded text-sm ${
                    isDarkMode
                      ? 'bg-gray-600 hover:bg-gray-500 text-gray-300'
                      : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
                  }`}
                >
                  Clear
                </button>
              </div>
            </div>
          </div>

          <div className="divide-y divide-gray-700">
            {filteredPayloads.map((payload) => (
              <div key={payload.id} className={`p-4 hover:bg-opacity-50 transition-colors ${
                isDarkMode ? 'hover:bg-gray-750' : 'hover:bg-gray-50'
              }`}>
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-4 flex-1">
                    {/* Selection Checkbox */}
                    <input
                      type="checkbox"
                      checked={selectedPayloads.includes(payload.id)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedPayloads(prev => [...prev, payload.id]);
                        } else {
                          setSelectedPayloads(prev => prev.filter(id => id !== payload.id));
                        }
                      }}
                      className="mt-1"
                    />

                    {/* Payload Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center space-x-2 mb-2">
                        <span className="text-lg">{getCategoryIcon(payload.category)}</span>
                        <h3 className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                          {payload.name}
                        </h3>
                        {payload.isFavorite && (
                          <Star className="w-4 h-4 text-yellow-400 fill-current" />
                        )}
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskColor(payload.riskLevel)}`}>
                          {payload.riskLevel.toUpperCase()}
                        </span>
                      </div>
                      
                      <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'} mb-2`}>
                        {payload.description}
                      </p>

                      <div className="flex items-center space-x-4 mb-3">
                        <span className={`text-xs px-2 py-1 rounded ${
                          isDarkMode ? 'bg-gray-600 text-gray-300' : 'bg-gray-100 text-gray-600'
                        }`}>
                          {payload.category}
                        </span>
                        <span className={`text-xs ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                          Used {payload.usageCount} times
                        </span>
                        {payload.lastUsed && (
                          <span className={`text-xs ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                            Last used: {payload.lastUsed.toLocaleDateString()}
                          </span>
                        )}
                      </div>

                      {/* Payload Content */}
                      <div className="space-y-2">
                        <div className="flex items-center space-x-2">
                          <code className={`flex-1 p-2 rounded text-sm font-mono ${
                            isDarkMode ? 'bg-gray-900 text-green-400' : 'bg-gray-100 text-green-600'
                          }`}>
                            {payload.content}
                          </code>
                          <button
                            onClick={() => copyToClipboard(payload.content)}
                            className={`p-2 rounded transition-colors ${
                              isDarkMode
                                ? 'text-gray-400 hover:text-white hover:bg-gray-700'
                                : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                            }`}
                          >
                            <Copy className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => setShowDetails(showDetails === payload.id ? null : payload.id)}
                            className={`p-2 rounded transition-colors ${
                              isDarkMode
                                ? 'text-gray-400 hover:text-white hover:bg-gray-700'
                                : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                            }`}
                          >
                            {showDetails === payload.id ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                          </button>
                        </div>

                        {/* Encoded Versions */}
                        {showDetails === payload.id && (
                          <div className="space-y-2">
                            <h4 className={`text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                              Encoded Versions:
                            </h4>
                            {['url', 'base64', 'html'].map((encoding) => (
                              <div key={encoding} className="flex items-center space-x-2">
                                <span className={`text-xs px-2 py-1 rounded font-medium ${
                                  isDarkMode ? 'bg-gray-600 text-gray-300' : 'bg-gray-200 text-gray-600'
                                }`}>
                                  {encoding.toUpperCase()}
                                </span>
                                <code className={`flex-1 p-2 rounded text-sm font-mono ${
                                  isDarkMode ? 'bg-gray-900 text-blue-400' : 'bg-gray-100 text-blue-600'
                                }`}>
                                  {encodePayload(payload.content, encoding)}
                                </code>
                                <button
                                  onClick={() => copyToClipboard(encodePayload(payload.content, encoding))}
                                  className={`p-2 rounded transition-colors ${
                                    isDarkMode
                                      ? 'text-gray-400 hover:text-white hover:bg-gray-700'
                                      : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                                  }`}
                                >
                                  <Copy className="w-4 h-4" />
                                </button>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Tags */}
                      <div className="flex flex-wrap gap-1 mt-3">
                        {payload.tags.map((tag) => (
                          <span
                            key={tag}
                            className={`px-2 py-1 rounded text-xs ${
                              isDarkMode ? 'bg-gray-600 text-gray-300' : 'bg-gray-100 text-gray-600'
                            }`}
                          >
                            #{tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center space-x-2 ml-4">
                    <button
                      onClick={() => toggleFavorite(payload.id)}
                      className={`p-2 rounded transition-colors ${
                        payload.isFavorite
                          ? 'text-yellow-400 hover:text-yellow-300'
                          : isDarkMode
                          ? 'text-gray-400 hover:text-yellow-400'
                          : 'text-gray-600 hover:text-yellow-600'
                      }`}
                    >
                      <Star className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => incrementUsage(payload.id)}
                      className={`p-2 rounded transition-colors ${
                        isDarkMode
                          ? 'text-gray-400 hover:text-white hover:bg-gray-700'
                          : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                      }`}
                    >
                      <Code className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => setEditingPayload(payload)}
                      className={`p-2 rounded transition-colors ${
                        isDarkMode
                          ? 'text-gray-400 hover:text-white hover:bg-gray-700'
                          : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                      }`}
                    >
                      <Edit className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => deletePayload(payload.id)}
                      className="p-2 rounded text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            ))}

            {filteredPayloads.length === 0 && (
              <div className="text-center py-12">
                <div className="w-16 h-16 mx-auto mb-4 p-4 bg-gray-500/20 rounded-full">
                  <Zap className="w-8 h-8 text-gray-400 mx-auto" />
                </div>
                <p className="text-gray-400">No payloads found</p>
                <p className="text-sm text-gray-500 mt-2">
                  Try adjusting your search criteria or add new payloads
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Statistics */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-lg p-4`}>
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-2xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                  {payloads.length}
                </p>
                <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                  Total Payloads
                </p>
              </div>
              <Zap className="w-8 h-8 text-blue-400" />
            </div>
          </div>
          <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-lg p-4`}>
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-2xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                  {payloads.filter(p => p.isFavorite).length}
                </p>
                <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                  Favorites
                </p>
              </div>
              <Star className="w-8 h-8 text-yellow-400" />
            </div>
          </div>
          <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-lg p-4`}>
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-2xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                  {payloads.reduce((sum, p) => sum + p.usageCount, 0)}
                </p>
                <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                  Total Usage
                </p>
              </div>
              <TrendingUp className="w-8 h-8 text-green-400" />
            </div>
          </div>
          <div className={`${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'} border rounded-lg p-4`}>
            <div className="flex items-center justify-between">
              <div>
                <p className={`text-2xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                  {categories.length}
                </p>
                <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                  Categories
                </p>
              </div>
              <FolderOpen className="w-8 h-8 text-purple-400" />
            </div>
          </div>
        </div>
      </div>

      {/* Add/Edit Payload Modal would go here */}
      {/* This is a placeholder for the modal implementation */}
    </div>
  );
};

export default PayloadManager;
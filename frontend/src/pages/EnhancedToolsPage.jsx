// Enhanced Tools Page with Modern Card Design
import React, { useState, useEffect } from 'react';
import { useScan } from '../context/EnhancedScanContext';
import { SCAN_STATUS } from '../utils/constants';
import { 
  Card, 
  Badge, 
  Button, 
  StatusIndicator,
  PageTransition,
  StaggeredList,
  SkeletonCard,
  EnhancedModal,
  FormModal
} from '../components/ThemeComponents';
import { 
  ToolsSkeleton
} from '../components/EnhancedLoadingSkeletons';


const EnhancedToolsPage = () => {
  const { 
    toolActivity, 
    scanStatus,
    connected 
  } = useScan();

  const [loading, setLoading] = useState(false);
  const [selectedTool, setSelectedTool] = useState(null);
  const [showToolModal, setShowToolModal] = useState(false);
  const [filterCategory, setFilterCategory] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  // Simulate loading state
  useEffect(() => {
    if (toolActivity.length === 0 && scanStatus === SCAN_STATUS.IDLE) {
      setLoading(true);
      const timer = setTimeout(() => setLoading(false), 1500);
      return () => clearTimeout(timer);
    }
  }, [toolActivity.length, scanStatus]);

  // Enhanced tools data with categories
  const toolsData = [
    {
      id: 'nmap',
      name: 'Nmap Scanner',
      category: 'network',
      description: 'Network discovery and security auditing tool',
      status: 'active',
      version: '7.94',
      author: 'Gordon Lyon',
      icon: '🔍',
      features: ['Port Scanning', 'Service Detection', 'OS Detection', 'Vulnerability Scripts'],
      severity: 'safe'
    },
    {
      id: 'sqlmap',
      name: 'SQLMap',
      category: 'web',
      description: 'Automatic SQL injection detection and exploitation tool',
      status: 'available',
      version: '1.7.12',
      author: 'Bernardo Damele',
      icon: '🗄️',
      features: ['SQL Injection Detection', 'Database Enumeration', 'Data Extraction', 'OS Command Execution'],
      severity: 'warning'
    },
    {
      id: 'nikto',
      name: 'Nikto',
      category: 'web',
      description: 'Web server scanner for dangerous files and configurations',
      status: 'available',
      version: '2.1.6',
      author: 'CIRT.net',
      icon: '🕵️',
      features: ['Web Server Scanning', 'Plugin System', 'SSL/TLS Testing', 'Directory Bruteforcing'],
      severity: 'warning'
    },
    {
      id: 'metasploit',
      name: 'Metasploit Framework',
      category: 'exploitation',
      description: 'Penetration testing framework for security assessments',
      status: 'available',
      version: '6.3.4',
      author: 'Rapid7',
      icon: '⚔️',
      features: ['Exploit Development', 'Payload Generation', 'Post-Exploitation', 'Module System'],
      severity: 'danger'
    },
    {
      id: 'dirb',
      name: 'DIRB',
      category: 'web',
      description: 'Web content scanner for directory and file discovery',
      status: 'available',
      version: '2.22',
      author: 'The Dark Raver',
      icon: '📁',
      features: ['Directory Discovery', 'File Bruteforcing', 'Wordlist Support', 'Recursive Scanning'],
      severity: 'safe'
    },
    {
      id: 'burpsuite',
      name: 'Burp Suite',
      category: 'web',
      description: 'Integrated platform for web application security testing',
      status: 'available',
      version: '2023.12',
      author: 'PortSwigger',
      icon: '🦀',
      features: ['Proxy Interception', 'Scanner', 'Repeater', 'Intruder', 'Collaborator'],
      severity: 'safe'
    },
    {
      id: 'wireshark',
      name: 'Wireshark',
      category: 'network',
      description: 'Network protocol analyzer for troubleshooting and analysis',
      status: 'active',
      version: '4.0.10',
      author: 'Gerald Combs',
      icon: '📊',
      features: ['Packet Capture', 'Protocol Analysis', 'VoIP Analysis', 'Expert System'],
      severity: 'safe'
    },
    {
      id: 'hashcat',
      name: 'Hashcat',
      category: 'cryptography',
      description: 'Advanced password recovery and hash cracking tool',
      status: 'available',
      version: '6.2.6',
      author: 'Jens Steube',
      icon: '🔓',
      features: ['Hash Cracking', 'Brute Force', 'Dictionary Attacks', 'Rule-based Attacks'],
      severity: 'warning'
    },
    {
      id: 'john',
      name: 'John the Ripper',
      category: 'cryptography',
      description: 'Fast password cracker for Unix and Windows systems',
      status: 'available',
      version: '1.9.0',
      author: 'Solar Designer',
      icon: '🗝️',
      features: ['Password Cracking', 'Multiple Hash Types', 'Wordlist Generation', 'Hybrid Attacks'],
      severity: 'warning'
    },
    {
      id: 'netcat',
      name: 'Netcat',
      category: 'network',
      description: 'Swiss army knife for networking and security testing',
      status: 'active',
      version: '1.218',
      author: 'Hobbit',
      icon: '🔌',
      features: ['Port Scanning', 'Banner Grabbing', 'File Transfer', 'Remote Shell'],
      severity: 'safe'
    },
    {
      id: 'aircrack',
      name: 'Aircrack-ng',
      category: 'wireless',
      description: 'Wireless network security assessment and monitoring tools',
      status: 'available',
      version: '1.7',
      author: 'Thomas d\'Otreppe',
      icon: '📡',
      features: ['WEP/WPA/WPA2 Cracking', 'Packet Injection', 'Monitoring Mode', 'Dictionary Attacks'],
      severity: 'danger'
    },
    {
      id: 'hydra',
      name: 'THC Hydra',
      category: 'authentication',
      description: 'Fast network logon cracker supporting many services',
      status: 'available',
      version: '9.4',
      author: 'van Hauser',
      icon: '💧',
      features: ['Brute Force Attack', 'Service Modules', 'Parallel Attacks', 'Custom Wordlists'],
      severity: 'danger'
    }
  ];

  // Filter tools by category and search term
  const filteredTools = toolsData.filter(tool => {
    const matchesCategory = filterCategory === 'all' || tool.category === filterCategory;
    const matchesSearch = tool.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         tool.description.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  const categories = [
    { value: 'all', label: 'All Tools', count: toolsData.length },
    { value: 'network', label: 'Network', count: toolsData.filter(t => t.category === 'network').length },
    { value: 'web', label: 'Web Security', count: toolsData.filter(t => t.category === 'web').length },
    { value: 'exploitation', label: 'Exploitation', count: toolsData.filter(t => t.category === 'exploitation').length },
    { value: 'cryptography', label: 'Cryptography', count: toolsData.filter(t => t.category === 'cryptography').length },
    { value: 'wireless', label: 'Wireless', count: toolsData.filter(t => t.category === 'wireless').length },
    { value: 'authentication', label: 'Authentication', count: toolsData.filter(t => t.category === 'authentication').length }
  ];

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'safe': return 'success';
      case 'warning': return 'warning';
      case 'danger': return 'error';
      default: return 'primary';
    }
  };

  const getSeverityBadge = (severity) => {
    const config = {
      safe: { variant: 'success', label: 'Safe' },
      warning: { variant: 'warning', label: 'Warning' },
      danger: { variant: 'error', label: 'Danger' }
    };
    return config[severity] || config.safe;
  };

  const handleToolClick = (tool) => {
    setSelectedTool(tool);
    setShowToolModal(true);
  };

  if (loading) {
    return <ToolsSkeleton />;
  }

  return (
    <PageTransition>
      <div className="space-y-8">
        {/* Enhanced Header */}
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 animate-fade-in-down">
          <div>
            <h1 className="text-4xl font-bold text-gradient mb-2">
              Security Tools
            </h1>
            <p className="text-gray-400">
              Comprehensive collection of penetration testing and security assessment tools
            </p>
          </div>
          
          <div className="flex items-center gap-4">
            {/* Connection Status */}
            <StatusIndicator 
              status={connected ? 'online' : 'offline'} 
              showText={true}
            />
            
            {/* Add Custom Tool Button */}
            <Button 
              variant="primary"
              icon={
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                </svg>
              }
            >
              Add Tool
            </Button>
          </div>
        </div>

        {/* Category Filter and Search */}
        <Card className="hover-glow">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            {/* Category Filters */}
            <div className="flex flex-wrap gap-2">
              {categories.map((category) => (
                <Button
                  key={category.value}
                  variant={filterCategory === category.value ? 'primary' : 'ghost'}
                  size="sm"
                  onClick={() => setFilterCategory(category.value)}
                >
                  {category.label}
                  <Badge variant={filterCategory === category.value ? 'primary' : 'primary'} size="sm" className="ml-2">
                    {category.count}
                  </Badge>
                </Button>
              ))}
            </div>
            
            {/* Search Input */}
            <div className="relative">
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search tools..."
                className="input pl-10 pr-4 w-64"
              />
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <svg className="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              </div>
            </div>
          </div>
        </Card>

        {/* Tools Grid */}
        <StaggeredList className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredTools.map((tool) => {
            const severityConfig = getSeverityBadge(tool.severity);
            const isActive = tool.status === 'active';
            
            return (
              <Card 
                key={tool.id}
                className="hover-glow cursor-pointer group"
                onClick={() => handleToolClick(tool)}
              >
                <div className="space-y-4">
                  {/* Tool Header */}
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className="text-3xl">{tool.icon}</div>
                      <div>
                        <h3 className="text-lg font-bold text-white group-hover:text-purple-400 transition-colors">
                          {tool.name}
                        </h3>
                        <p className="text-sm text-gray-400">v{tool.version}</p>
                      </div>
                    </div>
                    
                    <div className="flex flex-col gap-2">
                      <Badge variant={severityConfig.variant} size="sm">
                        {severityConfig.label}
                      </Badge>
                      <Badge 
                        variant={isActive ? 'success' : 'primary'} 
                        size="sm"
                        pulse={isActive}
                      >
                        {isActive ? 'Running' : 'Available'}
                      </Badge>
                    </div>
                  </div>
                  
                  {/* Tool Description */}
                  <p className="text-sm text-gray-300 line-clamp-2">
                    {tool.description}
                  </p>
                  
                  {/* Tool Features */}
                  <div className="space-y-2">
                    <h4 className="text-xs font-medium text-gray-400 uppercase tracking-wide">
                      Key Features
                    </h4>
                    <div className="flex flex-wrap gap-1">
                      {tool.features.slice(0, 3).map((feature, index) => (
                        <Badge key={index} variant="primary" size="sm">
                          {feature}
                        </Badge>
                      ))}
                      {tool.features.length > 3 && (
                        <Badge variant="ghost" size="sm">
                          +{tool.features.length - 3} more
                        </Badge>
                      )}
                    </div>
                  </div>
                  
                  {/* Tool Footer */}
                  <div className="flex items-center justify-between pt-2 border-t border-gray-700">
                    <div className="text-xs text-gray-500">
                      by {tool.author}
                    </div>
                    <div className="flex items-center gap-2">
                      <Button variant="ghost" size="sm" className="opacity-0 group-hover:opacity-100 transition-opacity">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                        </svg>
                      </Button>
                      <Button 
                        variant={isActive ? 'danger' : 'primary'} 
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          // Handle tool launch
                        }}
                      >
                        {isActive ? 'Stop' : 'Launch'}
                      </Button>
                    </div>
                  </div>
                </div>
              </Card>
            );
          })}
        </StaggeredList>

        {/* No Results State */}
        {filteredTools.length === 0 && (
          <Card>
            <div className="text-center py-16">
              <div className="w-20 h-20 mx-auto mb-6 p-5 bg-gray-800 rounded-full">
                <svg className="w-10 h-10 text-gray-400 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              </div>
              <h3 className="text-xl font-semibold text-gray-300 mb-2">No Tools Found</h3>
              <p className="text-gray-400 mb-6">
                {searchTerm ? `No tools match "${searchTerm}"` : 'No tools available in this category'}
              </p>
              <Button 
                variant="primary" 
                onClick={() => {
                  setSearchTerm('');
                  setFilterCategory('all');
                }}
              >
                Clear Filters
              </Button>
            </div>
          </Card>
        )}

        {/* Tool Detail Modal */}
        <EnhancedModal
          isOpen={showToolModal}
          onClose={() => setShowToolModal(false)}
          title={selectedTool?.name || 'Tool Details'}
          size="lg"
          footer={
            <>
              <Button variant="ghost" onClick={() => setShowToolModal(false)}>
                Close
              </Button>
              <Button 
                variant={selectedTool?.status === 'active' ? 'danger' : 'primary'}
                onClick={() => {
                  // Handle tool launch/stop
                  setShowToolModal(false);
                }}
              >
                {selectedTool?.status === 'active' ? 'Stop Tool' : 'Launch Tool'}
              </Button>
            </>
          }
        >
          {selectedTool && (
            <div className="space-y-6">
              {/* Tool Overview */}
              <div className="flex items-start gap-4">
                <div className="text-4xl">{selectedTool.icon}</div>
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-2xl font-bold text-white">{selectedTool.name}</h3>
                    <Badge variant={getSeverityBadge(selectedTool.severity).variant}>
                      {getSeverityBadge(selectedTool.severity).label}
                    </Badge>
                    <Badge variant={selectedTool.status === 'active' ? 'success' : 'primary'}>
                      {selectedTool.status}
                    </Badge>
                  </div>
                  <p className="text-gray-300 mb-2">{selectedTool.description}</p>
                  <div className="flex items-center gap-4 text-sm text-gray-400">
                    <span>Version: {selectedTool.version}</span>
                    <span>Author: {selectedTool.author}</span>
                    <span>Category: {selectedTool.category}</span>
                  </div>
                </div>
              </div>

              {/* Features List */}
              <div>
                <h4 className="text-lg font-semibold text-white mb-3">Features & Capabilities</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {selectedTool.features.map((feature, index) => (
                    <div key={index} className="flex items-center gap-2">
                      <div className="w-2 h-2 bg-purple-500 rounded-full" />
                      <span className="text-gray-300">{feature}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Usage Statistics */}
              <div>
                <h4 className="text-lg font-semibold text-white mb-3">Usage Statistics</h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="text-center p-4 bg-gray-800/50 rounded-lg">
                    <div className="text-2xl font-bold text-purple-400">127</div>
                    <div className="text-sm text-gray-400">Total Runs</div>
                  </div>
                  <div className="text-center p-4 bg-gray-800/50 rounded-lg">
                    <div className="text-2xl font-bold text-green-400">89</div>
                    <div className="text-sm text-gray-400">Successful</div>
                  </div>
                  <div className="text-center p-4 bg-gray-800/50 rounded-lg">
                    <div className="text-2xl font-bold text-yellow-400">23</div>
                    <div className="text-sm text-gray-400">This Month</div>
                  </div>
                  <div className="text-center p-4 bg-gray-800/50 rounded-lg">
                    <div className="text-2xl font-bold text-blue-400">15m</div>
                    <div className="text-sm text-gray-400">Avg Duration</div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </EnhancedModal>
      </div>
    </PageTransition>
  );
};

export default EnhancedToolsPage;

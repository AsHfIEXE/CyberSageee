import React, { useState } from 'react';
import { Clock, Activity, Eye, Trash2, Download, Search, Filter, RefreshCw } from 'lucide-react';
import { useTheme } from '../components/ThemeComponents';
import { HistorySkeleton } from '../components/EnhancedLoadingSkeletons';
import { EnhancedModal } from '../components/ThemeComponents';

const EnhancedHistoryPage = () => {
  const { isDark } = useTheme();
  const [selectedScan, setSelectedScan] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [scanToDelete, setScanToDelete] = useState(null);

  // Mock data for scan history
  const [scanHistory] = useState([
    {
      id: '1',
      name: 'Website Security Scan',
      target: 'example.com',
      type: 'Full Scan',
      status: 'completed',
      startTime: '2024-10-31T10:30:00Z',
      endTime: '2024-10-31T11:45:00Z',
      vulnerabilities: 15,
      critical: 2,
      high: 5,
      medium: 6,
      low: 2,
      scanId: 'SCAN-2024-1001'
    },
    {
      id: '2',
      name: 'Network Discovery',
      target: '192.168.1.0/24',
      type: 'Network Scan',
      status: 'running',
      startTime: '2024-10-31T09:15:00Z',
      endTime: null,
      vulnerabilities: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      scanId: 'SCAN-2024-1002'
    },
    {
      id: '3',
      name: 'SSL Certificate Analysis',
      target: 'secure.example.com',
      type: 'SSL Scan',
      status: 'completed',
      startTime: '2024-10-31T08:00:00Z',
      endTime: '2024-10-31T08:30:00Z',
      vulnerabilities: 3,
      critical: 1,
      high: 1,
      medium: 1,
      low: 0,
      scanId: 'SCAN-2024-1003'
    }
  ]);

  // Filter scans based on search and type filter
  const filteredScans = scanHistory.filter(scan => {
    const matchesSearch = scan.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         scan.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         scan.scanId.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesFilter = filterType === 'all' || 
                         (filterType === 'running' && scan.status === 'running') ||
                         (filterType === 'completed' && scan.status === 'completed') ||
                         (filterType === 'vulnerable' && scan.vulnerabilities > 0);
    
    return matchesSearch && matchesFilter;
  });

  React.useEffect(() => {
    // Simulate loading
    const timer = setTimeout(() => setIsLoading(false), 1500);
    return () => clearTimeout(timer);
  }, []);

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  const getDuration = (start, end) => {
    if (!end) return 'In Progress';
    const duration = Math.round((new Date(end) - new Date(start)) / 1000 / 60);
    return `${duration} min`;
  };

  const getStatusBadge = (status) => {
    const statusConfig = {
      completed: { 
        text: 'Completed', 
        className: 'bg-green-500/20 text-green-400 border-green-500/30' 
      },
      running: { 
        text: 'Running', 
        className: 'bg-blue-500/20 text-blue-400 border-blue-500/30 animate-pulse' 
      },
      failed: { 
        text: 'Failed', 
        className: 'bg-red-500/20 text-red-400 border-red-500/30' 
      }
    };

    const config = statusConfig[status] || statusConfig.failed;
    
    return (
      <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${config.className}`}>
        <span className="w-1.5 h-1.5 bg-current rounded-full mr-1.5"></span>
        {config.text}
      </span>
    );
  };

  const getSeverityBadge = (count, color) => {
    if (count === 0) return null;
    return (
      <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${color}`}>
        {count}
      </span>
    );
  };

  const handleDeleteScan = (scan) => {
    setScanToDelete(scan);
    setShowDeleteModal(true);
  };

  const confirmDelete = () => {
    // In a real app, this would delete from backend
    console.log('Deleting scan:', scanToDelete.id);
    setShowDeleteModal(false);
    setScanToDelete(null);
  };

  if (isLoading) {
    return <HistorySkeleton />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-bold bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
            Scan History
          </h2>
          <p className="text-sm text-gray-400 mt-1">
            View and manage previous security scans
          </p>
        </div>
        <button className="inline-flex items-center px-4 py-2 bg-primary hover:bg-primary/90 text-white rounded-lg transition-all duration-200 hover:scale-105">
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </button>
      </div>

      {/* Search and Filter Controls */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
          <input
            type="text"
            placeholder="Search scans by name, target, or ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent transition-all duration-200"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="text-gray-400 w-4 h-4" />
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="px-3 py-2 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent transition-all duration-200"
          >
            <option value="all">All Scans</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="vulnerable">With Issues</option>
          </select>
        </div>
      </div>

      {/* Scan History Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        {filteredScans.map((scan) => (
          <div
            key={scan.id}
            className="bg-white dark:bg-gray-800 rounded-xl shadow-sm hover:shadow-lg transition-all duration-300 hover:-translate-y-1 border border-gray-200 dark:border-gray-700"
          >
            {/* Card Header */}
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-1">
                    {scan.name}
                  </h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                    {scan.target}
                  </p>
                  <p className="text-xs text-gray-500 dark:text-gray-500">
                    {scan.scanId}
                  </p>
                </div>
                {getStatusBadge(scan.status)}
              </div>
            </div>

            {/* Card Content */}
            <div className="p-6 space-y-4">
              {/* Scan Info */}
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Type:</span>
                  <p className="font-medium text-gray-900 dark:text-white">{scan.type}</p>
                </div>
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Duration:</span>
                  <p className="font-medium text-gray-900 dark:text-white">
                    {getDuration(scan.startTime, scan.endTime)}
                  </p>
                </div>
              </div>

              {/* Timeline */}
              <div className="flex items-center text-sm text-gray-500 dark:text-gray-400">
                <Clock className="w-4 h-4 mr-2" />
                <span>{formatDate(scan.startTime)}</span>
              </div>

              {/* Vulnerability Summary */}
              {scan.status === 'completed' && (
                <div className="space-y-2">
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                    Vulnerabilities Found:
                  </span>
                  <div className="flex items-center gap-2">
                    {getSeverityBadge(scan.critical, 'bg-red-500/20 text-red-400 border border-red-500/30')}
                    {getSeverityBadge(scan.high, 'bg-orange-500/20 text-orange-400 border border-orange-500/30')}
                    {getSeverityBadge(scan.medium, 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30')}
                    {getSeverityBadge(scan.low, 'bg-blue-500/20 text-blue-400 border border-blue-500/30')}
                  </div>
                </div>
              )}
            </div>

            {/* Card Actions */}
            <div className="px-6 py-4 bg-gray-50 dark:bg-gray-750 border-t border-gray-200 dark:border-gray-700">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setSelectedScan(scan)}
                    className="inline-flex items-center px-3 py-1.5 text-xs font-medium text-primary bg-primary/10 hover:bg-primary/20 rounded-lg transition-colors duration-200"
                  >
                    <Eye className="w-3 h-3 mr-1" />
                    View Details
                  </button>
                  {scan.status === 'completed' && (
                    <button className="inline-flex items-center px-3 py-1.5 text-xs font-medium text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white rounded-lg transition-colors duration-200">
                      <Download className="w-3 h-3 mr-1" />
                      Export
                    </button>
                  )}
                </div>
                <button
                  onClick={() => handleDeleteScan(scan)}
                  className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors duration-200"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* No Results */}
      {filteredScans.length === 0 && (
        <div className="text-center py-12">
          <Activity className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
            No scans found
          </h3>
          <p className="text-gray-500 dark:text-gray-400">
            {searchTerm || filterType !== 'all' 
              ? 'Try adjusting your search or filter criteria'
              : 'Start your first scan to see it here'
            }
          </p>
        </div>
      )}

      {/* Scan Details Modal */}
      {selectedScan && (
        <EnhancedModal
          isOpen={!!selectedScan}
          onClose={() => setSelectedScan(null)}
          title={`Scan Details - ${selectedScan.name}`}
          maxWidth="2xl"
        >
          <div className="space-y-6">
            {/* Scan Information */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">
                  Scan ID
                </h4>
                <p className="text-gray-900 dark:text-white">{selectedScan.scanId}</p>
              </div>
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">
                  Status
                </h4>
                {getStatusBadge(selectedScan.status)}
              </div>
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">
                  Target
                </h4>
                <p className="text-gray-900 dark:text-white">{selectedScan.target}</p>
              </div>
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">
                  Type
                </h4>
                <p className="text-gray-900 dark:text-white">{selectedScan.type}</p>
              </div>
            </div>

            {/* Timing Information */}
            <div>
              <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
                Timing
              </h4>
              <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4 space-y-2">
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Start Time:</span>
                  <span className="text-gray-900 dark:text-white">{formatDate(selectedScan.startTime)}</span>
                </div>
                {selectedScan.endTime && (
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">End Time:</span>
                    <span className="text-gray-900 dark:text-white">{formatDate(selectedScan.endTime)}</span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Duration:</span>
                  <span className="text-gray-900 dark:text-white">
                    {getDuration(selectedScan.startTime, selectedScan.endTime)}
                  </span>
                </div>
              </div>
            </div>

            {/* Vulnerability Summary */}
            {selectedScan.status === 'completed' && (
              <div>
                <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
                  Vulnerability Summary
                </h4>
                <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4">
                  <div className="grid grid-cols-2 gap-4">
                    {getSeverityBadge(selectedScan.critical, 'bg-red-500/20 text-red-400 border border-red-500/30 rounded px-3 py-2')}
                    {getSeverityBadge(selectedScan.high, 'bg-orange-500/20 text-orange-400 border border-orange-500/30 rounded px-3 py-2')}
                    {getSeverityBadge(selectedScan.medium, 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 rounded px-3 py-2')}
                    {getSeverityBadge(selectedScan.low, 'bg-blue-500/20 text-blue-400 border border-blue-500/30 rounded px-3 py-2')}
                  </div>
                </div>
              </div>
            )}
          </div>
        </EnhancedModal>
      )}

      {/* Delete Confirmation Modal */}
      <EnhancedModal
        isOpen={showDeleteModal}
        onClose={() => setShowDeleteModal(false)}
        title="Delete Scan"
        maxWidth="md"
      >
        <div className="space-y-4">
          <p className="text-gray-600 dark:text-gray-400">
            Are you sure you want to delete the scan "{scanToDelete?.name}"? This action cannot be undone.
          </p>
          <div className="flex justify-end gap-3">
            <button
              onClick={() => setShowDeleteModal(false)}
              className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white rounded-lg transition-colors duration-200"
            >
              Cancel
            </button>
            <button
              onClick={confirmDelete}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors duration-200"
            >
              Delete
            </button>
          </div>
        </div>
      </EnhancedModal>
    </div>
  );
};

export default EnhancedHistoryPage;
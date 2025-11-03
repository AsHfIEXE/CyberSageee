import React, { useState, useEffect, useRef } from 'react';

const RealTimeLogs = ({ socket, scanId, logs: externalLogs, setLogs: setExternalLogs }) => {
  // Use external logs if provided, otherwise use internal state
  const [internalLogs, setInternalLogs] = useState([]);
  const logs = externalLogs !== undefined ? externalLogs : internalLogs;
  const setLogs = setExternalLogs !== undefined ? setExternalLogs : setInternalLogs;
  
  const [autoScroll, setAutoScroll] = useState(true);
  const [filter, setFilter] = useState('all'); // all, info, warning, error
  const [connectionStatus, setConnectionStatus] = useState('connected');
  const [errorCount, setErrorCount] = useState(0);
  const logsEndRef = useRef(null);
  const logsContainerRef = useRef(null);
  const MAX_LOGS = 500;

  useEffect(() => {
    if (!socket) {
      setConnectionStatus('disconnected');
      return;
    }

    setConnectionStatus('connected');

    // Listen for various events with error handling
    const handlers = {
      scan_log: (data) => {
        try {
          addLog(data.message, data.level || 'info', data.timestamp);
        } catch (error) {
          console.error('Error processing scan_log:', error);
          setErrorCount(prev => prev + 1);
        }
      },
      tool_started: (data) => {
        addLog(`🔧 [${data.tool}] Starting scan on ${data.target}`, 'info', data.timestamp);
      },
      tool_completed: (data) => {
        addLog(`✓ [${data.tool}] Completed - ${data.findings_count || 0} findings`, 'success', data.timestamp);
      },
      vulnerability_found: (data) => {
        addLog(`⚠️ [${data.severity.toUpperCase()}] Found: ${data.type} in ${data.url}`, 'warning', data.timestamp);
      },
      endpoint_discovered: (data) => {
        addLog(`🔍 Discovered endpoint: ${data.method} ${data.url}`, 'info', data.timestamp);
      },
      scan_progress: (data) => {
        addLog(`📊 Progress: ${data.progress}% - ${data.phase}`, 'info', data.timestamp);
      },
      scan_completed: (data) => {
        addLog(`✅ Scan completed successfully`, 'success', data.timestamp);
      },
      scan_error: (data) => {
        addLog(`❌ Scan error: ${data.error}`, 'error', data.timestamp);
      },
      connect: () => {
        setConnectionStatus('connected');
        addLog('📡 Reconnected to server', 'success', Date.now() / 1000);
      },
      disconnect: () => {
        setConnectionStatus('disconnected');
        addLog('⚠️ Disconnected from server', 'warning', Date.now() / 1000);
      },
      connect_error: (error) => {
        setConnectionStatus('error');
        addLog(`❌ Connection error: ${error.message}`, 'error', Date.now() / 1000);
        setErrorCount(prev => prev + 1);
      }
    };

    Object.entries(handlers).forEach(([event, handler]) => {
      socket.on(event, handler);
    });

    return () => {
      Object.keys(handlers).forEach(event => {
        socket.off(event);
      });
    };
  }, [socket]);

  useEffect(() => {
    if (autoScroll && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  const addLog = (message, level, timestamp) => {
    try {
      const newLog = {
        id: Date.now() + Math.random(),
        message,
        level,
        timestamp: timestamp || Date.now(),
        time: new Date((timestamp ? timestamp * 1000 : Date.now())).toLocaleTimeString()
      };
      setLogs(prev => {
        const updated = [...prev, newLog];
        // Keep only last MAX_LOGS entries for performance
        return updated.slice(-MAX_LOGS);
      });
    } catch (error) {
      console.error('Error adding log:', error);
      setErrorCount(prev => prev + 1);
    }
  };

  const clearLogs = () => {
    setLogs([]);
  };

  const exportLogs = () => {
    const logText = logs.map(log => `[${log.time}] [${log.level.toUpperCase()}] ${log.message}`).join('\n');
    const blob = new Blob([logText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybersage-logs-${scanId || 'scan'}-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredLogs = logs.filter(log => {
    if (filter === 'all') return true;
    return log.level === filter;
  });

  const getLevelColor = (level) => {
    switch (level) {
      case 'error': return 'text-red-400';
      case 'warning': return 'text-yellow-400';
      case 'success': return 'text-green-400';
      case 'info':
      default: return 'text-blue-400';
    }
  };

  const getLevelBg = (level) => {
    switch (level) {
      case 'error': return 'bg-red-900/20';
      case 'warning': return 'bg-yellow-900/20';
      case 'success': return 'bg-green-900/20';
      case 'info':
      default: return 'bg-blue-900/20';
    }
  };

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
      {/* Header */}
      <div className="bg-gray-800 border-b border-gray-700 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="text-2xl">📝</div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-white font-bold text-lg">Real-Time Scan Logs</h3>
                <div className={`w-2 h-2 rounded-full ${
                  connectionStatus === 'connected' ? 'bg-green-500 animate-pulse' :
                  connectionStatus === 'error' ? 'bg-red-500' :
                  'bg-yellow-500'
                }`} title={connectionStatus} />
              </div>
              <p className="text-gray-400 text-sm">
                {filteredLogs.length} log entries
                {errorCount > 0 && <span className="text-red-400 ml-2">({errorCount} errors)</span>}
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            {/* Filter */}
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="px-3 py-1.5 bg-gray-700 text-white rounded border border-gray-600 text-sm"
            >
              <option value="all">All Logs</option>
              <option value="info">Info</option>
              <option value="success">Success</option>
              <option value="warning">Warnings</option>
              <option value="error">Errors</option>
            </select>
            
            {/* Auto-scroll toggle */}
            <button
              onClick={() => setAutoScroll(!autoScroll)}
              className={`px-3 py-1.5 rounded text-sm font-medium ${
                autoScroll
                  ? 'bg-purple-600 text-white'
                  : 'bg-gray-700 text-gray-300'
              }`}
            >
              {autoScroll ? '📌 Auto-scroll' : '📌 Manual'}
            </button>
            
            {/* Export */}
            <button
              onClick={exportLogs}
              className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded text-sm"
            >
              💾 Export
            </button>
            
            {/* Clear */}
            <button
              onClick={clearLogs}
              className="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded text-sm"
            >
              🗑️ Clear
            </button>
          </div>
        </div>
      </div>

      {/* Logs Container */}
      <div 
        ref={logsContainerRef}
        className="h-96 overflow-y-auto bg-gray-950 p-4 font-mono text-sm"
        style={{ scrollBehavior: 'smooth' }}
      >
        {filteredLogs.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-500">
            <div className="text-center">
              <div className="text-4xl mb-2">📭</div>
              <p>No logs yet. Start a scan to see real-time activity.</p>
            </div>
          </div>
        ) : (
          <div className="space-y-1">
            {filteredLogs.map((log) => (
              <div
                key={log.id}
                className={`flex items-start space-x-3 p-2 rounded ${getLevelBg(log.level)} hover:bg-opacity-75 transition`}
              >
                <span className="text-gray-500 text-xs whitespace-nowrap mt-0.5">
                  {log.time}
                </span>
                <span className={`${getLevelColor(log.level)} whitespace-pre-wrap flex-1`}>
                  {log.message}
                </span>
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        )}
      </div>

      {/* Footer Stats */}
      <div className="bg-gray-800 border-t border-gray-700 p-3">
        <div className="flex items-center justify-between text-xs text-gray-400">
          <div className="flex space-x-4">
            <span>ℹ️ Info: {logs.filter(l => l.level === 'info').length}</span>
            <span>✅ Success: {logs.filter(l => l.level === 'success').length}</span>
            <span>⚠️ Warnings: {logs.filter(l => l.level === 'warning').length}</span>
            <span>❌ Errors: {logs.filter(l => l.level === 'error').length}</span>
          </div>
          <div>
            Total: {logs.length} logs
          </div>
        </div>
      </div>
    </div>
  );
};

export default RealTimeLogs;

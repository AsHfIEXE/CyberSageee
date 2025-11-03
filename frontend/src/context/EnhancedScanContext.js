import React, { createContext, useContext, useReducer, useEffect, useMemo } from 'react';
import { SOCKET_EVENTS, SCAN_STATUS, WS_CONNECTION_STATES } from '../utils/constants';
import { enhancedWebSocketService } from '../services/enhancedWebSocket';
import { enhancedScanService, enhancedVulnerabilityService } from '../services/enhancedApi';
import { ErrorFactory, ErrorLogger } from '../utils/errors';
import { connectionMonitor } from '../utils/connection';

// Enhanced initial state with new features
const initialState = {
  // Connection status
  connected: false,
  connectionState: WS_CONNECTION_STATES.DISCONNECTED,
  connectionQuality: 'unknown',
  connectionLatency: 0,
  
  // Scan state
  scanStatus: SCAN_STATUS.IDLE,
  progress: 0,
  currentPhase: '',
  currentScanId: null,
  
  // Data
  vulnerabilities: [],
  chains: [],
  toolActivity: [],
  stats: { critical: 0, high: 0, medium: 0, low: 0 },
  aiInsights: [],
  httpHistory: [],
  persistentLogs: [],
  
  // Enhanced features
  offlineQueue: [],
  healthStatus: null,
  performanceMetrics: {
    apiRequests: 0,
    successfulRequests: 0,
    failedRequests: 0,
    averageResponseTime: 0,
    cacheHitRate: 0,
  },
  connectionMetrics: {
    totalConnections: 0,
    reconnectionAttempts: 0,
    messagesSent: 0,
    messagesReceived: 0,
  },
  
  // Errors with enhanced tracking
  error: null,
  errorHistory: [],
  isRetrying: false,
  lastError: null,
};

// Enhanced action types
const ACTION_TYPES = {
  SET_CONNECTION_STATUS: 'SET_CONNECTION_STATUS',
  SET_CONNECTION_STATE: 'SET_CONNECTION_STATE',
  SET_CONNECTION_QUALITY: 'SET_CONNECTION_QUALITY',
  SET_CONNECTION_LATENCY: 'SET_CONNECTION_LATENCY',
  SET_SCAN_STATUS: 'SET_SCAN_STATUS',
  SET_PROGRESS: 'SET_PROGRESS',
  SET_CURRENT_PHASE: 'SET_CURRENT_PHASE',
  SET_CURRENT_SCAN_ID: 'SET_CURRENT_SCAN_ID',
  ADD_VULNERABILITY: 'ADD_VULNERABILITY',
  SET_VULNERABILITIES: 'SET_VULNERABILITIES',
  ADD_CHAIN: 'ADD_CHAIN',
  SET_CHAINS: 'SET_CHAINS',
  ADD_TOOL_ACTIVITY: 'ADD_TOOL_ACTIVITY',
  UPDATE_TOOL_ACTIVITY: 'UPDATE_TOOL_ACTIVITY',
  SET_TOOL_ACTIVITY: 'SET_TOOL_ACTIVITY',
  SET_STATS: 'SET_STATS',
  ADD_AI_INSIGHT: 'ADD_AI_INSIGHT',
  SET_AI_INSIGHTS: 'SET_AI_INSIGHTS',
  ADD_HTTP_HISTORY: 'ADD_HTTP_HISTORY',
  SET_HTTP_HISTORY: 'SET_HTTP_HISTORY',
  ADD_PERSISTENT_LOG: 'ADD_PERSISTENT_LOG',
  SET_PERSISTENT_LOGS: 'SET_PERSISTENT_LOGS',
  SET_ERROR: 'SET_ERROR',
  CLEAR_ERROR: 'CLEAR_ERROR',
  ADD_ERROR_TO_HISTORY: 'ADD_ERROR_TO_HISTORY',
  SET_RETRYING: 'SET_RETRYING',
  SET_HEALTH_STATUS: 'SET_HEALTH_STATUS',
  UPDATE_PERFORMANCE_METRICS: 'UPDATE_PERFORMANCE_METRICS',
  UPDATE_CONNECTION_METRICS: 'UPDATE_CONNECTION_METRICS',
  ADD_TO_OFFLINE_QUEUE: 'ADD_TO_OFFLINE_QUEUE',
  REMOVE_FROM_OFFLINE_QUEUE: 'REMOVE_FROM_OFFLINE_QUEUE',
  CLEAR_OFFLINE_QUEUE: 'CLEAR_OFFLINE_QUEUE',
  RESET_SCAN_DATA: 'RESET_SCAN_DATA',
};

// Enhanced reducer function
function scanReducer(state, action) {
  switch (action.type) {
    case ACTION_TYPES.SET_CONNECTION_STATUS:
      return { ...state, connected: action.payload };
    
    case ACTION_TYPES.SET_CONNECTION_STATE:
      return { ...state, connectionState: action.payload };
    
    case ACTION_TYPES.SET_CONNECTION_QUALITY:
      return { ...state, connectionQuality: action.payload };
    
    case ACTION_TYPES.SET_CONNECTION_LATENCY:
      return { ...state, connectionLatency: action.payload };
    
    case ACTION_TYPES.SET_SCAN_STATUS:
      return { ...state, scanStatus: action.payload };
    
    case ACTION_TYPES.SET_PROGRESS:
      return { ...state, progress: action.payload };
    
    case ACTION_TYPES.SET_CURRENT_PHASE:
      return { ...state, currentPhase: action.payload };
    
    case ACTION_TYPES.SET_CURRENT_SCAN_ID:
      return { ...state, currentScanId: action.payload };
    
    case ACTION_TYPES.ADD_VULNERABILITY:
      const newVuln = { ...action.payload, id: Date.now() + Math.random() };
      return {
        ...state,
        vulnerabilities: [newVuln, ...state.vulnerabilities],
        stats: {
          ...state.stats,
          [newVuln.severity]: state.stats[newVuln.severity] + 1
        }
      };
    
    case ACTION_TYPES.SET_VULNERABILITIES:
      return { ...state, vulnerabilities: action.payload };
    
    case ACTION_TYPES.ADD_CHAIN:
      const newChain = { ...action.payload, id: Date.now() };
      return { ...state, chains: [newChain, ...state.chains] };
    
    case ACTION_TYPES.SET_CHAINS:
      return { ...state, chains: action.payload };
    
    case ACTION_TYPES.ADD_TOOL_ACTIVITY:
      const newActivity = {
        tool: action.payload.tool,
        target: action.payload.target,
        status: action.payload.status,
        timestamp: action.payload.timestamp
      };
      return {
        ...state,
        toolActivity: [newActivity, ...state.toolActivity].slice(0, 10)
      };
    
    case ACTION_TYPES.UPDATE_TOOL_ACTIVITY:
      return {
        ...state,
        toolActivity: state.toolActivity.map(item =>
          item.tool === action.payload.tool
            ? { ...item, status: action.payload.status, findings: action.payload.findings_count }
            : item
        )
      };
    
    case ACTION_TYPES.SET_TOOL_ACTIVITY:
      return { ...state, toolActivity: action.payload };
    
    case ACTION_TYPES.SET_STATS:
      return { ...state, stats: action.payload };
    
    case ACTION_TYPES.ADD_AI_INSIGHT:
      return { ...state, aiInsights: [action.payload, ...state.aiInsights] };
    
    case ACTION_TYPES.SET_AI_INSIGHTS:
      return { ...state, aiInsights: action.payload };
    
    case ACTION_TYPES.ADD_HTTP_HISTORY:
      return { ...state, httpHistory: [action.payload, ...state.httpHistory] };
    
    case ACTION_TYPES.SET_HTTP_HISTORY:
      return { ...state, httpHistory: action.payload };
    
    case ACTION_TYPES.ADD_PERSISTENT_LOG:
      return {
        ...state,
        persistentLogs: [...state.persistentLogs, action.payload].slice(0, 1000)
      };
    
    case ACTION_TYPES.SET_PERSISTENT_LOGS:
      return { ...state, persistentLogs: action.payload };
    
    case ACTION_TYPES.SET_ERROR:
      return { 
        ...state, 
        error: action.payload,
        lastError: action.payload 
      };
    
    case ACTION_TYPES.CLEAR_ERROR:
      return { 
        ...state, 
        error: null,
        isRetrying: false
      };
    
    case ACTION_TYPES.ADD_ERROR_TO_HISTORY:
      return {
        ...state,
        errorHistory: [action.payload, ...state.errorHistory].slice(0, 50) // Keep last 50 errors
      };
    
    case ACTION_TYPES.SET_RETRYING:
      return { ...state, isRetrying: action.payload };
    
    case ACTION_TYPES.SET_HEALTH_STATUS:
      return { ...state, healthStatus: action.payload };
    
    case ACTION_TYPES.UPDATE_PERFORMANCE_METRICS:
      return {
        ...state,
        performanceMetrics: {
          ...state.performanceMetrics,
          ...action.payload
        }
      };
    
    case ACTION_TYPES.UPDATE_CONNECTION_METRICS:
      return {
        ...state,
        connectionMetrics: {
          ...state.connectionMetrics,
          ...action.payload
        }
      };
    
    case ACTION_TYPES.ADD_TO_OFFLINE_QUEUE:
      return {
        ...state,
        offlineQueue: [...state.offlineQueue, action.payload]
      };
    
    case ACTION_TYPES.REMOVE_FROM_OFFLINE_QUEUE:
      return {
        ...state,
        offlineQueue: state.offlineQueue.filter(item => item.id !== action.payload)
      };
    
    case ACTION_TYPES.CLEAR_OFFLINE_QUEUE:
      return { ...state, offlineQueue: [] };
    
    case ACTION_TYPES.RESET_SCAN_DATA:
      return {
        ...state,
        scanStatus: SCAN_STATUS.IDLE,
        progress: 0,
        currentPhase: '',
        currentScanId: null,
        vulnerabilities: [],
        chains: [],
        toolActivity: [],
        stats: { critical: 0, high: 0, medium: 0, low: 0 },
        aiInsights: [],
        httpHistory: [],
      };
    
    default:
      return state;
  }
}

// Create enhanced context
const ScanContext = createContext();

// Enhanced context provider
export function ScanProvider({ children }) {
  const [state, dispatch] = useReducer(scanReducer, initialState);

  // Enhanced action creators
  const actions = useMemo(() => ({
    setConnectionStatus: (connected) => 
      dispatch({ type: ACTION_TYPES.SET_CONNECTION_STATUS, payload: connected }),
    
    setConnectionState: (state) => 
      dispatch({ type: ACTION_TYPES.SET_CONNECTION_STATE, payload: state }),
    
    setConnectionQuality: (quality) => 
      dispatch({ type: ACTION_TYPES.SET_CONNECTION_QUALITY, payload: quality }),
    
    setConnectionLatency: (latency) => 
      dispatch({ type: ACTION_TYPES.SET_CONNECTION_LATENCY, payload: latency }),
    
    setScanStatus: (scanStatus) => 
      dispatch({ type: ACTION_TYPES.SET_SCAN_STATUS, payload: scanStatus }),
    
    setProgress: (progress) => 
      dispatch({ type: ACTION_TYPES.SET_PROGRESS, payload: progress }),
    
    setCurrentPhase: (phase) => 
      dispatch({ type: ACTION_TYPES.SET_CURRENT_PHASE, payload: phase }),
    
    setCurrentScanId: (scanId) => 
      dispatch({ type: ACTION_TYPES.SET_CURRENT_SCAN_ID, payload: scanId }),
    
    addVulnerability: (vulnerability) => 
      dispatch({ type: ACTION_TYPES.ADD_VULNERABILITY, payload: vulnerability }),
    
    setVulnerabilities: (vulnerabilities) => 
      dispatch({ type: ACTION_TYPES.SET_VULNERABILITIES, payload: vulnerabilities }),
    
    addChain: (chain) => 
      dispatch({ type: ACTION_TYPES.ADD_CHAIN, payload: chain }),
    
    setChains: (chains) => 
      dispatch({ type: ACTION_TYPES.SET_CHAINS, payload: chains }),
    
    addToolActivity: (activity) => 
      dispatch({ type: ACTION_TYPES.ADD_TOOL_ACTIVITY, payload: activity }),
    
    updateToolActivity: (activity) => 
      dispatch({ type: ACTION_TYPES.UPDATE_TOOL_ACTIVITY, payload: activity }),
    
    setToolActivity: (activity) => 
      dispatch({ type: ACTION_TYPES.SET_TOOL_ACTIVITY, payload: activity }),
    
    setStats: (stats) => 
      dispatch({ type: ACTION_TYPES.SET_STATS, payload: stats }),
    
    addAIInsight: (insight) => 
      dispatch({ type: ACTION_TYPES.ADD_AI_INSIGHT, payload: insight }),
    
    setAIInsights: (insights) => 
      dispatch({ type: ACTION_TYPES.SET_AI_INSIGHTS, payload: insights }),
    
    addHTTPHistory: (history) => 
      dispatch({ type: ACTION_TYPES.ADD_HTTP_HISTORY, payload: history }),
    
    setHTTPHistory: (history) => 
      dispatch({ type: ACTION_TYPES.SET_HTTP_HISTORY, payload: history }),
    
    addPersistentLog: (log) => 
      dispatch({ type: ACTION_TYPES.ADD_PERSISTENT_LOG, payload: log }),
    
    setPersistentLogs: (logs) => 
      dispatch({ type: ACTION_TYPES.SET_PERSISTENT_LOGS, payload: logs }),
    
    setError: (error) => {
      const errorLog = ErrorFactory.createFromError(error);
      ErrorLogger.log(errorLog, { context: 'ScanContext' });
      dispatch({ type: ACTION_TYPES.ADD_ERROR_TO_HISTORY, payload: errorLog });
      dispatch({ type: ACTION_TYPES.SET_ERROR, payload: errorLog });
    },
    
    clearError: () => 
      dispatch({ type: ACTION_TYPES.CLEAR_ERROR }),
    
    setRetrying: (retrying) => 
      dispatch({ type: ACTION_TYPES.SET_RETRYING, payload: retrying }),
    
    setHealthStatus: (status) => 
      dispatch({ type: ACTION_TYPES.SET_HEALTH_STATUS, payload: status }),
    
    updatePerformanceMetrics: (metrics) => 
      dispatch({ type: ACTION_TYPES.UPDATE_PERFORMANCE_METRICS, payload: metrics }),
    
    updateConnectionMetrics: (metrics) => 
      dispatch({ type: ACTION_TYPES.UPDATE_CONNECTION_METRICS, payload: metrics }),
    
    addToOfflineQueue: (item) => 
      dispatch({ type: ACTION_TYPES.ADD_TO_OFFLINE_QUEUE, payload: item }),
    
    removeFromOfflineQueue: (id) => 
      dispatch({ type: ACTION_TYPES.REMOVE_FROM_OFFLINE_QUEUE, payload: id }),
    
    clearOfflineQueue: () => 
      dispatch({ type: ACTION_TYPES.CLEAR_OFFLINE_QUEUE }),
    
    resetScanData: () => 
      dispatch({ type: ACTION_TYPES.RESET_SCAN_DATA }),

    // Enhanced WebSocket methods
    startScan: async (scanConfig) => {
      try {
        actions.setError(null);
        actions.setRetrying(true);
        
        const result = await enhancedScanService.startScan(scanConfig);
        
        enhancedWebSocketService.emitMessage(SOCKET_EVENTS.SCAN_STARTED, scanConfig);
        
        actions.setRetrying(false);
        return result;
      } catch (error) {
        actions.setRetrying(false);
        actions.setError(error);
        
        // Queue for offline retry if needed
        if (!navigator.onLine) {
          const queueItem = {
            id: Date.now(),
            type: 'start_scan',
            data: scanConfig,
            timestamp: Date.now()
          };
          actions.addToOfflineQueue(queueItem);
        }
        
        throw error;
      }
    },
    
    stopScan: async () => {
      try {
        actions.setError(null);
        enhancedWebSocketService.emitMessage('stop_scan', { scan_id: state.currentScanId });
      } catch (error) {
        actions.setError(error);
        throw error;
      }
    },
    
    pauseScan: async () => {
      try {
        actions.setError(null);
        enhancedWebSocketService.emitMessage('pause_scan', { scan_id: state.currentScanId });
      } catch (error) {
        actions.setError(error);
        throw error;
      }
    },
    
    resumeScan: async () => {
      try {
        actions.setError(null);
        enhancedWebSocketService.emitMessage('resume_scan', { scan_id: state.currentScanId });
      } catch (error) {
        actions.setError(error);
        throw error;
      }
    },

    // Enhanced API methods
    fetchScanResults: async (scanId) => {
      try {
        actions.setError(null);
        const results = await enhancedScanService.getScanResults(scanId);
        actions.setVulnerabilities(results.vulnerabilities || []);
        return results;
      } catch (error) {
        actions.setError(error);
        throw error;
      }
    },

    fetchVulnerabilities: async (scanId) => {
      try {
        actions.setError(null);
        const vulnerabilities = await enhancedVulnerabilityService.getVulnerabilities(scanId);
        actions.setVulnerabilities(vulnerabilities);
        return vulnerabilities;
      } catch (error) {
        actions.setError(error);
        throw error;
      }
    },

    getStatistics: async (scanId) => {
      try {
        actions.setError(null);
        const stats = await enhancedVulnerabilityService.getStatistics(scanId);
        actions.setStats(stats);
        return stats;
      } catch (error) {
        actions.setError(error);
        throw error;
      }
    },

    // Health check
    checkHealth: async () => {
      try {
        const healthStatus = await enhancedScanService.healthCheck();
        actions.setHealthStatus(healthStatus);
        return healthStatus;
      } catch (error) {
        actions.setError(error);
        return { healthy: false, error: error.message };
      }
    },

    // Connection management
    reconnectWebSocket: () => {
      enhancedWebSocketService.forceReconnect();
    },

    flushOfflineQueue: async () => {
      if (state.offlineQueue.length === 0) return;
      
      for (const item of state.offlineQueue) {
        try {
          if (item.type === 'start_scan') {
            await enhancedScanService.startScan(item.data);
          }
          actions.removeFromOfflineQueue(item.id);
        } catch (error) {
          console.warn('Failed to process offline queue item:', error);
        }
      }
    }
  }), [state.currentScanId, state.offlineQueue]);

  // Enhanced WebSocket event handlers
  useEffect(() => {
    // Connect to enhanced WebSocket
    enhancedWebSocketService.connect();
    
    // Subscribe to connection events
    const unsubscribeConnection = enhancedWebSocketService.subscribe('connection', (data) => {
      actions.setConnectionStatus(data.connected);
      actions.setConnectionState(data.state);
      actions.clearError();
      
      if (data.connected) {
        actions.addPersistentLog({
          timestamp: Date.now(),
          type: 'websocket_connected',
          message: 'WebSocket connection established',
          data
        });
      }
    });

    // Subscribe to state changes
    const unsubscribeStateChange = enhancedWebSocketService.subscribe('stateChange', (data) => {
      actions.updateConnectionMetrics({
        reconnectionAttempts: data.newState === 'reconnecting' ? 
          state.connectionMetrics.reconnectionAttempts + 1 : 
          state.connectionMetrics.reconnectionAttempts
      });
    });

    // Subscribe to WebSocket scan events
    const unsubscribeScanStarted = enhancedWebSocketService.subscribe(SOCKET_EVENTS.SCAN_STARTED, (data) => {
      actions.setScanStatus(SCAN_STATUS.RUNNING);
      actions.setProgress(0);
      actions.setCurrentScanId(data.scan_id);
      actions.resetScanData();
      actions.addPersistentLog({
        timestamp: Date.now(),
        type: 'scan_started',
        message: `Scan started: ${data.scan_id}`,
        data
      });
    });
    
    const unsubscribeScanProgress = enhancedWebSocketService.subscribe(SOCKET_EVENTS.SCAN_PROGRESS, (data) => {
      actions.setProgress(data.progress);
      actions.setCurrentPhase(data.phase);
      actions.addPersistentLog({
        timestamp: Date.now(),
        type: 'scan_progress',
        message: `${data.phase}: ${Math.round(data.progress)}%`,
        data
      });
    });
    
    const unsubscribeScanCompleted = enhancedWebSocketService.subscribe('scan_completed', (data) => {
      actions.setScanStatus(SCAN_STATUS.COMPLETED);
      actions.addPersistentLog({
        timestamp: Date.now(),
        type: 'scan_completed',
        message: 'Scan completed successfully',
        data
      });
    });
    
    const unsubscribeScanFailed = enhancedWebSocketService.subscribe('scan_failed', (data) => {
      actions.setScanStatus(SCAN_STATUS.FAILED);
      actions.setError(data.error || 'Scan failed');
      actions.addPersistentLog({
        timestamp: Date.now(),
        type: 'scan_failed',
        message: `Scan failed: ${data.error}`,
        data
      });
    });
    
    const unsubscribeToolStarted = enhancedWebSocketService.subscribe(SOCKET_EVENTS.TOOL_STARTED, (data) => {
      actions.addToolActivity(data);
      actions.addPersistentLog({
        timestamp: Date.now(),
        type: 'tool_started',
        message: `Tool started: ${data.tool}`,
        data
      });
    });
    
    const unsubscribeToolCompleted = enhancedWebSocketService.subscribe(SOCKET_EVENTS.TOOL_COMPLETED, (data) => {
      actions.updateToolActivity(data);
      actions.addPersistentLog({
        timestamp: Date.now(),
        type: 'tool_completed',
        message: `Tool completed: ${data.tool}`,
        data
      });
    });
    
    const unsubscribeVulnerabilityFound = enhancedWebSocketService.subscribe(SOCKET_EVENTS.VULNERABILITY_FOUND, (data) => {
      actions.addVulnerability(data);
      actions.addPersistentLog({
        timestamp: Date.now(),
        type: 'vulnerability_found',
        message: `Vulnerability found: ${data.title}`,
        data
      });
    });
    
    const unsubscribeChainDetected = enhancedWebSocketService.subscribe(SOCKET_EVENTS.CHAIN_DETECTED, (data) => {
      actions.addChain(data);
      actions.addPersistentLog({
        timestamp: Date.now(),
        type: 'chain_detected',
        message: 'Attack chain detected',
        data
      });
    });
    
    const unsubscribeAIInsight = enhancedWebSocketService.subscribe(SOCKET_EVENTS.AI_INSIGHT, (data) => {
      actions.addAIInsight(data);
      actions.addPersistentLog({
        timestamp: Date.now(),
        type: 'ai_insight',
        message: 'AI Insight generated',
        data
      });
    });
    
    const unsubscribeLogEntry = enhancedWebSocketService.subscribe(SOCKET_EVENTS.LOG_ENTRY, (data) => {
      actions.addPersistentLog({
        timestamp: Date.now(),
        type: 'log_entry',
        message: data.message,
        data
      });
    });

    // Connection monitoring
    const unsubscribeStatusChange = connectionMonitor.on('statusChange', (data) => {
      actions.setConnectionStatus(data.isOnline);
      actions.setConnectionQuality(data.isOnline ? 'good' : 'offline');
      
      if (data.isOnline) {
        actions.flushOfflineQueue();
      }
    });

    const unsubscribeQualityChange = connectionMonitor.on('qualityChange', (data) => {
      actions.setConnectionQuality(data.quality);
      actions.setConnectionLatency(data.latency);
    });

    const unsubscribeMetricsUpdate = connectionMonitor.on('metricsUpdate', (metrics) => {
      actions.updatePerformanceMetrics({
        apiRequests: metrics.totalRequests,
        successfulRequests: metrics.successfulRequests,
        failedRequests: metrics.failedRequests,
        averageResponseTime: metrics.averageLatency,
      });
    });

    // Health monitoring
    const unsubscribeHealthCheck = enhancedWebSocketService.subscribe('healthCheck', (data) => {
      actions.setHealthStatus(data);
    });

    return () => {
      unsubscribeConnection();
      unsubscribeStateChange();
      unsubscribeScanStarted();
      unsubscribeScanProgress();
      unsubscribeScanCompleted();
      unsubscribeScanFailed();
      unsubscribeToolStarted();
      unsubscribeToolCompleted();
      unsubscribeVulnerabilityFound();
      unsubscribeChainDetected();
      unsubscribeAIInsight();
      unsubscribeLogEntry();
      unsubscribeStatusChange();
      unsubscribeQualityChange();
      unsubscribeMetricsUpdate();
      unsubscribeHealthCheck();
      
      enhancedWebSocketService.disconnect();
    };
  }, [actions, state.connectionMetrics.reconnectionAttempts]);

  const contextValue = useMemo(() => ({
    // State
    ...state,
    
    // Actions
    actions,
  }), [state, actions]);

  return (
    <ScanContext.Provider value={contextValue}>
      {children}
    </ScanContext.Provider>
  );
}

// Custom hook to use the enhanced scan context
export function useScan() {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error('useScan must be used within a ScanProvider');
  }
  return context;
}

// Export context for advanced usage
export { ScanContext };
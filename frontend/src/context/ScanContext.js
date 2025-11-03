import React, { createContext, useContext, useReducer, useEffect, useMemo } from 'react';
import { SOCKET_EVENTS, SCAN_STATUS } from '../utils/constants';
import webSocketService from '../services/websocket';

// Initial state
const initialState = {
  // Connection status
  connected: false,
  
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
  
  // Errors
  error: null,
};

// Action types
const ACTION_TYPES = {
  SET_CONNECTION_STATUS: 'SET_CONNECTION_STATUS',
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
  RESET_SCAN_DATA: 'RESET_SCAN_DATA',
};

// Reducer function
function scanReducer(state, action) {
  switch (action.type) {
    case ACTION_TYPES.SET_CONNECTION_STATUS:
      return { ...state, connected: action.payload };
    
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
      return { ...state, error: action.payload };
    
    case ACTION_TYPES.CLEAR_ERROR:
      return { ...state, error: null };
    
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

// Create context
const ScanContext = createContext();

// Context provider component
export function ScanProvider({ children }) {
  const [state, dispatch] = useReducer(scanReducer, initialState);

  // Action creators
  const actions = useMemo(() => ({
    setConnectionStatus: (connected) => 
      dispatch({ type: ACTION_TYPES.SET_CONNECTION_STATUS, payload: connected }),
    
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
    
    setError: (error) => 
      dispatch({ type: ACTION_TYPES.SET_ERROR, payload: error }),
    
    clearError: () => 
      dispatch({ type: ACTION_TYPES.CLEAR_ERROR }),
    
    resetScanData: () => 
      dispatch({ type: ACTION_TYPES.RESET_SCAN_DATA }),
    
    // WebSocket methods
    startScan: (scanConfig) => {
      webSocketService.emitMessage(SOCKET_EVENTS.SCAN_STARTED, scanConfig);
    },
    
    stopScan: () => {
      webSocketService.emitMessage('stop_scan', { scan_id: state.currentScanId });
    },
    
    pauseScan: () => {
      webSocketService.emitMessage('pause_scan', { scan_id: state.currentScanId });
    },
    
    resumeScan: () => {
      webSocketService.emitMessage('resume_scan', { scan_id: state.currentScanId });
    },
  }), [dispatch, state.currentScanId]);

  // WebSocket event handlers
  useEffect(() => {
    // Connect to WebSocket
    webSocketService.connect();
    
    // Subscribe to events
    const unsubscribers = [
      webSocketService.subscribe(SOCKET_EVENTS.CONNECT, () => {
        actions.setConnectionStatus(true);
        actions.clearError();
      }),
      
      webSocketService.subscribe(SOCKET_EVENTS.DISCONNECT, () => {
        actions.setConnectionStatus(false);
      }),
      
      webSocketService.subscribe(SOCKET_EVENTS.SCAN_STARTED, (data) => {
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
      }),
      
      webSocketService.subscribe(SOCKET_EVENTS.SCAN_PROGRESS, (data) => {
        actions.setProgress(data.progress);
        actions.setCurrentPhase(data.phase);
        actions.addPersistentLog({
          timestamp: Date.now(),
          type: 'scan_progress',
          message: `${data.phase}: ${Math.round(data.progress)}%`,
          data
        });
      }),
      
      webSocketService.subscribe('scan_completed', (data) => {
        actions.setScanStatus(SCAN_STATUS.COMPLETED);
        actions.addPersistentLog({
          timestamp: Date.now(),
          type: 'scan_completed',
          message: 'Scan completed successfully',
          data
        });
      }),
      
      webSocketService.subscribe('scan_failed', (data) => {
        actions.setScanStatus(SCAN_STATUS.FAILED);
        actions.setError(data.error || 'Scan failed');
        actions.addPersistentLog({
          timestamp: Date.now(),
          type: 'scan_failed',
          message: `Scan failed: ${data.error}`,
          data
        });
      }),
      
      webSocketService.subscribe(SOCKET_EVENTS.TOOL_STARTED, (data) => {
        actions.addToolActivity(data);
        actions.addPersistentLog({
          timestamp: Date.now(),
          type: 'tool_started',
          message: `Tool started: ${data.tool}`,
          data
        });
      }),
      
      webSocketService.subscribe(SOCKET_EVENTS.TOOL_COMPLETED, (data) => {
        actions.updateToolActivity(data);
        actions.addPersistentLog({
          timestamp: Date.now(),
          type: 'tool_completed',
          message: `Tool completed: ${data.tool}`,
          data
        });
      }),
      
      webSocketService.subscribe(SOCKET_EVENTS.VULNERABILITY_FOUND, (data) => {
        actions.addVulnerability(data);
        actions.addPersistentLog({
          timestamp: Date.now(),
          type: 'vulnerability_found',
          message: `Vulnerability found: ${data.title}`,
          data
        });
      }),
      
      webSocketService.subscribe(SOCKET_EVENTS.CHAIN_DETECTED, (data) => {
        actions.addChain(data);
        actions.addPersistentLog({
          timestamp: Date.now(),
          type: 'chain_detected',
          message: 'Attack chain detected',
          data
        });
      }),
      
      webSocketService.subscribe(SOCKET_EVENTS.AI_INSIGHT, (data) => {
        actions.addAIInsight(data);
        actions.addPersistentLog({
          timestamp: Date.now(),
          type: 'ai_insight',
          message: 'AI Insight generated',
          data
        });
      }),
      
      webSocketService.subscribe(SOCKET_EVENTS.LOG_ENTRY, (data) => {
        actions.addPersistentLog({
          timestamp: Date.now(),
          type: 'log_entry',
          message: data.message,
          data
        });
      }),
    ];

    // Cleanup function
    return () => {
      unsubscribers.forEach(unsubscribe => unsubscribe());
      webSocketService.disconnect();
    };
  }, [actions]);

  const contextValue = {
    // State
    ...state,
    
    // Actions
    actions,
  };

  return (
    <ScanContext.Provider value={contextValue}>
      {children}
    </ScanContext.Provider>
  );
}

// Custom hook to use the scan context
export function useScan() {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error('useScan must be used within a ScanProvider');
  }
  return context;
}
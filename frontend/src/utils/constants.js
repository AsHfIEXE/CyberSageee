// Application Constants and Configuration
export const API_CONFIG = {
  BASE_URL: process.env.REACT_APP_BACKEND_URL || 'http://localhost:5000',
  WS_URL: process.env.REACT_APP_WS_URL || 'http://localhost:5000',
  ENDPOINTS: {
    SCAN: '/scan',
    VULNERABILITIES: '/vulnerabilities',
    HISTORY: '/history',
    REPEATER: '/repeater',
    HEALTH: '/health',
    STATS: '/stats',
  },
  TIMEOUT: {
    DEFAULT: 30000, // 30 seconds
    SCAN: 60000, // 60 seconds for scan operations
    EXPORT: 120000, // 2 minutes for exports
  },
  RETRY_CONFIG: {
    MAX_ATTEMPTS: 3,
    INITIAL_DELAY: 1000, // 1 second
    MAX_DELAY: 30000, // 30 seconds
    BACKOFF_MULTIPLIER: 2,
    JITTER: 0.1, // 10% jitter
  },
  CACHE_CONFIG: {
    ENABLED: true,
    DEFAULT_TTL: 300000, // 5 minutes
    SCAN_RESULTS_TTL: 600000, // 10 minutes
    VULNERABILITIES_TTL: 300000, // 5 minutes
    MAX_CACHE_SIZE: 50, // Maximum cached entries
  },
};

// Application Navigation Routes
export const ROUTES = {
  DASHBOARD: '/',
  SCANNER: '/scanner',
  VULNERABILITIES: '/vulnerabilities',
  CHAINS: '/chains',
  REPEATER: '/repeater',
  HISTORY: '/history',
  BLUEPRINT: '/blueprint',
  STATISTICS: '/statistics',
  TOOLS: '/tools',
};

// Navigation Configuration
export const NAVIGATION_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: '📊', desc: 'Overview & Stats', route: ROUTES.DASHBOARD },
  { id: 'scanner', label: 'Scanner', icon: '🎯', desc: 'Start New Scan', route: ROUTES.SCANNER },
  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: '⚠️', desc: 'View Findings', route: ROUTES.VULNERABILITIES },
  { id: 'repeater', label: 'Repeater', icon: '🔄', desc: 'HTTP Testing', route: ROUTES.REPEATER },
  { id: 'chains', label: 'Attack Chains', icon: '⛓️', desc: 'Linked Vulns', route: ROUTES.CHAINS },
  { id: 'tools', label: 'Tools', icon: '🛠️', desc: 'Pro Tools', route: ROUTES.TOOLS },
];

// Socket Event Names
export const SOCKET_EVENTS = {
  CONNECT: 'connect',
  DISCONNECT: 'disconnect',
  SCAN_STARTED: 'scan_started',
  SCAN_PROGRESS: 'scan_progress',
  SCAN_COMPLETED: 'scan_completed',
  TOOL_STARTED: 'tool_started',
  TOOL_COMPLETED: 'tool_completed',
  VULNERABILITY_FOUND: 'vulnerability_found',
  CHAIN_DETECTED: 'chain_detected',
  AI_INSIGHT: 'ai_insight',
  LOG_ENTRY: 'log_entry',
};

// Scan Status Types
export const SCAN_STATUS = {
  IDLE: 'idle',
  RUNNING: 'running',
  COMPLETED: 'completed',
  FAILED: 'failed',
  PAUSED: 'paused',
};

// Vulnerability Severity Levels
export const SEVERITY_LEVELS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
};

// Vulnerability Severity Colors
export const SEVERITY_COLORS = {
  critical: 'red',
  high: 'orange',
  medium: 'yellow',
  low: 'blue',
};

// WebSocket Connection States
export const WS_CONNECTION_STATES = {
  DISCONNECTED: 'disconnected',
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  RECONNECTING: 'reconnecting',
  FAILED: 'failed',
};

// API Error Types
export const ERROR_TYPES = {
  NETWORK_ERROR: 'network_error',
  TIMEOUT_ERROR: 'timeout_error',
  AUTHENTICATION_ERROR: 'authentication_error',
  VALIDATION_ERROR: 'validation_error',
  SERVER_ERROR: 'server_error',
  CONNECTION_ERROR: 'connection_error',
  RATE_LIMIT_ERROR: 'rate_limit_error',
};

// Cache Key Prefixes
export const CACHE_KEYS = {
  SCAN_RESULTS: 'scan_results',
  VULNERABILITIES: 'vulnerabilities',
  HISTORY: 'history',
  STATISTICS: 'statistics',
  HEALTH_STATUS: 'health_status',
};

// Performance Metrics
export const PERFORMANCE_CONFIG = {
  HEALTH_CHECK_INTERVAL: 30000, // 30 seconds
  WS_PING_INTERVAL: 25000, // 25 seconds
  METRICS_BATCH_SIZE: 10,
  METRICS_FLUSH_INTERVAL: 5000, // 5 seconds
};

// Request Queue Configuration
export const QUEUE_CONFIG = {
  MAX_QUEUE_SIZE: 100,
  FLUSH_INTERVAL: 1000, // 1 second
  PRIORITY_HIGH: 'high',
  PRIORITY_NORMAL: 'normal',
  PRIORITY_LOW: 'low',
};

// Rate Limiting
export const RATE_LIMIT_CONFIG = {
  REQUESTS_PER_MINUTE: 60,
  BURST_LIMIT: 10,
  WINDOW_SIZE: 60000, // 1 minute
};
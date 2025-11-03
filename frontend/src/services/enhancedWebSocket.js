import { io } from 'socket.io-client';
import { API_CONFIG, SOCKET_EVENTS, WS_CONNECTION_STATES } from '../utils/constants';
import { ErrorLogger } from '../utils/errors';
import { connectionMonitor } from '../utils/connection';

export class EnhancedWebSocketService {
  constructor() {
    this.socket = null;
    this.listeners = new Map();
    this.connectionState = WS_CONNECTION_STATES.DISCONNECTED;
    this.reconnectionAttempts = 0;
    this.maxReconnectionAttempts = 10;
    this.reconnectDelay = 1000;
    this.maxReconnectDelay = 30000;
    this.pingInterval = null;
    this.pongTimeout = null;
    this.lastPingTime = null;
    this.pingInterval = null;
    this.messageQueue = [];
    this.processingQueue = false;
    this.eventBuffer = [];
    this.bufferFlushInterval = null;
    this.metrics = {
      totalConnections: 0,
      successfulReconnections: 0,
      failedReconnections: 0,
      totalMessagesSent: 0,
      totalMessagesReceived: 0,
      averageLatency: 0,
      lastConnectionTime: null
    };
    this.healthCheckInterval = null;
    this.setupEventBuffering();
  }

  // Connect to WebSocket server
  connect() {
    if (this.socket && this.connectionState === WS_CONNECTION_STATES.CONNECTED) {
      return this.socket;
    }

    this.updateConnectionState(WS_CONNECTION_STATES.CONNECTING);

    const wsUrl = `${API_CONFIG.WS_URL}/scan`;
    
    try {
      this.socket = io(wsUrl, {
        transports: ['polling', 'websocket'],
        reconnection: false, // We'll handle reconnection manually
        timeout: 10000,
        forceNew: true,
      });

      this.setupEventListeners();
      this.setupHealthMonitoring();
      
      return this.socket;
    } catch (error) {
      this.updateConnectionState(WS_CONNECTION_STATES.FAILED);
      throw error;
    }
  }

  // Setup core event listeners
  setupEventListeners() {
    this.socket.on(SOCKET_EVENTS.CONNECT, () => {
      this.metrics.totalConnections++;
      this.metrics.lastConnectionTime = Date.now();
      this.reconnectionAttempts = 0;
      this.reconnectDelay = 1000;
      
      this.updateConnectionState(WS_CONNECTION_STATES.CONNECTED);
      this.startPingPong();
      this.processQueuedMessages();
      
      console.log('WebSocket connected');
      this.emit('connection', { connected: true, state: this.connectionState });
    });

    this.socket.on(SOCKET_EVENTS.DISCONNECT, (reason) => {
      this.updateConnectionState(WS_CONNECTION_STATES.DISCONNECTED);
      this.stopPingPong();
      
      console.log('WebSocket disconnected:', reason);
      this.emit('connection', { connected: false, state: this.connectionState, reason });
      
      // Attempt reconnection unless it was a manual disconnect
      if (reason !== 'io client disconnect') {
        this.scheduleReconnection();
      }
    });

    this.socket.on('connect_error', (error) => {
      this.metrics.failedReconnections++;
      this.updateConnectionState(WS_CONNECTION_STATES.FAILED);
      
      console.error('WebSocket connection error:', error);
      this.emit('connection', { 
        connected: false, 
        state: this.connectionState, 
        error: error.message 
      });
      
      this.scheduleReconnection();
    });

    this.socket.on('reconnect', (attempt) => {
      this.metrics.successfulReconnections++;
      console.log(`WebSocket reconnected after ${attempt} attempts`);
      this.emit('connection', { 
        connected: true, 
        state: this.connectionState, 
        reconnected: true, 
        attempt 
      });
    });

    // Setup ping/pong handlers
    this.socket.on('pong', () => {
      this.handlePong();
    });

    // Handle all Socket.IO events
    this.socket.onAny((eventName, ...args) => {
      this.handleIncomingMessage(eventName, args);
    });
  }

  // Setup ping/pong for connection health
  startPingPong() {
    this.stopPingPong();
    
    this.pingInterval = setInterval(() => {
      if (this.connectionState === WS_CONNECTION_STATES.CONNECTED) {
        this.sendPing();
      }
    }, 25000); // Ping every 25 seconds
  }

  stopPingPong() {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
    
    if (this.pongTimeout) {
      clearTimeout(this.pongTimeout);
      this.pongTimeout = null;
    }
  }

  sendPing() {
    if (this.socket && this.connectionState === WS_CONNECTION_STATES.CONNECTED) {
      this.lastPingTime = Date.now();
      this.socket.emit('ping');
      
      // Set pong timeout
      this.pongTimeout = setTimeout(() => {
        console.warn('WebSocket pong timeout - connection may be stale');
        this.handleConnectionStale();
      }, 10000); // 10 second timeout
    }
  }

  handlePong() {
    if (this.pongTimeout) {
      clearTimeout(this.pongTimeout);
      this.pongTimeout = null;
    }
    
    if (this.lastPingTime) {
      const latency = Date.now() - this.lastPingTime;
      this.metrics.averageLatency = 
        (this.metrics.averageLatency + latency) / 2;
      
      connectionMonitor.recordRequest(true, latency);
      this.lastPingTime = null;
    }
  }

  handleConnectionStale() {
    console.warn('WebSocket connection detected as stale, forcing reconnection');
    this.disconnect();
    this.scheduleReconnection(0); // Immediate reconnection
  }

  // Setup health monitoring
  setupHealthMonitoring() {
    this.healthCheckInterval = setInterval(() => {
      if (this.connectionState === WS_CONNECTION_STATES.CONNECTED) {
        this.performHealthCheck();
      }
    }, 30000); // Check every 30 seconds
  }

  async performHealthCheck() {
    try {
      const response = await fetch(`${API_CONFIG.WS_URL}/health`, {
        method: 'GET',
        cache: 'no-cache'
      });
      
      const isHealthy = response.ok;
      const timestamp = Date.now();
      
      this.emit('healthCheck', { 
        healthy: isHealthy, 
        status: response.status, 
        timestamp 
      });
      
      if (!isHealthy) {
        console.warn('WebSocket health check failed');
      }
    } catch (error) {
      this.emit('healthCheck', { 
        healthy: false, 
        error: error.message, 
        timestamp: Date.now() 
      });
    }
  }

  // Schedule reconnection with exponential backoff
  scheduleReconnection(delay = null) {
    if (this.reconnectionAttempts >= this.maxReconnectionAttempts) {
      console.error('Max reconnection attempts reached');
      this.updateConnectionState(WS_CONNECTION_STATES.FAILED);
      return;
    }

    const reconnectDelay = delay || this.calculateReconnectDelay();
    this.reconnectionAttempts++;
    
    this.updateConnectionState(WS_CONNECTION_STATES.RECONNECTING);
    
    console.log(`Scheduling WebSocket reconnection in ${reconnectDelay}ms (attempt ${this.reconnectionAttempts})`);
    
    setTimeout(() => {
      if (this.connectionState === WS_CONNECTION_STATES.RECONNECTING) {
        this.connect();
      }
    }, reconnectDelay);
  }

  calculateReconnectDelay() {
    const exponentialDelay = Math.min(
      this.reconnectDelay * Math.pow(2, this.reconnectionAttempts - 1),
      this.maxReconnectDelay
    );
    
    // Add jitter
    const jitter = exponentialDelay * 0.1 * (Math.random() - 0.5) * 2;
    
    return Math.max(1000, exponentialDelay + jitter);
  }

  // Update connection state
  updateConnectionState(newState) {
    const oldState = this.connectionState;
    this.connectionState = newState;
    
    if (oldState !== newState) {
      this.emit('stateChange', { 
        oldState, 
        newState, 
        timestamp: Date.now() 
      });
    }
  }

  // Handle incoming messages with buffering
  handleIncomingMessage(eventName, args) {
    const message = {
      eventName,
      data: args.length === 1 ? args[0] : args,
      timestamp: Date.now(),
      id: this.generateMessageId()
    };

    // Buffer high-frequency events
    if (this.isHighFrequencyEvent(eventName)) {
      this.eventBuffer.push(message);
      return;
    }

    // Emit immediately for low-frequency events
    this.emit(eventName, message.data);
    this.metrics.totalMessagesReceived++;
  }

  // Setup event buffering for performance
  setupEventBuffering() {
    this.bufferFlushInterval = setInterval(() => {
      this.flushEventBuffer();
    }, 100); // Flush every 100ms
  }

  flushEventBuffer() {
    if (this.eventBuffer.length === 0) return;

    // Group events by type
    const groupedEvents = this.eventBuffer.reduce((groups, event) => {
      if (!groups[event.eventName]) {
        groups[event.eventName] = [];
      }
      groups[event.eventName].push(event.data);
      return groups;
    }, {});

    // Emit grouped events
    Object.entries(groupedEvents).forEach(([eventName, dataArray]) => {
      this.emit(eventName, dataArray);
      this.metrics.totalMessagesReceived += dataArray.length;
    });

    this.eventBuffer = [];
  }

  // Check if event is high frequency
  isHighFrequencyEvent(eventName) {
    const highFrequencyEvents = [
      SOCKET_EVENTS.SCAN_PROGRESS,
      SOCKET_EVENTS.LOG_ENTRY
    ];
    return highFrequencyEvents.includes(eventName);
  }

  // Subscribe to events
  subscribe(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    
    this.listeners.get(event).add(callback);
    
    // Setup listener on socket if connected
    if (this.socket && this.connectionState === WS_CONNECTION_STATES.CONNECTED) {
      this.socket.on(event, callback);
    }
    
    // Return unsubscribe function
    return () => {
      this.unsubscribe(event, callback);
    };
  }

  // Unsubscribe from events
  unsubscribe(event, callback) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).delete(callback);
    }
    
    if (this.socket) {
      this.socket.off(event, callback);
    }
  }

  // Emit event (mainly for internal use)
  emit(event, data) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          console.error('Error in WebSocket event listener:', error);
          ErrorLogger.log(error, { event, data });
        }
      });
    }
  }

  // Send message to server with queue support
  emitMessage(event, data, options = {}) {
    const message = {
      event,
      data,
      timestamp: Date.now(),
      id: this.generateMessageId(),
      ...options
    };

    if (this.connectionState === WS_CONNECTION_STATES.CONNECTED && this.socket) {
      try {
        this.socket.emit(event, data);
        this.metrics.totalMessagesSent++;
        return { sent: true, messageId: message.id };
      } catch (error) {
        console.warn('Failed to send WebSocket message:', error);
        this.queueMessage(message);
        return { sent: false, queued: true, messageId: message.id };
      }
    } else {
      this.queueMessage(message);
      return { sent: false, queued: true, messageId: message.id };
    }
  }

  // Queue message for later sending
  queueMessage(message) {
    if (this.messageQueue.length >= 1000) {
      console.warn('WebSocket message queue is full, dropping message');
      return;
    }
    
    this.messageQueue.push(message);
    this.emit('messageQueued', message);
  }

  // Process queued messages
  async processQueuedMessages() {
    if (this.processingQueue || this.messageQueue.length === 0) {
      return;
    }

    this.processingQueue = true;

    try {
      while (this.messageQueue.length > 0) {
        const message = this.messageQueue.shift();
        
        try {
          this.socket.emit(message.event, message.data);
          this.metrics.totalMessagesSent++;
          this.emit('messageSent', message);
        } catch (error) {
          console.warn('Failed to send queued message, re-queuing:', error);
          // Re-queue failed messages
          this.messageQueue.unshift(message);
          break;
        }
        
        // Small delay to prevent overwhelming the server
        await this.delay(10);
      }
    } finally {
      this.processingQueue = false;
    }
  }

  // Delay utility
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Generate unique message ID
  generateMessageId() {
    return `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Disconnect WebSocket
  disconnect() {
    this.stopPingPong();
    
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }
    
    if (this.bufferFlushInterval) {
      clearInterval(this.bufferFlushInterval);
      this.bufferFlushInterval = null;
    }

    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }

    this.updateConnectionState(WS_CONNECTION_STATES.DISCONNECTED);
    this.messageQueue = [];
    this.eventBuffer = [];
    
    // Clear all listeners
    this.listeners.clear();
  }

  // Get connection status
  isConnected() {
    return this.connectionState === WS_CONNECTION_STATES.CONNECTED;
  }

  // Get detailed connection status
  getConnectionStatus() {
    return {
      state: this.connectionState,
      connected: this.isConnected(),
      socket: this.socket ? this.socket.connected : false,
      reconnectionAttempts: this.reconnectionAttempts,
      maxReconnectionAttempts: this.maxReconnectionAttempts,
      messageQueueSize: this.messageQueue.length,
      eventBufferSize: this.eventBuffer.length,
      metrics: { ...this.metrics },
      latency: this.metrics.averageLatency,
      lastConnectionTime: this.metrics.lastConnectionTime
    };
  }

  // Get performance metrics
  getMetrics() {
    const uptime = this.metrics.lastConnectionTime 
      ? Date.now() - this.metrics.lastConnectionTime 
      : 0;

    return {
      ...this.metrics,
      uptime,
      connectionState: this.connectionState,
      messageQueueSize: this.messageQueue.length,
      eventBufferSize: this.eventBuffer.length
    };
  }

  // Force reconnection
  forceReconnect() {
    this.disconnect();
    this.scheduleReconnection(0);
  }

  // Set maximum reconnection attempts
  setMaxReconnectionAttempts(maxAttempts) {
    this.maxReconnectionAttempts = maxAttempts;
  }

  // Get socket instance
  getSocket() {
    return this.socket;
  }

  // Cleanup
  destroy() {
    this.disconnect();
    
    // Clean up intervals
    if (this.pingInterval) clearInterval(this.pingInterval);
    if (this.pongTimeout) clearTimeout(this.pongTimeout);
    if (this.healthCheckInterval) clearInterval(this.healthCheckInterval);
    if (this.bufferFlushInterval) clearInterval(this.bufferFlushInterval);
  }
}

// Create and export singleton instance
export const enhancedWebSocketService = new EnhancedWebSocketService();

// Export the enhanced service class for custom usage
export default EnhancedWebSocketService;
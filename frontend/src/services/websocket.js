import { io } from 'socket.io-client';
import { API_CONFIG, SOCKET_EVENTS } from '../utils/constants';

class WebSocketService {
  constructor() {
    this.socket = null;
    this.listeners = new Map();
    this.connected = false;
    this.reconnectionAttempts = 0;
    this.maxReconnectionAttempts = 5;
  }

  // Connect to WebSocket server
  connect() {
    if (this.socket && this.connected) {
      return this.socket;
    }

    const wsUrl = `${API_CONFIG.WS_URL}/scan`;
    
    this.socket = io(wsUrl, {
      transports: ['polling', 'websocket'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      maxReconnectionAttempts: this.maxReconnectionAttempts,
    });

    this.setupEventListeners();
    return this.socket;
  }

  // Setup core event listeners
  setupEventListeners() {
    this.socket.on(SOCKET_EVENTS.CONNECT, () => {
      this.connected = true;
      this.reconnectionAttempts = 0;
      console.log('WebSocket connected');
      this.emit('connection', { connected: true });
    });

    this.socket.on(SOCKET_EVENTS.DISCONNECT, () => {
      this.connected = false;
      console.log('WebSocket disconnected');
      this.emit('connection', { connected: false });
    });

    this.socket.on('connect_error', (error) => {
      this.reconnectionAttempts++;
      console.error('WebSocket connection error:', error);
      this.emit('connection', { connected: false, error });
    });

    this.socket.on('reconnect', (attempt) => {
      console.log(`WebSocket reconnected after ${attempt} attempts`);
      this.emit('connection', { connected: true, reconnected: true });
    });
  }

  // Subscribe to events
  subscribe(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    
    this.listeners.get(event).add(callback);
    
    // Setup listener on socket if not already set
    if (!this.socket) {
      this.connect();
    }
    
    this.socket.on(event, callback);
    
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
        }
      });
    }
  }

  // Send message to server
  emitMessage(event, data) {
    if (this.socket && this.connected) {
      this.socket.emit(event, data);
    } else {
      console.warn('WebSocket not connected, message not sent:', event, data);
    }
  }

  // Disconnect WebSocket
  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
      this.connected = false;
      
      // Clear all listeners
      this.listeners.clear();
    }
  }

  // Get connection status
  isConnected() {
    return this.connected && this.socket && this.socket.connected;
  }

  // Get socket instance
  getSocket() {
    return this.socket;
  }
}

// Create and export singleton instance
const webSocketService = new WebSocketService();

export default webSocketService;
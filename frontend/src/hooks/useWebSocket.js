import { useState, useEffect } from 'react';
import { io } from 'socket.io-client';

/**
 * Enhanced WebSocket Hook for CyberSage v2.0
 * With comprehensive debugging and fallback mechanisms
 */
export const useWebSocket = () => {
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);
  const [backendUrl, setBackendUrl] = useState(null);
  const [debugInfo, setDebugInfo] = useState([]);

  // Debug logging function
  const debugLog = (type, message, data = null) => {
    const timestamp = new Date().toISOString();
    const logEntry = { timestamp, type, message, data };
    console.log(`[${type}] ${message}`, data || '');
    setDebugInfo(prev => [...prev.slice(-9), logEntry]); // Keep last 10 entries
  };

  useEffect(() => {
    debugLog('INFO', 'WebSocket hook initialized');

    // Force backend URL to localhost:5000 for now
    const detectBackendUrl = async () => {
      const urls = [
        'http://localhost:5000',
        'http://127.0.0.1:5000',
        'http://192.168.0.102:5000'
      ];

      debugLog('INFO', 'Testing backend URLs:', urls);

      for (const url of urls) {
        try {
          debugLog('TEST', `Testing: ${url}/api/health`);

          const response = await fetch(`${url}/api/health`, {
            method: 'GET',
            headers: {
              'Accept': 'application/json',
              'Content-Type': 'application/json'
            }
          });

          if (response.ok) {
            const data = await response.json();
            debugLog('SUCCESS', `Backend found at: ${url}`, data);
            return url;
          }
        } catch (error) {
          debugLog('ERROR', `Failed to reach ${url}: ${error.message}`);
        }
      }

      debugLog('WARNING', 'No backend found, using localhost:5000 as fallback');
      return 'http://localhost:5000';
    };

    // Initialize connection
    const initializeSocket = async () => {
      try {
        const discoveredUrl = await detectBackendUrl();
        setBackendUrl(discoveredUrl);

        debugLog('INFO', 'Initializing WebSocket connection to:', discoveredUrl);

        // Create socket connection with optimized configuration
        const newSocket = io(`${discoveredUrl}/scan`, {
          transports: ['websocket', 'polling'], // Try websocket first
          reconnection: true,
          reconnectionDelay: 1000,
          reconnectionDelayMax: 5000,
          reconnectionAttempts: 5,
          timeout: 10000,
          upgrade: true,
          forceNew: true,
          autoConnect: true,
          withCredentials: false,
          path: '/socket.io',
          query: {
            EIO: '4',
            transport: 'websocket'
          }
        });

        // Add comprehensive event logging
        newSocket.onAny((event, ...args) => {
          debugLog('EVENT', `Socket event: ${event}`, args);
        });

        // Connection event handlers
        newSocket.on('connect', () => {
          debugLog('SUCCESS', 'WebSocket connected successfully!');
          debugLog('INFO', `Socket ID: ${newSocket.id}`);
          debugLog('INFO', `Transport: ${newSocket.io.engine.transport.name}`);
          debugLog('INFO', `Backend URL: ${discoveredUrl}`);
          setConnected(true);
          setReconnecting(false);

          // Send a test message immediately after connection
          setTimeout(() => {
            newSocket.emit('ping');
            debugLog('TEST', 'Sent ping after connection');
          }, 100);
        });

        newSocket.on('disconnect', (reason) => {
          debugLog('ERROR', `WebSocket disconnected: ${reason}`);
          setConnected(false);

          if (reason === 'io server disconnect') {
            debugLog('INFO', 'Server disconnected, will attempt reconnect');
            setTimeout(() => newSocket.connect(), 1000);
          }
        });

        newSocket.on('connect_error', (error) => {
          debugLog('ERROR', 'WebSocket connection error:', error);
          debugLog('ERROR', `Error message: ${error.message}`);
          debugLog('ERROR', `Error type: ${error.type}`);
          setConnected(false);
          setReconnecting(true);
        });

        newSocket.on('reconnect_attempt', (attemptNumber) => {
          debugLog('INFO', `Reconnection attempt ${attemptNumber}...`);
          setReconnecting(true);
        });

        newSocket.on('reconnect', (attemptNumber) => {
          debugLog('SUCCESS', `Reconnected after ${attemptNumber} attempts`);
          setConnected(true);
          setReconnecting(false);
        });

        newSocket.on('reconnect_failed', () => {
          debugLog('ERROR', 'Reconnection failed after all attempts');
          setConnected(false);
          setReconnecting(false);
        });

        newSocket.on('error', (error) => {
          debugLog('ERROR', 'Socket error:', error);
        });

        // Handle ping/pong for connection health
        newSocket.on('pong', (data) => {
          debugLog('INFO', 'Pong received - Connection healthy', data);
        });

        // Backend-specific events
        newSocket.on('connected', (data) => {
          debugLog('SUCCESS', 'Backend connected event received', data);
        });

        newSocket.on('test_response', (data) => {
          debugLog('SUCCESS', 'Test connection response received', data);
        });

        newSocket.on('scan_started', (data) => {
          debugLog('INFO', 'Scan started event received', data);
        });

        newSocket.on('scan_completed', (data) => {
          debugLog('INFO', 'Scan completed event received', data);
        });

        newSocket.on('vulnerability_found', (data) => {
          debugLog('INFO', 'Vulnerability found event received', data);
        });

        setSocket(newSocket);

        // Send test connection immediately after setup
        setTimeout(() => {
          debugLog('TEST', 'Sending test connection');
          newSocket.emit('test_connection', {
            timestamp: Date.now(),
            test: 'WebSocket connection test',
            frontend: 'CyberSage v2.0 Frontend'
          });
        }, 500);

        // Cleanup on unmount
        return () => {
          debugLog('INFO', 'Cleaning up WebSocket connection');
          newSocket.close();
        };

      } catch (error) {
        debugLog('ERROR', 'Failed to initialize WebSocket:', error);
      }
    };

    initializeSocket();
  }, []);

  // Helper: Check connection health
  const checkConnection = () => {
    if (socket && socket.connected) {
      debugLog('TEST', 'Sending ping to check connection');
      socket.emit('ping');
      return true;
    }
    debugLog('WARNING', 'Socket not connected');
    return false;
  };

  // Helper: Manual reconnect
  const reconnect = () => {
    if (socket) {
      debugLog('INFO', 'Manual reconnection triggered');
      socket.disconnect();
      setTimeout(() => socket.connect(), 1000);
    }
  };

  // Helper: Get current backend URL
  const getBackendUrl = () => {
    return backendUrl;
  };

  // Helper: Get connection info for debugging
  const getConnectionInfo = () => {
    if (!socket) return null;

    return {
      connected: socket.connected,
      id: socket.id,
      backendUrl: backendUrl,
      transport: socket.io?.engine?.transport?.name,
      protocol: 'EIO=4 (Socket.IO v4)',
      state: socket.io?.engine?.readyState,
      debugLogs: debugInfo
    };
  };

  return {
    socket,
    connected,
    reconnecting,
    checkConnection,
    reconnect,
    backendUrl: getBackendUrl(),
    connectionInfo: getConnectionInfo(),
    debugInfo
  };
};
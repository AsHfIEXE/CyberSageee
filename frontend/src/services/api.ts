/**
 * CyberSage API Integration Service
 * Connects the new security testing frontend to the existing CyberSage backend
 */

import { io, Socket } from 'socket.io-client';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';
const WEBSOCKET_URL = import.meta.env.VITE_WEBSOCKET_URL || 'http://localhost:5000';

interface ApiResponse<T = any> {
  status?: string;
  message?: string;
  data?: T;
  error?: string;
}

interface HttpRequestPayload {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  timeout?: number;
  scan_id?: string;
}

interface ScanOptions {
  intensity?: 'quick' | 'normal' | 'deep' | 'elite';
  auth?: Record<string, any>;
  policy?: Record<string, any>;
  spiderConfig?: Record<string, any>;
  tools?: Record<string, any>;
}

interface ScanResult {
  scan_id: string;
  status: string;
  summary: {
    total_vulnerabilities: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    scan_duration?: string;
    tools_executed?: number;
  };
  vulnerabilities?: any[];
  technical_details?: any;
}

class CyberSageAPI {
  private socket: Socket | null = null;
  private apiKey: string = 'development-key'; // For development, would be user-specific

  constructor() {
    this.initializeWebSocket();
  }

  private initializeWebSocket() {
    this.socket = io(WEBSOCKET_URL, {
      auth: { token: this.apiKey },
      transports: ['websocket', 'polling']
    });

    this.socket.on('connect', () => {
      console.log('✅ Connected to CyberSage WebSocket');
    });

    this.socket.on('disconnect', () => {
      console.log('❌ Disconnected from CyberSage WebSocket');
    });
  }

  // HTTP Repeater Methods
  async sendHttpRequest(payload: HttpRequestPayload): Promise<ApiResponse> {
    try {
      const response = await fetch(`${API_BASE_URL}/api/repeater/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      return { status: 'success', data };
    } catch (error) {
      console.error('HTTP Request failed:', error);
      return { 
        status: 'error', 
        error: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }

  // Scan Management Methods
  async startScan(target: string, mode: string = 'elite', options: ScanOptions = {}): Promise<string | null> {
    return new Promise((resolve, reject) => {
      if (!this.socket) {
        reject(new Error('WebSocket not connected'));
        return;
      }

      const scanData = {
        target,
        mode,
        ...options
      };

      this.socket.emit('start_scan', scanData, (response: any) => {
        if (response?.error) {
          reject(new Error(response.error));
        } else {
          resolve(response?.scan_id || null);
        }
      });
    });
  }

  async stopScan(scanId: string): Promise<boolean> {
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve(false);
        return;
      }

      this.socket.emit('stop_scan', { scan_id: scanId }, (response: any) => {
        resolve(!response?.error);
      });
    });
  }

  async getScanResults(scanId: string): Promise<ApiResponse<ScanResult>> {
    try {
      const response = await fetch(`${API_BASE_URL}/api/scan/${scanId}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      return { status: 'success', data };
    } catch (error) {
      return { 
        status: 'error', 
        error: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }

  async getAllScans(): Promise<ApiResponse<any[]>> {
    try {
      const response = await fetch(`${API_BASE_URL}/api/scans`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      return { status: 'success', data: data.scans };
    } catch (error) {
      return { 
        status: 'error', 
        error: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }

  async exportScanResults(scanId: string, format: 'json' | 'pdf' = 'json'): Promise<ApiResponse> {
    try {
      const endpoint = format === 'pdf' ? 'pdf' : '';
      const response = await fetch(`${API_BASE_URL}/api/scan/${scanId}/export${endpoint ? `/${endpoint}` : ''}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      if (format === 'pdf') {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cybersage-scan-${scanId}.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      }

      return { status: 'success' };
    } catch (error) {
      return { 
        status: 'error', 
        error: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }

  async analyzeForm(formData: any): Promise<ApiResponse> {
    try {
      const response = await fetch(`${API_BASE_URL}/api/forms/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`
        },
        body: JSON.stringify({ form_data: formData })
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      return { status: 'success', data };
    } catch (error) {
      return { 
        status: 'error', 
        error: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }

  // WebSocket Event Listeners
  onScanStarted(callback: (data: any) => void) {
    this.socket?.on('scan_started', callback);
  }

  onScanProgress(callback: (data: any) => void) {
    this.socket?.on('scan_progress', callback);
  }

  onScanCompleted(callback: (data: any) => void) {
    this.socket?.on('scan_completed', callback);
  }

  onScanError(callback: (data: any) => void) {
    this.socket?.on('scan_error', callback);
  }

  onVulnerabilityDiscovered(callback: (data: any) => void) {
    this.socket?.on('vulnerability_discovered', callback);
  }

  onToolStatus(callback: (data: any) => void) {
    this.socket?.on('tool_status', callback);
  }

  onScanStatus(callback: (data: any) => void) {
    this.socket?.on('scan_status', callback);
  }

  // Utility Methods
  testConnection(): Promise<boolean> {
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve(false);
        return;
      }

      this.socket.emit('test_connection', { timestamp: Date.now() }, (response: any) => {
        resolve(response?.status === 'success');
      });
    });
  }

  disconnect() {
    this.socket?.disconnect();
  }

  isConnected(): boolean {
    return this.socket?.connected || false;
  }
}

// Export singleton instance
export const apiService = new CyberSageAPI();
export default apiService;

// Export types for use in components
export type {
  HttpRequestPayload,
  ScanOptions,
  ScanResult,
  ApiResponse
};

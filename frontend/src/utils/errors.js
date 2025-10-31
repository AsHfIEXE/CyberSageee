import { ERROR_TYPES } from '../utils/constants';

// Enhanced Error Classes
export class ApiError extends Error {
  constructor(message, type = ERROR_TYPES.NETWORK_ERROR, status = null, details = {}) {
    super(message);
    this.name = 'ApiError';
    this.type = type;
    this.status = status;
    this.details = details;
    this.timestamp = Date.now();
  }

  isNetworkError() {
    return this.type === ERROR_TYPES.NETWORK_ERROR;
  }

  isTimeoutError() {
    return this.type === ERROR_TYPES.TIMEOUT_ERROR;
  }

  isServerError() {
    return this.status >= 500;
  }

  isClientError() {
    return this.status >= 400 && this.status < 500;
  }

  isRetryable() {
    return [
      ERROR_TYPES.NETWORK_ERROR,
      ERROR_TYPES.TIMEOUT_ERROR,
      ERROR_TYPES.SERVER_ERROR,
      ERROR_TYPES.CONNECTION_ERROR
    ].includes(this.type) || this.isServerError();
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      type: this.type,
      status: this.status,
      details: this.details,
      timestamp: this.timestamp,
      stack: this.stack
    };
  }
}

export class NetworkError extends ApiError {
  constructor(message = 'Network connection failed', details = {}) {
    super(message, ERROR_TYPES.NETWORK_ERROR, null, details);
    this.name = 'NetworkError';
  }
}

export class TimeoutError extends ApiError {
  constructor(timeout = 30000, details = {}) {
    super(`Request timeout after ${timeout}ms`, ERROR_TYPES.TIMEOUT_ERROR, null, { timeout, ...details });
    this.name = 'TimeoutError';
  }
}

export class ServerError extends ApiError {
  constructor(message = 'Server error', status = 500, details = {}) {
    super(message, ERROR_TYPES.SERVER_ERROR, status, details);
    this.name = 'ServerError';
  }
}

export class AuthenticationError extends ApiError {
  constructor(message = 'Authentication failed', status = 401, details = {}) {
    super(message, ERROR_TYPES.AUTHENTICATION_ERROR, status, details);
    this.name = 'AuthenticationError';
  }
}

export class ValidationError extends ApiError {
  constructor(message = 'Validation failed', status = 400, details = {}) {
    super(message, ERROR_TYPES.VALIDATION_ERROR, status, details);
    this.name = 'ValidationError';
  }
}

export class RateLimitError extends ApiError {
  constructor(message = 'Rate limit exceeded', status = 429, details = {}) {
    super(message, ERROR_TYPES.RATE_LIMIT_ERROR, status, details);
    this.name = 'RateLimitError';
  }
}

// Error Factory
export class ErrorFactory {
  static createFromResponse(response, data = null) {
    const status = response.status;
    const message = response.statusText || 'HTTP Error';
    
    let errorClass = ApiError;
    
    if (status === 401) {
      errorClass = AuthenticationError;
    } else if (status === 400) {
      errorClass = ValidationError;
    } else if (status === 429) {
      errorClass = RateLimitError;
    } else if (status >= 500) {
      errorClass = ServerError;
    }
    
    return new errorClass(message, status, {
      response: response.statusText,
      status,
      data,
      url: response.url
    });
  }

  static createFromError(error) {
    if (error instanceof ApiError) {
      return error;
    }

    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      return new NetworkError('Failed to connect to server', {
        originalError: error.message
      });
    }

    if (error.name === 'AbortError') {
      return new TimeoutError('Request was aborted', {
        originalError: error.message
      });
    }

    return new ApiError(error.message || 'Unknown error', ERROR_TYPES.NETWORK_ERROR, null, {
      originalError: error.toString(),
      stack: error.stack
    });
  }

  static createTimeoutError(timeout) {
    return new TimeoutError(timeout);
  }

  static createNetworkError(message = 'Network connection failed') {
    return new NetworkError(message);
  }
}

// User-friendly error messages
export class ErrorMessages {
  static getMessage(error) {
    if (error.isNetworkError()) {
      return 'Unable to connect to the server. Please check your internet connection.';
    }
    
    if (error.isTimeoutError()) {
      return 'The request took too long to complete. Please try again.';
    }
    
    if (error.isClientError()) {
      if (error.status === 401) {
        return 'Your session has expired. Please log in again.';
      }
      if (error.status === 403) {
        return 'You do not have permission to perform this action.';
      }
      if (error.status === 404) {
        return 'The requested resource was not found.';
      }
      if (error.status === 429) {
        return 'Too many requests. Please wait a moment and try again.';
      }
      return 'There was a problem with your request. Please check the data and try again.';
    }
    
    if (error.isServerError()) {
      return 'The server is temporarily unavailable. Please try again later.';
    }
    
    return error.message || 'An unexpected error occurred. Please try again.';
  }

  static getTechnicalDetails(error) {
    if (process.env.NODE_ENV === 'development') {
      return {
        type: error.type,
        status: error.status,
        message: error.message,
        timestamp: new Date(error.timestamp).toISOString(),
        stack: error.stack
      };
    }
    return null;
  }
}

// Error Logger
export class ErrorLogger {
  static logs = [];
  static maxLogs = 100;

  static log(error, context = {}) {
    const logEntry = {
      timestamp: Date.now(),
      error: error.toJSON ? error.toJSON() : error,
      context,
      userAgent: navigator.userAgent,
      url: window.location.href
    };

    this.logs.unshift(logEntry);
    
    if (this.logs.length > this.maxLogs) {
      this.logs = this.logs.slice(0, this.maxLogs);
    }

    // Log to console in development
    if (process.env.NODE_ENV === 'development') {
      console.error('API Error:', logEntry);
    }

    return logEntry;
  }

  static getLogs(filter = {}) {
    return this.logs.filter(log => {
      if (filter.type && log.error.type !== filter.type) return false;
      if (filter.status && log.error.status !== filter.status) return false;
      if (filter.since && log.timestamp < filter.since) return false;
      return true;
    });
  }

  static clearLogs() {
    this.logs = [];
  }

  static getStats() {
    const stats = {};
    this.logs.forEach(log => {
      const type = log.error.type || 'unknown';
      stats[type] = (stats[type] || 0) + 1;
    });
    return stats;
  }
}
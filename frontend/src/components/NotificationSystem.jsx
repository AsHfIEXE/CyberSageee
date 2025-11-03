import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import toast, { Toaster } from 'react-hot-toast';
import {
  AlertTriangle, CheckCircle, XCircle, Info, 
  Zap, Shield, Bug, X, Bell, BellOff
} from 'lucide-react';

// Custom toast component for vulnerabilities
export const VulnerabilityToast = ({ vulnerability, onView }) => (
  <motion.div
    initial={{ scale: 0.9, opacity: 0 }}
    animate={{ scale: 1, opacity: 1 }}
    className="flex items-start space-x-3 p-4 bg-gray-900 rounded-lg border border-red-500/30 shadow-xl max-w-md"
  >
    <div className="flex-shrink-0">
      <div className="p-2 bg-red-500/20 rounded-lg">
        <AlertTriangle className="w-5 h-5 text-red-500" />
      </div>
    </div>
    <div className="flex-1">
      <div className="flex items-center justify-between mb-1">
        <p className="font-semibold text-white">Vulnerability Found!</p>
        <span className="px-2 py-0.5 bg-red-500/20 text-red-400 text-xs rounded-full">
          {vulnerability.severity}
        </span>
      </div>
      <p className="text-sm text-gray-300 mb-2">{vulnerability.type}</p>
      <p className="text-xs text-gray-500 font-mono mb-3">
        {vulnerability.url?.substring(0, 50)}...
      </p>
      <button
        onClick={onView}
        className="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-xs rounded-lg transition-colors"
      >
        View Details
      </button>
    </div>
  </motion.div>
);

// Notification center component
export const NotificationCenter = ({ notifications = [], onClear, onViewAll }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const [mutedTypes, setMutedTypes] = useState(new Set());

  useEffect(() => {
    setUnreadCount(notifications.filter(n => !n.read).length);
  }, [notifications]);

  const toggleMute = (type) => {
    const newMuted = new Set(mutedTypes);
    if (newMuted.has(type)) {
      newMuted.delete(type);
    } else {
      newMuted.add(type);
    }
    setMutedTypes(newMuted);
  };

  const getNotificationIcon = (type) => {
    switch (type) {
      case 'vulnerability': return AlertTriangle;
      case 'scan_complete': return CheckCircle;
      case 'error': return XCircle;
      case 'info': return Info;
      case 'critical': return Zap;
      default: return Bell;
    }
  };

  const getNotificationColor = (type) => {
    switch (type) {
      case 'vulnerability': return 'text-yellow-500';
      case 'scan_complete': return 'text-green-500';
      case 'error': return 'text-red-500';
      case 'info': return 'text-blue-500';
      case 'critical': return 'text-red-600';
      default: return 'text-gray-500';
    }
  };

  return (
    <>
      {/* Notification Bell */}
      <div className="relative">
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          onClick={() => setIsOpen(!isOpen)}
          className="relative p-2 hover:bg-gray-800 rounded-lg transition-colors"
        >
          <Bell className="w-5 h-5 text-gray-400" />
          {unreadCount > 0 && (
            <motion.span
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              className="absolute -top-1 -right-1 px-1.5 py-0.5 bg-red-500 text-white text-xs rounded-full min-w-[20px] text-center"
            >
              {unreadCount > 99 ? '99+' : unreadCount}
            </motion.span>
          )}
        </motion.button>

        {/* Notification Dropdown */}
        <AnimatePresence>
          {isOpen && (
            <motion.div
              initial={{ opacity: 0, y: -10, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -10, scale: 0.95 }}
              className="absolute right-0 mt-2 w-96 bg-gray-900 rounded-xl shadow-2xl border border-gray-800 z-50"
            >
              {/* Header */}
              <div className="p-4 border-b border-gray-800">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-white">Notifications</h3>
                  <div className="flex items-center space-x-2">
                    {notifications.length > 0 && (
                      <button
                        onClick={onClear}
                        className="text-xs text-gray-400 hover:text-white transition-colors"
                      >
                        Clear All
                      </button>
                    )}
                    <button
                      onClick={() => setIsOpen(false)}
                      className="p-1 hover:bg-gray-800 rounded transition-colors"
                    >
                      <X className="w-4 h-4 text-gray-400" />
                    </button>
                  </div>
                </div>
              </div>

              {/* Notifications List */}
              <div className="max-h-96 overflow-y-auto">
                {notifications.length > 0 ? (
                  notifications.slice(0, 10).map((notification, index) => {
                    const Icon = getNotificationIcon(notification.type);
                    const isMuted = mutedTypes.has(notification.type);
                    
                    return (
                      <motion.div
                        key={notification.id || index}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: isMuted ? 0.5 : 1, x: 0 }}
                        transition={{ delay: index * 0.05 }}
                        className={`p-4 border-b border-gray-800 hover:bg-gray-800/50 transition-colors ${
                          !notification.read ? 'bg-purple-500/5' : ''
                        }`}
                      >
                        <div className="flex items-start space-x-3">
                          <div className={`p-2 bg-gray-800 rounded-lg ${getNotificationColor(notification.type)}`}>
                            <Icon className="w-4 h-4" />
                          </div>
                          <div className="flex-1">
                            <p className="text-sm font-medium text-white">
                              {notification.title}
                            </p>
                            <p className="text-xs text-gray-400 mt-1">
                              {notification.message}
                            </p>
                            <p className="text-xs text-gray-500 mt-2">
                              {notification.time}
                            </p>
                          </div>
                          <button
                            onClick={() => toggleMute(notification.type)}
                            className="p-1 hover:bg-gray-700 rounded transition-colors"
                          >
                            {isMuted ? (
                              <BellOff className="w-3 h-3 text-gray-500" />
                            ) : (
                              <Bell className="w-3 h-3 text-gray-500" />
                            )}
                          </button>
                        </div>
                      </motion.div>
                    );
                  })
                ) : (
                  <div className="p-8 text-center">
                    <Bell className="w-12 h-12 text-gray-600 mx-auto mb-3" />
                    <p className="text-gray-400">No notifications</p>
                  </div>
                )}
              </div>

              {/* Footer */}
              {notifications.length > 10 && (
                <div className="p-3 border-t border-gray-800">
                  <button
                    onClick={onViewAll}
                    className="w-full py-2 text-sm text-purple-400 hover:text-purple-300 transition-colors"
                  >
                    View All Notifications
                  </button>
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </>
  );
};

// Browser notification helper
export const requestNotificationPermission = async () => {
  if ('Notification' in window && Notification.permission === 'default') {
    const permission = await Notification.requestPermission();
    return permission === 'granted';
  }
  return Notification.permission === 'granted';
};

export const sendBrowserNotification = (title, options = {}) => {
  if ('Notification' in window && Notification.permission === 'granted') {
    const notification = new Notification(title, {
      icon: '/logo.png',
      badge: '/badge.png',
      vibrate: [200, 100, 200],
      ...options
    });

    notification.onclick = () => {
      window.focus();
      notification.close();
    };

    setTimeout(() => notification.close(), 5000);
  }
};

// Toast notification helpers
export const showVulnerabilityToast = (vulnerability, onView) => {
  toast.custom((t) => (
    <VulnerabilityToast 
      vulnerability={vulnerability} 
      onView={() => {
        onView(vulnerability);
        toast.dismiss(t.id);
      }}
    />
  ), {
    duration: 5000,
    position: 'top-right'
  });

  // Also send browser notification for critical vulnerabilities
  if (vulnerability.severity === 'critical') {
    sendBrowserNotification(
      '🚨 Critical Vulnerability Found!',
      {
        body: `${vulnerability.type} detected at ${vulnerability.url}`,
        tag: 'critical-vulnerability',
        requireInteraction: true
      }
    );
  }
};

export const showSuccessToast = (message) => {
  toast.success(message, {
    style: {
      background: '#1f2937',
      color: '#fff',
      border: '1px solid #10b981'
    },
    iconTheme: {
      primary: '#10b981',
      secondary: '#fff'
    }
  });
};

export const showErrorToast = (message) => {
  toast.error(message, {
    style: {
      background: '#1f2937',
      color: '#fff',
      border: '1px solid #dc2626'
    },
    iconTheme: {
      primary: '#dc2626',
      secondary: '#fff'
    }
  });
};

export const showInfoToast = (message) => {
  toast(message, {
    icon: <Info className="w-5 h-5 text-blue-500" />,
    style: {
      background: '#1f2937',
      color: '#fff',
      border: '1px solid #3b82f6'
    }
  });
};

// Global toast configuration component
export const ToastContainer = () => (
  <Toaster
    position="top-right"
    reverseOrder={false}
    gutter={8}
    toastOptions={{
      duration: 4000,
      style: {
        background: '#1f2937',
        color: '#fff',
        borderRadius: '0.75rem',
        boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)'
      }
    }}
  />
);

export default {
  NotificationCenter,
  VulnerabilityToast,
  ToastContainer,
  showVulnerabilityToast,
  showSuccessToast,
  showErrorToast,
  showInfoToast,
  requestNotificationPermission,
  sendBrowserNotification
};

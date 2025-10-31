import React, { createContext, useContext, useEffect, useState } from 'react';

// Theme Context
const ThemeContext = createContext();

// Theme Provider Component
export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(() => {
    // Get theme from localStorage or default to dark
    const savedTheme = localStorage.getItem('cybersage-theme');
    return savedTheme || 'dark';
  });

  // Apply theme to document
  useEffect(() => {
    const root = document.documentElement;
    
    // Remove existing theme classes
    root.removeAttribute('data-theme');
    
    // Apply new theme
    if (theme === 'light') {
      root.setAttribute('data-theme', 'light');
    }
    
    // Save to localStorage
    localStorage.setItem('cybersage-theme', theme);
    
    // Add transition class for smooth theme switching
    document.body.classList.add('theme-transitioning');
    
    // Remove transition class after animation
    setTimeout(() => {
      document.body.classList.remove('theme-transitioning');
    }, 300);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prevTheme => prevTheme === 'dark' ? 'light' : 'dark');
  };

  const value = {
    theme,
    toggleTheme,
    isDark: theme === 'dark',
    isLight: theme === 'light'
  };

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
}

// Custom hook to use theme
export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
}

// Theme Toggle Component
export function ThemeToggle() {
  const { toggleTheme, isDark, isLight } = useTheme();

  return (
    <button
      onClick={toggleTheme}
      className="nav-item hover-glow"
      aria-label={`Switch to ${isDark ? 'light' : 'dark'} theme`}
      title={`Switch to ${isDark ? 'light' : 'dark'} theme`}
    >
      <div className="relative w-6 h-6">
        {/* Sun Icon (for dark theme) */}
        <svg
          className={`absolute inset-0 w-6 h-6 text-yellow-400 transition-all duration-300 ${
            isDark ? 'opacity-100 rotate-0' : 'opacity-0 rotate-90'
          }`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          xmlns="http://www.w3.org/2000/svg"
        >
          <circle cx="12" cy="12" r="4"/>
          <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/>
        </svg>

        {/* Moon Icon (for light theme) */}
        <svg
          className={`absolute inset-0 w-6 h-6 text-blue-300 transition-all duration-300 ${
            isLight ? 'opacity-100 rotate-0' : 'opacity-0 rotate-90'
          }`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/>
        </svg>
      </div>
      <span className="text-sm font-medium">
        {isDark ? 'Light Mode' : 'Dark Mode'}
      </span>
    </button>
  );
}

// Enhanced Status Indicator Component
export function StatusIndicator({ status, size = 'md', showText = true }) {
  const statusClasses = {
    online: 'status-online',
    offline: 'status-offline', 
    warning: 'status-warning',
    connecting: 'bg-yellow-500 animate-pulse',
    error: 'status-offline'
  };

  const sizeClasses = {
    sm: 'w-2 h-2',
    md: 'w-3 h-3',
    lg: 'w-4 h-4',
    xl: 'w-5 h-5'
  };

  const textClasses = {
    online: 'text-green-400',
    offline: 'text-red-400',
    warning: 'text-yellow-400', 
    connecting: 'text-yellow-400',
    error: 'text-red-400'
  };

  const statusLabels = {
    online: 'Connected',
    offline: 'Disconnected',
    warning: 'Warning',
    connecting: 'Connecting',
    error: 'Error'
  };

  return (
    <div className="flex items-center gap-2">
      <div
        className={`${sizeClasses[size]} ${statusClasses[status]} rounded-full ${
          status === 'connecting' ? 'animate-pulse' : ''
        }`}
      />
      {showText && (
        <span className={`text-sm font-medium ${textClasses[status]}`}>
          {statusLabels[status]}
        </span>
      )}
    </div>
  );
}

// Enhanced Loading Spinner Component
export function LoadingSpinner({ size = 'md', color = 'primary', text = null }) {
  const sizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-6 h-6',
    lg: 'w-8 h-8',
    xl: 'w-12 h-12'
  };

  const colorClasses = {
    primary: 'border-purple-500 border-t-transparent',
    secondary: 'border-gray-400 border-t-transparent',
    success: 'border-green-500 border-t-transparent',
    warning: 'border-yellow-500 border-t-transparent',
    error: 'border-red-500 border-t-transparent'
  };

  return (
    <div className="flex items-center justify-center gap-2">
      <div
        className={`${sizeClasses[size]} border-2 border-solid rounded-full animate-spin ${colorClasses[color]}`}
      />
      {text && (
        <span className="text-sm text-gray-400 font-medium">{text}</span>
      )}
    </div>
  );
}

// Loading Dots Component
export function LoadingDots({ text = 'Loading', size = 'sm' }) {
  const sizeClasses = {
    sm: 'w-2 h-2',
    md: 'w-3 h-3',
    lg: 'w-4 h-4'
  };

  return (
    <div className="flex items-center gap-1">
      <span className="text-sm text-gray-400">{text}</span>
      <div className="flex gap-1">
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            className={`${sizeClasses[size]} bg-current rounded-full animate-pulse`}
            style={{
              animationDelay: `${i * 0.2}s`,
              animationDuration: '1.4s'
            }}
          />
        ))}
      </div>
    </div>
  );
}

// Enhanced Badge Component
export function Badge({ 
  variant = 'primary', 
  size = 'md', 
  children, 
  icon = null,
  pulse = false,
  className = '' 
}) {
  const variantClasses = {
    primary: 'badge-primary',
    success: 'badge-success',
    warning: 'badge-warning',
    error: 'badge-error',
    info: 'badge-primary'
  };

  const severityClasses = {
    critical: 'severity-critical',
    high: 'severity-high', 
    medium: 'severity-medium',
    low: 'severity-low'
  };

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5',
    md: 'text-sm px-2.5 py-1',
    lg: 'text-base px-3 py-1.5'
  };

  // Check if variant is severity-based
  const isSeverity = ['critical', 'high', 'medium', 'low'].includes(variant);
  const badgeClass = isSeverity ? severityClasses[variant] : variantClasses[variant];

  return (
    <span 
      className={`
        inline-flex items-center gap-1.5 font-medium rounded-full border 
        ${badgeClass} ${sizeClasses[size]} ${pulse ? 'animate-pulse' : ''} 
        ${className}
      `}
    >
      {icon && <span className="text-current">{icon}</span>}
      {children}
    </span>
  );
}

// Skeleton Components
export function SkeletonText({ lines = 1, className = '' }) {
  return (
    <div className={`space-y-2 ${className}`}>
      {Array.from({ length: lines }).map((_, i) => (
        <div
          key={i}
          className={`skeleton ${lines === 1 ? 'h-4' : 'h-4'}`}
          style={{ 
            width: i === lines - 1 ? '60%' : '100%',
            animationDelay: `${i * 0.1}s`
          }}
        />
      ))}
    </div>
  );
}

export function SkeletonCard({ className = '' }) {
  return (
    <div className={`skeleton-card space-y-4 ${className}`}>
      <div className="skeleton-title" />
      <div className="skeleton-text" lines={3} />
      <div className="flex gap-2">
        <div className="skeleton w-16 h-6" />
        <div className="skeleton w-20 h-6" />
      </div>
    </div>
  );
}

export function SkeletonAvatar({ size = 'md', className = '' }) {
  const sizeClasses = {
    sm: 'w-8 h-8',
    md: 'w-12 h-12', 
    lg: 'w-16 h-16',
    xl: 'w-20 h-20'
  };

  return (
    <div className={`skeleton skeleton-avatar ${sizeClasses[size]} ${className}`} />
  );
}

export function SkeletonList({ items = 3, className = '' }) {
  return (
    <div className={`space-y-3 ${className}`}>
      {Array.from({ length: items }).map((_, i) => (
        <div key={i} className="flex items-center gap-3">
          <SkeletonAvatar size="sm" />
          <div className="flex-1 space-y-1">
            <SkeletonText lines={1} />
            <SkeletonText lines={1} />
          </div>
        </div>
      ))}
    </div>
  );
}

// Page Transition Component
export function PageTransition({ children, className = '' }) {
  return (
    <div className={`animate-fade-in-up ${className}`}>
      {children}
    </div>
  );
}

// Staggered List Component  
export function StaggeredList({ children, className = '' }) {
  return (
    <div className={`stagger-animation ${className}`}>
      {children}
    </div>
  );
}

// Enhanced Progress Bar Component
export function ProgressBar({ 
  value = 0, 
  max = 100, 
  size = 'md', 
  showLabel = false,
  label = '',
  color = 'primary',
  animated = true,
  className = '' 
}) {
  const percentage = Math.min(Math.max((value / max) * 100, 0), 100);
  
  const sizeClasses = {
    sm: 'h-1',
    md: 'h-2',
    lg: 'h-3',
    xl: 'h-4'
  };

  const colorClasses = {
    primary: 'bg-gradient-to-r from-purple-500 to-pink-500',
    success: 'bg-gradient-to-r from-green-500 to-emerald-500',
    warning: 'bg-gradient-to-r from-yellow-500 to-orange-500',
    error: 'bg-gradient-to-r from-red-500 to-pink-500'
  };

  return (
    <div className={`progress-bar ${sizeClasses[size]} ${className}`}>
      <div
        className={`progress-fill ${colorClasses[color]} ${animated ? 'animate-pulse' : ''}`}
        style={{ width: `${percentage}%` }}
      />
      {showLabel && (
        <div className="mt-1 text-xs text-gray-400 text-center">
          {label} {percentage.toFixed(0)}%
        </div>
      )}
    </div>
  );
}

// Enhanced Button Component
export function Button({ 
  variant = 'primary', 
  size = 'md', 
  children, 
  icon = null,
  loading = false,
  disabled = false,
  fullWidth = false,
  className = '',
  ...props 
}) {
  const variantClasses = {
    primary: 'btn-primary',
    secondary: 'btn-secondary',
    ghost: 'btn-ghost',
    danger: 'bg-red-600 hover:bg-red-700 text-white',
    success: 'bg-green-600 hover:bg-green-700 text-white'
  };

  const sizeClasses = {
    sm: 'btn-sm',
    md: '',
    lg: 'btn-lg'
  };

  const baseClasses = `
    btn ${variantClasses[variant]} ${sizeClasses[size]}
    ${fullWidth ? 'w-full' : ''}
    ${loading ? 'opacity-75 cursor-not-allowed' : ''}
    ${disabled ? 'opacity-50 cursor-not-allowed' : ''}
    ${className}
  `;

  return (
    <button
      className={baseClasses}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? (
        <LoadingSpinner size="sm" />
      ) : (
        <>
          {icon && <span className="text-current">{icon}</span>}
          {children}
        </>
      )}
    </button>
  );
}

// Enhanced Card Component
export function Card({ 
  children, 
  variant = 'default',
  padding = 'md',
  hover = true,
  glow = false,
  className = '',
  ...props 
}) {
  const variantClasses = {
    default: 'card',
    elevated: 'card-elevated',
    outlined: 'border-2 border-gray-600 bg-transparent'
  };

  const paddingClasses = {
    sm: 'p-4',
    md: 'p-6',
    lg: 'p-8',
    xl: 'p-10'
  };

  const hoverClasses = hover ? 'hover-lift' : '';
  const glowClasses = glow ? 'hover-glow' : '';

  return (
    <div
      className={`
        ${variantClasses[variant]} ${paddingClasses[padding]} 
        ${hoverClasses} ${glowClasses} ${className}
      `}
      {...props}
    >
      {children}
    </div>
  );
}
// Simple modal implementations for build compatibility
export const EnhancedModal = ({ isOpen, onClose, title, children, size = 'lg' }) => {
  if (!isOpen) return null;
  
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50">
      <div className={`bg-white dark:bg-gray-800 rounded-xl shadow-lg max-w-${size === 'lg' ? '2xl' : 'md'} w-full`}>
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold">{title}</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">×</button>
        </div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
};

export const DetailModal = ({ isOpen, onClose, title, data, fields }) => {
  if (!isOpen) return null;
  
  return (
    <EnhancedModal isOpen={isOpen} onClose={onClose} title={title} size="lg">
      <div className="space-y-4">
        {fields.map((field, index) => (
          <div key={index}>
            <label className="block text-sm font-medium">{field.label}</label>
            <p className="text-gray-900 dark:text-white">{field.value || 'N/A'}</p>
          </div>
        ))}
      </div>
    </EnhancedModal>
  );
};

export const ConfirmationModal = ({ isOpen, onClose, title, message, onConfirm }) => {
  if (!isOpen) return null;
  
  return (
    <EnhancedModal isOpen={isOpen} onClose={onClose} title={title}>
      <div className="space-y-4">
        <p>{message}</p>
        <div className="flex gap-3 justify-end">
          <button onClick={onClose}>Cancel</button>
          <button onClick={onConfirm} className="bg-red-600 text-white px-4 py-2 rounded">Confirm</button>
        </div>
      </div>
    </EnhancedModal>
  );
};

export const AlertModal = ({ isOpen, onClose, title, message }) => {
  if (!isOpen) return null;
  
  return (
    <EnhancedModal isOpen={isOpen} onClose={onClose} title={title}>
      <div className="space-y-4">
        <p>{message}</p>
        <div className="flex justify-end">
          <button onClick={onClose} className="bg-primary text-white px-4 py-2 rounded">OK</button>
        </div>
      </div>
    </EnhancedModal>
  );
};

export const FormModal = ({ isOpen, onClose, title, children, onSubmit }) => {
  if (!isOpen) return null;
  
  return (
    <EnhancedModal isOpen={isOpen} onClose={onClose} title={title}>
      <form onSubmit={onSubmit} className="space-y-4">
        {children}
      </form>
    </EnhancedModal>
  );
};
export const Modal = EnhancedModal;
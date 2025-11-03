// Simplified Enhanced Modal Component for testing
import React, { useEffect, useRef } from 'react';

const EnhancedModal = ({ 
  isOpen, 
  onClose, 
  title, 
  children, 
  size = 'md',
  showCloseButton = true,
  className = ''
}) => {
  const modalRef = useRef(null);
  const previousFocusRef = useRef(null);

  useEffect(() => {
    if (isOpen) {
      // Store the previously focused element
      previousFocusRef.current = document.activeElement;
      
      // Focus the modal
      modalRef.current?.focus();
      
      // Prevent body scroll
      document.body.style.overflow = 'hidden';
    } else {
      // Restore focus and body scroll
      previousFocusRef.current?.focus();
      document.body.style.overflow = 'unset';
    }

    return () => {
      document.body.style.overflow = 'unset';
    };
  }, [isOpen]);

  useEffect(() => {
    const handleEscape = (e) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const sizeClasses = {
    sm: 'max-w-md',
    md: 'max-w-lg', 
    lg: 'max-w-2xl',
    xl: 'max-w-4xl',
    '2xl': 'max-w-6xl'
  }[size] || 'max-w-lg';

  return (
    <div 
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 animate-fade-in"
      onClick={(e) => {
        if (e.target === e.currentTarget) {
          onClose();
        }
      }}
    >
      <div 
        className={`bg-white dark:bg-gray-800 rounded-2xl shadow-2xl border border-gray-200 dark:border-gray-700 w-full transform transition-all duration-300 scale-100 translate-y-0 opacity-100 ${sizeClasses} ${className}`}
        ref={modalRef}
        tabIndex="-1"
      >
        {/* Header */}
        {title && (
          <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-xl font-semibold text-gray-900 dark:text-white">
              {title}
            </h3>
            {showCloseButton && (
              <button
                onClick={onClose}
                className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors duration-200"
              >
                ×
              </button>
            )}
          </div>
        )}

        {/* Content */}
        <div className="p-6">
          {children}
        </div>
      </div>
    </div>
  );
};

export default EnhancedModal;

// DetailModal component for displaying detailed information
export const DetailModal = ({ 
  isOpen, 
  onClose, 
  title, 
  data = {},
  fields = [],
  className = ''
}) => {
  if (!isOpen) return null;

  const renderField = (field) => {
    const { label, value, type = 'text' } = field;
    
    if (type === 'object' && typeof value === 'object') {
      return (
        <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-3 font-mono text-sm">
          <pre className="text-gray-800 dark:text-gray-200">
            {JSON.stringify(value, null, 2)}
          </pre>
        </div>
      );
    }

    return (
      <p className="text-gray-700 dark:text-gray-300">
        {value || 'N/A'}
      </p>
    );
  };

  return (
    <EnhancedModal
      isOpen={isOpen}
      onClose={onClose}
      title={title}
      size="lg"
      className={className}
    >
      <div className="space-y-4">
        {fields.map((field, index) => (
          <div key={index} className="space-y-2">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              {field.label}
            </label>
            {renderField(field)}
          </div>
        ))}
      </div>
    </EnhancedModal>
  );
};
import React, { useState } from 'react';
import EnhancedHttpRepeater from '../components/EnhancedHttpRepeater';
import { useTheme } from '../components/ThemeComponents';

const EnhancedRepeaterPage = () => {
  const { isDark } = useTheme();

  return (
    <div className={`min-h-screen transition-colors duration-300 ${
      isDark ? 'bg-gray-900 text-white' : 'bg-white text-gray-900'
    }`}>
      <div className="container mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold mb-2">Enhanced HTTP Request Repeater</h1>
          <p className={`${isDark ? 'text-gray-400' : 'text-gray-600'}`}>
            Advanced Burp Suite-like HTTP request testing with parameter injection, fuzzing, and security analysis
          </p>
        </div>
        
        <EnhancedHttpRepeater />
      </div>
    </div>
  );
};

export default EnhancedRepeaterPage;

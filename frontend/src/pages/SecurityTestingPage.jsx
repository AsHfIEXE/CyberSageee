import React, { useState } from 'react';
import SecurityTestingDashboard from '../components/SecurityTestingDashboard';
import { useTheme } from '../components/ThemeComponents';

const SecurityTestingPage = () => {
  const { isDark } = useTheme();

  return (
    <div className={`min-h-screen transition-colors duration-300 ${
      isDark ? 'bg-gray-900 text-white' : 'bg-white text-gray-900'
    }`}>
      <div className="container mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold mb-2">Security Testing Dashboard</h1>
          <p className={`${isDark ? 'text-gray-400' : 'text-gray-600'}`}>
            Comprehensive security operations center with vulnerability tracking and analytics
          </p>
        </div>
        
        <SecurityTestingDashboard />
      </div>
    </div>
  );
};

export default SecurityTestingPage;

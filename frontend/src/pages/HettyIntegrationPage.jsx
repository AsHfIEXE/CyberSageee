import React, { useState } from 'react';
import HettyIntegration from '../components/HettyIntegration';
import { useTheme } from '../components/ThemeComponents';

const HettyIntegrationPage = () => {
  const { isDark } = useTheme();

  return (
    <div className={`min-h-screen transition-colors duration-300 ${
      isDark ? 'bg-gray-900 text-white' : 'bg-white text-gray-900'
    }`}>
      <div className="container mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold mb-2">HETTY HTTP/2 Integration</h1>
          <p className={`${isDark ? 'text-gray-400' : 'text-gray-600'}`}>
            Advanced HTTP/2 testing and proxy functionality with traffic interception and analysis
          </p>
        </div>
        
        <HettyIntegration />
      </div>
    </div>
  );
};

export default HettyIntegrationPage;

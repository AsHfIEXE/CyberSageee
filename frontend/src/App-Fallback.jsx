import React, { useState } from 'react';
import { ScanProvider } from './context/ScanContext';
import Navigation from './components/Navigation';
import DashboardPage from './pages/DashboardPage';
import ScannerPage from './pages/ScannerPage';
import VulnerabilitiesPage from './pages/VulnerabilitiesPage';
import ChainsPage from './pages/ChainsPage';
import RepeaterPage from './pages/RepeaterPage';
import HistoryPage from './pages/HistoryPage';
import BlueprintPage from './pages/BlueprintPage';
import StatisticsPage from './pages/StatisticsPage';
import ToolsPage from './pages/ToolsPage';

function App() {
  const [currentPage, setCurrentPage] = useState('dashboard');

  const renderPage = () => {
    switch (currentPage) {
      case 'scanner':
        return <ScannerPage />;
      case 'vulnerabilities':
        return <VulnerabilitiesPage />;
      case 'chains':
        return <ChainsPage />;
      case 'repeater':
        return <RepeaterPage />;
      case 'history':
        return <HistoryPage />;
      case 'blueprint':
        return <BlueprintPage />;
      case 'statistics':
        return <StatisticsPage />;
      case 'tools':
        return <ToolsPage />;
      default:
        return <DashboardPage />;
    }
  };

  return (
    <ScanProvider>
      <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black text-white">
        {/* Modern Sidebar Navigation */}
        <Navigation 
          currentPage={currentPage}
          setCurrentPage={setCurrentPage}
        />

        {/* Main Content Area */}
        <main className="ml-72 min-h-screen p-8">
          {renderPage()}
        </main>
      </div>
    </ScanProvider>
  );
}

export default App;
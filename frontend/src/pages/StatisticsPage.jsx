import React from 'react';
import { useScan } from '../context/EnhancedScanContext';
import ScanStatistics from '../components/ScanStatistics';

const StatisticsPage = () => {
  const { currentScanId, vulnerabilities, toolActivity } = useScan();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold">Scan Statistics</h2>
        <div className="text-sm text-gray-400">
          {currentScanId ? `Scan ID: ${currentScanId}` : 'No active scan'}
        </div>
      </div>

      {/* Scan Statistics Component */}
      <ScanStatistics 
        scanId={currentScanId}
        vulnerabilities={vulnerabilities}
        toolActivity={toolActivity}
      />
    </div>
  );
};

export default StatisticsPage;
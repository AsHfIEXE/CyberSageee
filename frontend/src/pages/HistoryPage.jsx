import React, { useState } from 'react';
import ScanHistory from '../components/ScanHistory';

const HistoryPage = () => {
  const [selectedScan, setSelectedScan] = useState(null);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold">Scan History</h2>
        <div className="text-sm text-gray-400">
          View and manage previous scans
        </div>
      </div>

      {/* Scan History Component */}
      <ScanHistory 
        onSelectScan={setSelectedScan}
        selectedScan={selectedScan}
      />
    </div>
  );
};

export default HistoryPage;
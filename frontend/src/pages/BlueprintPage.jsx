import React from 'react';
import { useScan } from '../context/EnhancedScanContext';
import EnhancedBlueprintViewer from '../components/EnhancedBlueprintViewer';

const BlueprintPage = () => {
  const { currentScanId, vulnerabilities, chains, toolActivity } = useScan();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold">Security Blueprint</h2>
        <div className="text-sm text-gray-400">
          {currentScanId ? `Scan ID: ${currentScanId}` : 'No active scan'}
        </div>
      </div>

      {/* Enhanced Blueprint Viewer Component */}
      <EnhancedBlueprintViewer 
        scanId={currentScanId}
        vulnerabilities={vulnerabilities}
        chains={chains}
        toolActivity={toolActivity}
      />
    </div>
  );
};

export default BlueprintPage;
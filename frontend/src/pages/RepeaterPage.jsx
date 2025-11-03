import React from 'react';
import HttpRepeater from '../components/HttpRepeater';

const RepeaterPage = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold">HTTP Repeater</h2>
        <div className="text-sm text-gray-400">
          Test and modify HTTP requests
        </div>
      </div>

      {/* HTTP Repeater Component */}
      <HttpRepeater />
    </div>
  );
};

export default RepeaterPage;
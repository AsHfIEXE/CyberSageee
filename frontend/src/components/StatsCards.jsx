import React from 'react';

const StatsCards = ({ stats, chains }) => {
  const statCards = [
    { title: 'Critical', count: stats.critical, color: 'from-red-500 to-pink-500', icon: '🔴' },
    { title: 'High', count: stats.high, color: 'from-orange-500 to-yellow-500', icon: '🟠' },
    { title: 'Medium', count: stats.medium, color: 'from-yellow-500 to-green-500', icon: '🟡' },
    { title: 'Low', count: stats.low, color: 'from-green-500 to-blue-500', icon: '🟢' }
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      {statCards.map((stat, index) => (
        <div
          key={index}
          className="bg-gray-800 rounded-lg p-6 border border-gray-700 hover:scale-105 transition transform cursor-pointer"
        >
          <div className="flex items-center justify-between mb-3">
            <div>
              <p className="text-gray-400 text-sm">{stat.title}</p>
              <p className="text-3xl font-bold text-white mt-1 animate-count-up">
                {stat.count}
              </p>
            </div>
            <span className="text-4xl">{stat.icon}</span>
          </div>
          <div className={`h-1 bg-gradient-to-r ${stat.color} rounded-full`} />
        </div>
      ))}
    </div>
  );
};

export default StatsCards;
// Beautiful Stats Card Component
import React from 'react';

const StatsCard = ({ title, value, icon, color, subtitle, trend }) => {
  const colorClasses = {
    red: {
      gradient: 'from-red-600 to-pink-600',
      bg: 'bg-red-500/10',
      border: 'border-red-500/30',
      text: 'text-red-400',
      glow: 'shadow-red-500/50'
    },
    orange: {
      gradient: 'from-orange-600 to-red-600',
      bg: 'bg-orange-500/10',
      border: 'border-orange-500/30',
      text: 'text-orange-400',
      glow: 'shadow-orange-500/50'
    },
    yellow: {
      gradient: 'from-yellow-600 to-orange-600',
      bg: 'bg-yellow-500/10',
      border: 'border-yellow-500/30',
      text: 'text-yellow-400',
      glow: 'shadow-yellow-500/50'
    },
    blue: {
      gradient: 'from-blue-600 to-cyan-600',
      bg: 'bg-blue-500/10',
      border: 'border-blue-500/30',
      text: 'text-blue-400',
      glow: 'shadow-blue-500/50'
    },
    green: {
      gradient: 'from-green-600 to-emerald-600',
      bg: 'bg-green-500/10',
      border: 'border-green-500/30',
      text: 'text-green-400',
      glow: 'shadow-green-500/50'
    },
    purple: {
      gradient: 'from-purple-600 to-pink-600',
      bg: 'bg-purple-500/10',
      border: 'border-purple-500/30',
      text: 'text-purple-400',
      glow: 'shadow-purple-500/50'
    }
  };

  const colors = colorClasses[color] || colorClasses.blue;

  return (
    <div className={`relative group overflow-hidden rounded-2xl border ${colors.border} ${colors.bg} backdrop-blur-sm transition-all duration-300 hover:scale-105 hover:shadow-xl ${colors.glow}`}>
      {/* Background Gradient */}
      <div className={`absolute inset-0 bg-gradient-to-br ${colors.gradient} opacity-5 group-hover:opacity-10 transition-opacity`} />
      
      {/* Content */}
      <div className="relative p-6">
        {/* Icon & Title */}
        <div className="flex items-center justify-between mb-4">
          <div>
            <p className="text-sm text-gray-400 font-medium">{title}</p>
            {subtitle && (
              <p className="text-xs text-gray-500 mt-1">{subtitle}</p>
            )}
          </div>
          <div className={`text-4xl opacity-80 group-hover:scale-110 transition-transform`}>
            {icon}
          </div>
        </div>

        {/* Value */}
        <div className="flex items-end justify-between">
          <p className={`text-4xl font-bold ${colors.text}`}>
            {value}
          </p>
          {trend && (
            <div className={`text-xs px-2 py-1 rounded ${trend > 0 ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>
              {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}
            </div>
          )}
        </div>
      </div>

      {/* Animated Border */}
      <div className="absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity">
        <div className={`absolute inset-0 rounded-2xl bg-gradient-to-r ${colors.gradient} opacity-20 blur-xl`} />
      </div>
    </div>
  );
};

export default StatsCard;

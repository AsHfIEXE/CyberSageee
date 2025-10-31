// Enhanced Stats Card Component with Modern Design
import React from 'react';

const EnhancedStatsCard = ({ 
  title, 
  value, 
  icon, 
  color = 'blue', 
  subtitle, 
  trend = 0,
  description = '',
  loading = false,
  animate = true,
  onClick = null 
}) => {
  const colorClasses = {
    red: {
      gradient: 'from-red-600 to-pink-600',
      bg: 'bg-red-500/10',
      border: 'border-red-500/30',
      text: 'text-red-400',
      glow: 'shadow-red-500/20',
      hoverGlow: 'shadow-red-500/40'
    },
    orange: {
      gradient: 'from-orange-600 to-red-600',
      bg: 'bg-orange-500/10',
      border: 'border-orange-500/30',
      text: 'text-orange-400',
      glow: 'shadow-orange-500/20',
      hoverGlow: 'shadow-orange-500/40'
    },
    yellow: {
      gradient: 'from-yellow-600 to-orange-600',
      bg: 'bg-yellow-500/10',
      border: 'border-yellow-500/30',
      text: 'text-yellow-400',
      glow: 'shadow-yellow-500/20',
      hoverGlow: 'shadow-yellow-500/40'
    },
    blue: {
      gradient: 'from-blue-600 to-cyan-600',
      bg: 'bg-blue-500/10',
      border: 'border-blue-500/30',
      text: 'text-blue-400',
      glow: 'shadow-blue-500/20',
      hoverGlow: 'shadow-blue-500/40'
    },
    green: {
      gradient: 'from-green-600 to-emerald-600',
      bg: 'bg-green-500/10',
      border: 'border-green-500/30',
      text: 'text-green-400',
      glow: 'shadow-green-500/20',
      hoverGlow: 'shadow-green-500/40'
    },
    purple: {
      gradient: 'from-purple-600 to-pink-600',
      bg: 'bg-purple-500/10',
      border: 'border-purple-500/30',
      text: 'text-purple-400',
      glow: 'shadow-purple-500/20',
      hoverGlow: 'shadow-purple-500/40'
    },
    cyan: {
      gradient: 'from-cyan-600 to-blue-600',
      bg: 'bg-cyan-500/10',
      border: 'border-cyan-500/30',
      text: 'text-cyan-400',
      glow: 'shadow-cyan-500/20',
      hoverGlow: 'shadow-cyan-500/40'
    }
  };

  const colors = colorClasses[color] || colorClasses.blue;

  if (loading) {
    return (
      <div className={`relative group overflow-hidden rounded-2xl border ${colors.border} ${colors.bg} backdrop-blur-sm transition-all duration-300 hover:shadow-xl ${colors.glow} animate-pulse`}>
        {/* Loading Skeleton */}
        <div className="relative p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="space-y-2">
              <div className="h-4 bg-gray-700 rounded w-24 animate-shimmer" />
              <div className="h-3 bg-gray-700 rounded w-16 animate-shimmer" />
            </div>
            <div className="w-12 h-12 bg-gray-700 rounded-xl animate-shimmer" />
          </div>
          <div className="flex items-end justify-between">
            <div className="h-10 bg-gray-700 rounded w-16 animate-shimmer" />
            <div className="h-6 bg-gray-700 rounded w-12 animate-shimmer" />
          </div>
        </div>
      </div>
    );
  }

  const cardContent = (
    <div className={`relative group overflow-hidden rounded-2xl border ${colors.border} ${colors.bg} backdrop-blur-sm transition-all duration-500 hover:scale-[1.02] hover:shadow-2xl ${colors.hoverGlow} ${animate ? 'animate-fade-in-up' : ''} ${onClick ? 'cursor-pointer' : ''}`}>
      {/* Animated Background Gradient */}
      <div className={`absolute inset-0 bg-gradient-to-br ${colors.gradient} opacity-0 group-hover:opacity-15 transition-all duration-500`} />
      
      {/* Content */}
      <div className="relative p-6">
        {/* Header Section */}
        <div className="flex items-center justify-between mb-6">
          <div className="space-y-1">
            <p className="text-sm font-semibold text-gray-300 group-hover:text-white transition-colors duration-300">{title}</p>
            {subtitle && (
              <p className="text-xs text-gray-500 group-hover:text-gray-400 transition-colors duration-300">{subtitle}</p>
            )}
          </div>
          
          <div className={`relative p-3 rounded-xl bg-gradient-to-br ${colors.gradient} opacity-80 group-hover:opacity-100 group-hover:scale-110 transition-all duration-300 shadow-lg`}>
            <div className="text-2xl text-white">
              {icon}
            </div>
            {/* Glow Effect */}
            <div className={`absolute inset-0 rounded-xl bg-gradient-to-br ${colors.gradient} opacity-0 group-hover:opacity-30 blur-xl transition-opacity duration-300`} />
          </div>
        </div>

        {/* Value and Trend Section */}
        <div className="flex items-end justify-between">
          <div className="space-y-1">
            <p className={`text-4xl font-bold ${colors.text} group-hover:scale-105 transition-transform duration-300`}>
              {typeof value === 'number' ? value.toLocaleString() : value}
            </p>
            {description && (
              <p className="text-xs text-gray-500 group-hover:text-gray-400 transition-colors duration-300">
                {description}
              </p>
            )}
          </div>
          
          {trend !== 0 && (
            <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-all duration-300 ${
              trend > 0 
                ? 'bg-red-500/20 text-red-400 group-hover:bg-red-500/30' 
                : 'bg-green-500/20 text-green-400 group-hover:bg-green-500/30'
            }`}>
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                {trend > 0 ? (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
                ) : (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 17h8m0 0V9m0 8l-8-8-4 4-6-6" />
                )}
              </svg>
              <span>{Math.abs(trend)}</span>
            </div>
          )}
        </div>

        {/* Animated Progress Bar (for value comparisons) */}
        {typeof value === 'number' && value > 0 && (
          <div className="mt-4 space-y-2">
            <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
              <div 
                className={`h-full bg-gradient-to-r ${colors.gradient} rounded-full transition-all duration-1000 ease-out animate-pulse`}
                style={{ 
                  width: animate ? '0%' : `${Math.min((value / Math.max(value * 1.5, 10)) * 100, 100)}%`,
                  animation: animate ? 'width 1.5s ease-out 0.5s forwards' : 'none'
                }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Hover Glow Border */}
      <div className="absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-all duration-500 pointer-events-none">
        <div className={`absolute inset-0 rounded-2xl bg-gradient-to-r ${colors.gradient} opacity-20 blur-xl animate-pulse`} />
      </div>

      {/* Corner Accent */}
      <div className={`absolute top-0 right-0 w-20 h-20 bg-gradient-to-br ${colors.gradient} opacity-10 group-hover:opacity-20 transition-all duration-500 transform rotate-45 translate-x-10 -translate-y-10`} />
    </div>
  );

  if (onClick) {
    return (
      <button onClick={onClick} className="w-full text-left group">
        {cardContent}
      </button>
    );
  }

  return cardContent;
};

export default EnhancedStatsCard;

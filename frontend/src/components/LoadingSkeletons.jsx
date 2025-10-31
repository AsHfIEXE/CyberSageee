import React from 'react';
import { motion } from 'framer-motion';

// Skeleton animation
const shimmer = {
  initial: { backgroundPosition: '-200% 0' },
  animate: {
    backgroundPosition: '200% 0',
    transition: {
      repeat: Infinity,
      duration: 1.5,
      ease: 'linear'
    }
  }
};

const SkeletonBox = ({ className = '', ...props }) => (
  <motion.div
    variants={shimmer}
    initial="initial"
    animate="animate"
    className={`bg-gradient-to-r from-gray-800 via-gray-700 to-gray-800 bg-[length:200%_100%] rounded-lg ${className}`}
    {...props}
  />
);

export const VulnerabilityCardSkeleton = () => (
  <div className="bg-gray-900/50 rounded-xl border border-gray-800 p-6">
    <div className="flex items-start space-x-4">
      <SkeletonBox className="w-12 h-12 rounded-lg" />
      <div className="flex-1 space-y-3">
        <SkeletonBox className="h-6 w-3/4" />
        <SkeletonBox className="h-4 w-1/2" />
        <div className="flex space-x-2">
          <SkeletonBox className="h-8 w-24" />
          <SkeletonBox className="h-8 w-24" />
        </div>
      </div>
    </div>
  </div>
);

export const DashboardStatsSkeleton = () => (
  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
    {[...Array(4)].map((_, i) => (
      <div key={i} className="bg-gray-900/50 rounded-xl p-6 border border-gray-800">
        <div className="flex items-center justify-between mb-4">
          <div className="space-y-2">
            <SkeletonBox className="h-4 w-20" />
            <SkeletonBox className="h-8 w-16" />
          </div>
          <SkeletonBox className="w-16 h-16 rounded-full" />
        </div>
        <SkeletonBox className="h-2 w-full" />
      </div>
    ))}
  </div>
);

export const ChartSkeleton = () => (
  <div className="bg-gray-900/50 rounded-xl p-6 border border-gray-800">
    <div className="flex items-center justify-between mb-4">
      <SkeletonBox className="h-6 w-32" />
      <SkeletonBox className="w-5 h-5 rounded" />
    </div>
    <SkeletonBox className="h-64 w-full" />
  </div>
);

export const TableRowSkeleton = () => (
  <div className="flex items-center space-x-4 p-4 border-b border-gray-800">
    <SkeletonBox className="w-10 h-10 rounded-full" />
    <div className="flex-1 space-y-2">
      <SkeletonBox className="h-4 w-3/4" />
      <SkeletonBox className="h-3 w-1/2" />
    </div>
    <SkeletonBox className="h-8 w-20" />
  </div>
);

export const ScanProgressSkeleton = () => (
  <div className="bg-gray-900/50 rounded-xl p-6 border border-gray-800">
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <SkeletonBox className="h-6 w-32" />
        <SkeletonBox className="h-4 w-16" />
      </div>
      <SkeletonBox className="h-3 w-full" />
      <div className="grid grid-cols-3 gap-4">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="space-y-2">
            <SkeletonBox className="h-4 w-20" />
            <SkeletonBox className="h-8 w-full" />
          </div>
        ))}
      </div>
    </div>
  </div>
);

export const NavigationSkeleton = () => (
  <div className="w-72 h-full bg-gray-900 p-4 space-y-2">
    <div className="p-4 mb-4">
      <div className="flex items-center space-x-3">
        <SkeletonBox className="w-12 h-12 rounded-xl" />
        <div className="space-y-2">
          <SkeletonBox className="h-6 w-24" />
          <SkeletonBox className="h-3 w-32" />
        </div>
      </div>
    </div>
    {[...Array(6)].map((_, i) => (
      <SkeletonBox key={i} className="h-16 w-full" />
    ))}
  </div>
);

export const FormSkeleton = () => (
  <div className="space-y-4">
    {[...Array(4)].map((_, i) => (
      <div key={i} className="space-y-2">
        <SkeletonBox className="h-4 w-24" />
        <SkeletonBox className="h-10 w-full" />
      </div>
    ))}
    <SkeletonBox className="h-10 w-32" />
  </div>
);

// Loading spinner component
export const LoadingSpinner = ({ size = 'md', className = '' }) => {
  const sizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-8 h-8',
    lg: 'w-12 h-12',
    xl: 'w-16 h-16'
  };

  return (
    <div className={`flex items-center justify-center ${className}`}>
      <motion.div
        animate={{ rotate: 360 }}
        transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
        className={`${sizeClasses[size]} border-2 border-purple-500 border-t-transparent rounded-full`}
      />
    </div>
  );
};

// Full page loading
export const FullPageLoader = ({ message = 'Loading...' }) => (
  <motion.div
    initial={{ opacity: 0 }}
    animate={{ opacity: 1 }}
    exit={{ opacity: 0 }}
    className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50"
  >
    <div className="bg-gray-900 rounded-xl p-8 shadow-2xl border border-gray-800">
      <LoadingSpinner size="lg" className="mb-4" />
      <p className="text-gray-300 text-center">{message}</p>
    </div>
  </motion.div>
);

// Scan progress loader
export const ScanProgressLoader = ({ phase, progress }) => (
  <div className="bg-gray-900/50 rounded-xl p-6 border border-purple-500/30">
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Scanning in Progress</h3>
        <span className="text-purple-400 font-mono">{progress}%</span>
      </div>
      
      <div className="relative">
        <div className="h-3 bg-gray-800 rounded-full overflow-hidden">
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.5 }}
            className="h-full bg-gradient-to-r from-purple-500 to-pink-500"
          />
        </div>
        <motion.div
          animate={{ left: `${progress}%` }}
          transition={{ duration: 0.5 }}
          className="absolute top-0 h-3 w-1 bg-white rounded-full shadow-lg"
          style={{ transform: 'translateX(-50%)' }}
        />
      </div>
      
      <div className="flex items-center space-x-2">
        <LoadingSpinner size="sm" />
        <p className="text-sm text-gray-400">{phase}</p>
      </div>
    </div>
  </div>
);

export default {
  VulnerabilityCardSkeleton,
  DashboardStatsSkeleton,
  ChartSkeleton,
  TableRowSkeleton,
  ScanProgressSkeleton,
  NavigationSkeleton,
  FormSkeleton,
  LoadingSpinner,
  FullPageLoader,
  ScanProgressLoader
};

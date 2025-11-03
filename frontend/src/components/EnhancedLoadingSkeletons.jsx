// Enhanced Loading Skeletons for Better UX
import React from 'react';
import { SkeletonText, SkeletonCard, SkeletonAvatar, SkeletonList } from './ThemeComponents';

export const DashboardSkeleton = () => (
  <div className="space-y-6 animate-fade-in">
    {/* Header Skeleton */}
    <div className="flex items-center justify-between">
      <div>
        <SkeletonText lines={1} className="w-48 h-8" />
        <SkeletonText lines={1} className="w-32 h-4 mt-2" />
      </div>
      <div className="flex gap-2">
        <SkeletonText lines={1} className="w-24 h-8" />
        <SkeletonText lines={1} className="w-32 h-8" />
      </div>
    </div>

    {/* Stats Cards Skeleton */}
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="stagger-animation">
          <SkeletonCard />
        </div>
      ))}
    </div>

    {/* Charts Skeleton */}
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <SkeletonCard className="h-64" />
      <SkeletonCard className="h-64" />
    </div>

    {/* Table Skeleton */}
    <SkeletonCard className="h-96">
      <SkeletonText lines={1} className="w-40 h-6 mb-4" />
      <div className="space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="flex items-center gap-3">
            <SkeletonAvatar size="sm" />
            <div className="flex-1 space-y-1">
              <SkeletonText lines={1} />
              <SkeletonText lines={1} className="w-3/4" />
            </div>
            <SkeletonText lines={1} className="w-16" />
          </div>
        ))}
      </div>
    </SkeletonCard>
  </div>
);

export const VulnerabilitiesSkeleton = () => (
  <div className="space-y-6 animate-fade-in">
    {/* Header */}
    <div className="flex items-center justify-between">
      <SkeletonText lines={1} className="w-48 h-8" />
      <div className="flex gap-2">
        <SkeletonText lines={1} className="w-32 h-10" />
        <SkeletonText lines={1} className="w-24 h-10" />
      </div>
    </div>

    {/* Filter Bar */}
    <div className="flex gap-4">
      {Array.from({ length: 4 }).map((_, i) => (
        <SkeletonText key={i} lines={1} className="w-20 h-8" />
      ))}
    </div>

    {/* Vulnerability Cards */}
    <div className="grid gap-4">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="stagger-animation">
          <SkeletonCard className="h-32">
            <div className="flex items-start justify-between mb-3">
              <div className="flex-1">
                <SkeletonText lines={1} className="w-3/4 h-5 mb-2" />
                <SkeletonText lines={1} className="w-1/2 h-4 mb-2" />
                <SkeletonText lines={1} className="w-full h-3" />
              </div>
              <SkeletonText lines={1} className="w-16 h-6" />
            </div>
            <div className="flex gap-2">
              <SkeletonText lines={1} className="w-20 h-5" />
              <SkeletonText lines={1} className="w-16 h-5" />
              <SkeletonText lines={1} className="w-24 h-5" />
            </div>
          </SkeletonCard>
        </div>
      ))}
    </div>
  </div>
);

export const ScannerSkeleton = () => (
  <div className="space-y-6 animate-fade-in">
    {/* Header */}
    <div className="flex items-center justify-between">
      <SkeletonText lines={1} className="w-48 h-8" />
      <SkeletonText lines={1} className="w-24 h-10" />
    </div>

    {/* Scanner Configuration */}
    <div className="grid lg:grid-cols-3 gap-6">
      <div className="lg:col-span-2">
        <SkeletonCard className="h-96">
          <SkeletonText lines={1} className="w-40 h-6 mb-6" />
          <div className="space-y-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i}>
                <SkeletonText lines={1} className="w-24 h-4 mb-2" />
                <SkeletonText lines={1} className="w-full h-10" />
              </div>
            ))}
          </div>
        </SkeletonCard>
      </div>
      
      <div>
        <SkeletonCard className="h-96">
          <SkeletonText lines={1} className="w-32 h-6 mb-6" />
          <SkeletonList items={6} />
        </SkeletonCard>
      </div>
    </div>
  </div>
);

export const ToolsSkeleton = () => (
  <div className="space-y-6 animate-fade-in">
    {/* Header */}
    <div className="flex items-center justify-between">
      <SkeletonText lines={1} className="w-48 h-8" />
      <SkeletonText lines={1} className="w-32 h-10" />
    </div>

    {/* Tool Categories */}
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="stagger-animation">
          <SkeletonCard className="h-48">
            <div className="flex items-center gap-3 mb-4">
              <SkeletonAvatar size="lg" />
              <div className="flex-1">
                <SkeletonText lines={1} className="w-3/4 h-5" />
                <SkeletonText lines={1} className="w-1/2 h-4" />
              </div>
            </div>
            <SkeletonText lines={3} className="mb-4" />
            <div className="flex gap-2">
              <SkeletonText lines={1} className="w-16 h-6" />
              <SkeletonText lines={1} className="w-20 h-6" />
            </div>
          </SkeletonCard>
        </div>
      ))}
    </div>
  </div>
);

export const HistorySkeleton = () => (
  <div className="space-y-6 animate-fade-in">
    {/* Header */}
    <div className="flex items-center justify-between">
      <SkeletonText lines={1} className="w-48 h-8" />
      <div className="flex gap-2">
        <SkeletonText lines={1} className="w-32 h-10" />
        <SkeletonText lines={1} className="w-24 h-10" />
      </div>
    </div>

    {/* Timeline */}
    <div className="space-y-4">
      {Array.from({ length: 8 }).map((_, i) => (
        <div key={i} className="stagger-animation">
          <SkeletonCard className="h-24">
            <div className="flex items-center gap-4">
              <SkeletonAvatar size="md" />
              <div className="flex-1">
                <div className="flex items-center justify-between mb-2">
                  <SkeletonText lines={1} className="w-1/3 h-5" />
                  <SkeletonText lines={1} className="w-20 h-6" />
                </div>
                <SkeletonText lines={1} className="w-full h-3" />
              </div>
            </div>
          </SkeletonCard>
        </div>
      ))}
    </div>
  </div>
);

export const BlueprintSkeleton = () => (
  <div className="space-y-6 animate-fade-in">
    {/* Header */}
    <div className="flex items-center justify-between">
      <SkeletonText lines={1} className="w-64 h-8" />
      <div className="flex gap-2">
        <SkeletonText lines={1} className="w-32 h-8" />
      </div>
    </div>

    {/* Overview Cards */}
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="stagger-animation">
          <SkeletonCard className="h-32">
            <div className="flex items-center justify-between mb-4">
              <SkeletonAvatar size="sm" />
              <SkeletonText lines={1} className="w-16 h-8" />
            </div>
            <div className="space-y-2">
              <SkeletonText lines={1} />
              <SkeletonText lines={1} className="w-3/4" />
            </div>
          </SkeletonCard>
        </div>
      ))}
    </div>

    {/* Main Content */}
    <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
      <div className="p-6 border-b border-gray-200 dark:border-gray-700">
        <SkeletonText lines={1} className="w-48 h-6" />
      </div>
      <div className="p-6">
        <SkeletonText lines={4} className="mb-4" />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <SkeletonCard className="h-64" />
          <SkeletonCard className="h-64" />
        </div>
      </div>
    </div>
  </div>
);

export const RepeaterSkeleton = () => (
  <div className="space-y-6 animate-fade-in">
    {/* Header */}
    <div className="flex items-center justify-between">
      <SkeletonText lines={1} className="w-48 h-8" />
      <SkeletonText lines={1} className="w-32 h-10" />
    </div>

    {/* Main Layout */}
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
      {/* Sidebar */}
      <div className="xl:col-span-3">
        <SkeletonCard className="h-96" />
      </div>
      
      {/* Request Builder */}
      <div className="xl:col-span-9 space-y-6">
        {/* Request Config */}
        <SkeletonCard className="h-32" />
        
        {/* Tabs */}
        <SkeletonCard className="h-64" />
        
        {/* Response Preview */}
        <SkeletonCard className="h-48" />
      </div>
    </div>
  </div>
);

// Enhanced Loading Spinner with Brand Colors
export const BrandLoadingSpinner = ({ size = 'lg', text = 'Loading CyberSage...', className = '' }) => {
  const sizeClasses = {
    sm: 'w-8 h-8',
    md: 'w-12 h-12', 
    lg: 'w-16 h-16',
    xl: 'w-20 h-20'
  };

  return (
    <div className={`flex flex-col items-center justify-center gap-4 ${className}`}>
      <div className={`relative ${sizeClasses[size]}`}>
        {/* Outer Ring */}
        <div className="absolute inset-0 rounded-full border-4 border-purple-500/20" />
        
        {/* Spinning Ring */}
        <div className={`absolute inset-0 rounded-full border-4 border-transparent border-t-purple-500 border-r-pink-500 animate-spin`} />
        
        {/* Glow Effect */}
        <div className="absolute inset-0 rounded-full bg-gradient-to-r from-purple-500/10 to-pink-500/10 blur-lg animate-pulse" />
      </div>
      
      {text && (
        <div className="text-center">
          <p className="text-sm font-medium text-gray-300 mb-1">{text}</p>
          <div className="flex items-center gap-1">
            {Array.from({ length: 3 }).map((_, i) => (
              <div
                key={i}
                className="w-2 h-2 bg-gradient-to-r from-purple-500 to-pink-500 rounded-full animate-pulse"
                style={{ animationDelay: `${i * 0.2}s` }}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// Page Level Loading Component
export const PageLoading = ({ title = 'Loading...', description = '' }) => (
  <div className="min-h-screen flex items-center justify-center p-8">
    <div className="text-center space-y-6 animate-fade-in">
      <BrandLoadingSpinner size="xl" />
      <div>
        <h2 className="text-2xl font-bold text-gradient mb-2">{title}</h2>
        {description && (
          <p className="text-gray-400 max-w-md">{description}</p>
        )}
      </div>
    </div>
  </div>
);

// Section Loading Component
export const SectionLoading = ({ title = 'Loading section...', height = 'h-64' }) => (
  <div className={`${height} flex items-center justify-center border border-gray-800 rounded-2xl bg-gray-900/50 animate-pulse`}>
    <div className="text-center space-y-3">
      <div className="w-12 h-12 mx-auto bg-gray-700 rounded-xl animate-shimmer" />
      <p className="text-sm text-gray-400">{title}</p>
    </div>
  </div>
);

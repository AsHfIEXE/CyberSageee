import React from 'react';
import { FileText, Activity, Shield, AlertTriangle, CheckCircle } from 'lucide-react';
import { useTheme } from '../components/ThemeComponents';
import { BlueprintSkeleton } from '../components/EnhancedLoadingSkeletons';
import EnhancedBlueprintViewer from '../components/EnhancedBlueprintViewer';
import { useScan } from '../context/EnhancedScanContext';

const EnhancedBlueprintPage = () => {
  const { isDark } = useTheme();
  const { currentScanId, vulnerabilities, chains, toolActivity } = useScan();
  const [isLoading, setIsLoading] = React.useState(true);

  React.useEffect(() => {
    // Simulate loading time for blueprint generation
    const timer = setTimeout(() => setIsLoading(false), 2000);
    return () => clearTimeout(timer);
  }, []);

  const blueprintStats = React.useMemo(() => {
    if (!vulnerabilities || vulnerabilities.length === 0) {
      return {
        totalVulnerabilities: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        resolvedCount: 0
      };
    }

    return {
      totalVulnerabilities: vulnerabilities.length,
      criticalCount: vulnerabilities.filter(v => v.severity === 'critical').length,
      highCount: vulnerabilities.filter(v => v.severity === 'high').length,
      mediumCount: vulnerabilities.filter(v => v.severity === 'medium').length,
      lowCount: vulnerabilities.filter(v => v.severity === 'low').length,
      resolvedCount: vulnerabilities.filter(v => v.status === 'resolved').length
    };
  }, [vulnerabilities]);

  const chainStats = React.useMemo(() => {
    if (!chains || chains.length === 0) {
      return {
        totalChains: 0,
        activeChains: 0,
        potentialChains: 0,
        mitigatedChains: 0
      };
    }

    return {
      totalChains: chains.length,
      activeChains: chains.filter(c => c.status === 'active').length,
      potentialChains: chains.filter(c => c.status === 'potential').length,
      mitigatedChains: chains.filter(c => c.status === 'mitigated').length
    };
  }, [chains]);

  const toolStats = React.useMemo(() => {
    if (!toolActivity || toolActivity.length === 0) {
      return {
        totalTools: 0,
        completedTools: 0,
        runningTools: 0,
        failedTools: 0
      };
    }

    return {
      totalTools: toolActivity.length,
      completedTools: toolActivity.filter(t => t.status === 'completed').length,
      runningTools: toolActivity.filter(t => t.status === 'running').length,
      failedTools: toolActivity.filter(t => t.status === 'failed').length
    };
  }, [toolActivity]);

  if (isLoading) {
    return <BlueprintSkeleton />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-bold bg-gradient-to-r from-purple-400 to-blue-500 bg-clip-text text-transparent">
            Security Blueprint
          </h2>
          <p className="text-sm text-gray-400 mt-1">
            {currentScanId 
              ? `Comprehensive security analysis and recommendations for Scan ID: ${currentScanId}` 
              : 'No active scan - start a security scan to generate your blueprint'
            }
          </p>
        </div>
        {currentScanId && (
          <div className="flex items-center gap-2">
            <div className={`inline-flex items-center px-3 py-1.5 rounded-full text-xs font-medium ${
              vulnerabilities && vulnerabilities.length > 0 
                ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' 
                : 'bg-green-500/20 text-green-400 border border-green-500/30'
            }`}>
              <Shield className="w-3 h-3 mr-1.5" />
              {vulnerabilities && vulnerabilities.length > 0 ? 'Issues Found' : 'No Issues'}
            </div>
          </div>
        )}
      </div>

      {/* Blueprint Overview Cards */}
      {currentScanId && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {/* Vulnerabilities Overview */}
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="p-2 bg-red-500/20 rounded-lg">
                  <AlertTriangle className="w-5 h-5 text-red-400" />
                </div>
                <div className="text-right">
                  <div className="text-2xl font-bold text-gray-900 dark:text-white">
                    {blueprintStats.totalVulnerabilities}
                  </div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">Total Issues</div>
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-red-400">Critical</span>
                  <span className="text-red-400 font-medium">{blueprintStats.criticalCount}</span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-orange-400">High</span>
                  <span className="text-orange-400 font-medium">{blueprintStats.highCount}</span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-yellow-400">Medium</span>
                  <span className="text-yellow-400 font-medium">{blueprintStats.mediumCount}</span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-blue-400">Low</span>
                  <span className="text-blue-400 font-medium">{blueprintStats.lowCount}</span>
                </div>
              </div>
            </div>
            {blueprintStats.resolvedCount > 0 && (
              <div className="px-6 py-3 bg-green-500/10 border-t border-green-500/20">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-green-400">Resolved</span>
                  <span className="text-sm font-medium text-green-400">{blueprintStats.resolvedCount}</span>
                </div>
              </div>
            )}
          </div>

          {/* Attack Chains Overview */}
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="p-2 bg-purple-500/20 rounded-lg">
                  <Activity className="w-5 h-5 text-purple-400" />
                </div>
                <div className="text-right">
                  <div className="text-2xl font-bold text-gray-900 dark:text-white">
                    {chainStats.totalChains}
                  </div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">Attack Chains</div>
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-red-400">Active</span>
                  <span className="text-red-400 font-medium">{chainStats.activeChains}</span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-orange-400">Potential</span>
                  <span className="text-orange-400 font-medium">{chainStats.potentialChains}</span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-green-400">Mitigated</span>
                  <span className="text-green-400 font-medium">{chainStats.mitigatedChains}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Tool Activity Overview */}
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="p-2 bg-blue-500/20 rounded-lg">
                  <FileText className="w-5 h-5 text-blue-400" />
                </div>
                <div className="text-right">
                  <div className="text-2xl font-bold text-gray-900 dark:text-white">
                    {toolStats.totalTools}
                  </div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">Tools Used</div>
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-green-400">Completed</span>
                  <span className="text-green-400 font-medium">{toolStats.completedTools}</span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-blue-400">Running</span>
                  <span className="text-blue-400 font-medium">{toolStats.runningTools}</span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-red-400">Failed</span>
                  <span className="text-red-400 font-medium">{toolStats.failedTools}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Overall Health Score */}
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="p-2 bg-green-500/20 rounded-lg">
                  <CheckCircle className="w-5 h-5 text-green-400" />
                </div>
                <div className="text-right">
                  <div className="text-2xl font-bold text-gray-900 dark:text-white">
                    {Math.max(0, 100 - (blueprintStats.criticalCount * 20) - (blueprintStats.highCount * 10) - (blueprintStats.mediumCount * 5))}
                  </div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">Health Score</div>
                </div>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div 
                  className="bg-gradient-to-r from-green-400 to-blue-500 h-2 rounded-full transition-all duration-500"
                  style={{ 
                    width: `${Math.max(0, 100 - (blueprintStats.criticalCount * 20) - (blueprintStats.highCount * 10) - (blueprintStats.mediumCount * 5))}%` 
                  }}
                ></div>
              </div>
              <div className="mt-2 text-xs text-gray-500 dark:text-gray-400">
                {blueprintStats.totalVulnerabilities === 0 ? 'Excellent security posture' : 'Needs attention'}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Blueprint Viewer */}
      <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
        {currentScanId ? (
          <EnhancedBlueprintViewer 
            scanId={currentScanId}
            vulnerabilities={vulnerabilities}
            chains={chains}
            toolActivity={toolActivity}
          />
        ) : (
          /* Empty State */
          <div className="p-12 text-center">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-gray-100 dark:bg-gray-700 rounded-full mb-4">
              <FileText className="w-8 h-8 text-gray-400" />
            </div>
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
              No Active Scan
            </h3>
            <p className="text-gray-500 dark:text-gray-400 mb-6 max-w-md mx-auto">
              Start a security scan to generate your comprehensive security blueprint with detailed analysis, 
              vulnerability assessment, and actionable recommendations.
            </p>
            <button className="inline-flex items-center px-6 py-3 bg-primary hover:bg-primary/90 text-white rounded-lg transition-all duration-200 hover:scale-105">
              <Activity className="w-4 h-4 mr-2" />
              Start Security Scan
            </button>
          </div>
        )}
      </div>

      {/* Blueprint Information Panel */}
      {currentScanId && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Recent Activity */}
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Recent Activity
              </h3>
            </div>
            <div className="p-6 space-y-4">
              {toolActivity && toolActivity.slice(0, 5).map((tool, index) => (
                <div key={index} className="flex items-center gap-3">
                  <div className={`w-2 h-2 rounded-full ${
                    tool.status === 'completed' ? 'bg-green-400' :
                    tool.status === 'running' ? 'bg-blue-400 animate-pulse' :
                    tool.status === 'failed' ? 'bg-red-400' : 'bg-gray-400'
                  }`}></div>
                  <div className="flex-1">
                    <p className="text-sm font-medium text-gray-900 dark:text-white">
                      {tool.name}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {tool.status} • {tool.duration ? `${tool.duration}s` : 'In progress'}
                    </p>
                  </div>
                </div>
              ))}
              {!toolActivity || toolActivity.length === 0 && (
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  No tool activity recorded
                </p>
              )}
            </div>
          </div>

          {/* Quick Actions */}
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Quick Actions
              </h3>
            </div>
            <div className="p-6 space-y-3">
              <button className="w-full flex items-center justify-between p-3 text-left hover:bg-gray-50 dark:hover:bg-gray-700 rounded-lg transition-colors duration-200">
                <div>
                  <p className="text-sm font-medium text-gray-900 dark:text-white">
                    Export Blueprint
                  </p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    Download as PDF or JSON
                  </p>
                </div>
                <FileText className="w-4 h-4 text-gray-400" />
              </button>
              
              <button className="w-full flex items-center justify-between p-3 text-left hover:bg-gray-50 dark:hover:bg-gray-700 rounded-lg transition-colors duration-200">
                <div>
                  <p className="text-sm font-medium text-gray-900 dark:text-white">
                    Schedule Rescan
                  </p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    Run security scan again
                  </p>
                </div>
                <Activity className="w-4 h-4 text-gray-400" />
              </button>
              
              <button className="w-full flex items-center justify-between p-3 text-left hover:bg-gray-50 dark:hover:bg-gray-700 rounded-lg transition-colors duration-200">
                <div>
                  <p className="text-sm font-medium text-gray-900 dark:text-white">
                    Share Blueprint
                  </p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    Send to team members
                  </p>
                </div>
                <Shield className="w-4 h-4 text-gray-400" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default EnhancedBlueprintPage;
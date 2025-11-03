import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Shield, TrendingUp, TrendingDown, AlertTriangle, 
  Activity, Globe, Lock, Zap, Target, Clock,
  BarChart3, PieChart, Users, Server
} from 'lucide-react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  RadialLinearScale,
  Filler
} from 'chart.js';
import { Line, Bar, Doughnut, Radar } from 'react-chartjs-2';
import { CircularProgressbar, buildStyles } from 'react-circular-progressbar';
import 'react-circular-progressbar/dist/styles.css';

// Register ChartJS components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  RadialLinearScale,
  Title,
  Tooltip,
  Legend,
  Filler
);

const EnhancedDashboard = ({ vulnerabilities, stats, scanHistory, currentScan }) => {
  const [timeRange, setTimeRange] = useState('7d');
  const [riskScore, setRiskScore] = useState(0);

  // Calculate risk score
  useEffect(() => {
    const score = Math.min(100, 
      (stats.critical * 30) + 
      (stats.high * 15) + 
      (stats.medium * 5) + 
      (stats.low * 1)
    );
    setRiskScore(score);
  }, [stats]);

  // Chart configurations
  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: false
      },
      tooltip: {
        backgroundColor: 'rgba(0, 0, 0, 0.8)',
        titleColor: '#fff',
        bodyColor: '#fff',
        borderColor: '#8b5cf6',
        borderWidth: 1
      }
    },
    scales: {
      x: {
        grid: {
          color: 'rgba(255, 255, 255, 0.1)'
        },
        ticks: {
          color: '#9ca3af'
        }
      },
      y: {
        grid: {
          color: 'rgba(255, 255, 255, 0.1)'
        },
        ticks: {
          color: '#9ca3af'
        }
      }
    }
  };

  // Vulnerability trend data
  const trendData = {
    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
    datasets: [
      {
        label: 'Critical',
        data: [12, 19, 15, 25, 22, 30, 28],
        borderColor: '#dc2626',
        backgroundColor: 'rgba(220, 38, 38, 0.1)',
        tension: 0.4,
        fill: true
      },
      {
        label: 'High',
        data: [8, 12, 10, 14, 18, 16, 20],
        borderColor: '#ea580c',
        backgroundColor: 'rgba(234, 88, 12, 0.1)',
        tension: 0.4,
        fill: true
      }
    ]
  };

  // Severity distribution data
  const severityData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
      data: [stats.critical, stats.high, stats.medium, stats.low],
      backgroundColor: [
        '#dc2626',
        '#ea580c',
        '#f59e0b',
        '#3b82f6'
      ],
      borderWidth: 0
    }]
  };

  // Attack surface radar data
  const radarData = {
    labels: ['XSS', 'SQLi', 'CSRF', 'XXE', 'SSRF', 'RCE'],
    datasets: [
      {
        label: 'Current Scan',
        data: [65, 80, 45, 70, 55, 90],
        backgroundColor: 'rgba(139, 92, 246, 0.2)',
        borderColor: '#8b5cf6',
        pointBackgroundColor: '#8b5cf6',
        pointBorderColor: '#fff',
        pointHoverBackgroundColor: '#fff',
        pointHoverBorderColor: '#8b5cf6'
      },
      {
        label: 'Industry Average',
        data: [50, 60, 40, 45, 35, 70],
        backgroundColor: 'rgba(107, 114, 128, 0.2)',
        borderColor: '#6b7280',
        pointBackgroundColor: '#6b7280',
        pointBorderColor: '#fff',
        pointHoverBackgroundColor: '#fff',
        pointHoverBorderColor: '#6b7280'
      }
    ]
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">
            Security Dashboard
          </h1>
          <p className="text-gray-400 mt-1">Real-time security posture overview</p>
        </div>
        
        {/* Time Range Selector */}
        <div className="flex space-x-2">
          {['24h', '7d', '30d', '90d'].map((range) => (
            <button
              key={range}
              onClick={() => setTimeRange(range)}
              className={`px-4 py-2 rounded-lg transition-all ${
                timeRange === range
                  ? 'bg-purple-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              {range}
            </button>
          ))}
        </div>
      </div>

      {/* Top Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Risk Score Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-gradient-to-br from-purple-900/50 to-pink-900/50 rounded-xl p-6 border border-purple-500/30"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <p className="text-gray-400 text-sm">Risk Score</p>
              <p className="text-3xl font-bold text-white mt-1">{riskScore}</p>
            </div>
            <div className="w-16 h-16">
              <CircularProgressbar
                value={riskScore}
                text=""
                styles={buildStyles({
                  pathColor: riskScore > 70 ? '#dc2626' : riskScore > 40 ? '#f59e0b' : '#10b981',
                  trailColor: 'rgba(255, 255, 255, 0.1)'
                })}
              />
            </div>
          </div>
          <div className="flex items-center space-x-2">
            {riskScore > 50 ? (
              <>
                <TrendingUp className="w-4 h-4 text-red-500" />
                <span className="text-xs text-red-500">+12% from last scan</span>
              </>
            ) : (
              <>
                <TrendingDown className="w-4 h-4 text-green-500" />
                <span className="text-xs text-green-500">-8% from last scan</span>
              </>
            )}
          </div>
        </motion.div>

        {/* Total Vulnerabilities */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-gray-900/50 rounded-xl p-6 border border-gray-800"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <p className="text-gray-400 text-sm">Total Vulnerabilities</p>
              <p className="text-3xl font-bold text-white mt-1">
                {stats.critical + stats.high + stats.medium + stats.low}
              </p>
            </div>
            <div className="p-3 bg-red-500/20 rounded-lg">
              <AlertTriangle className="w-6 h-6 text-red-500" />
            </div>
          </div>
          <div className="flex space-x-4 text-xs">
            <span className="text-red-500">Critical: {stats.critical}</span>
            <span className="text-orange-500">High: {stats.high}</span>
          </div>
        </motion.div>

        {/* Scan Coverage */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-gray-900/50 rounded-xl p-6 border border-gray-800"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <p className="text-gray-400 text-sm">Scan Coverage</p>
              <p className="text-3xl font-bold text-white mt-1">94%</p>
            </div>
            <div className="p-3 bg-green-500/20 rounded-lg">
              <Target className="w-6 h-6 text-green-500" />
            </div>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-2">
            <div className="bg-gradient-to-r from-green-500 to-emerald-500 h-2 rounded-full" style={{ width: '94%' }} />
          </div>
        </motion.div>

        {/* Active Threats */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-gray-900/50 rounded-xl p-6 border border-gray-800"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <p className="text-gray-400 text-sm">Active Threats</p>
              <p className="text-3xl font-bold text-white mt-1">7</p>
            </div>
            <div className="p-3 bg-yellow-500/20 rounded-lg">
              <Zap className="w-6 h-6 text-yellow-500" />
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <div className="flex -space-x-1">
              <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
              <div className="w-2 h-2 bg-orange-500 rounded-full animate-pulse delay-75" />
              <div className="w-2 h-2 bg-yellow-500 rounded-full animate-pulse delay-150" />
            </div>
            <span className="text-xs text-gray-400">Requires immediate attention</span>
          </div>
        </motion.div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Vulnerability Trend */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="bg-gray-900/50 rounded-xl p-6 border border-gray-800"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Vulnerability Trend</h3>
            <Activity className="w-5 h-5 text-gray-400" />
          </div>
          <div className="h-64">
            <Line data={trendData} options={chartOptions} />
          </div>
        </motion.div>

        {/* Severity Distribution */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.1 }}
          className="bg-gray-900/50 rounded-xl p-6 border border-gray-800"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Severity Distribution</h3>
            <PieChart className="w-5 h-5 text-gray-400" />
          </div>
          <div className="h-64 flex items-center justify-center">
            <div className="w-48 h-48">
              <Doughnut 
                data={severityData} 
                options={{
                  ...chartOptions,
                  cutout: '70%',
                  plugins: {
                    ...chartOptions.plugins,
                    legend: {
                      display: true,
                      position: 'right',
                      labels: {
                        color: '#9ca3af',
                        padding: 15,
                        font: {
                          size: 12
                        }
                      }
                    }
                  }
                }}
              />
            </div>
          </div>
        </motion.div>

        {/* Attack Surface Analysis */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2 }}
          className="bg-gray-900/50 rounded-xl p-6 border border-gray-800"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Attack Surface Analysis</h3>
            <Globe className="w-5 h-5 text-gray-400" />
          </div>
          <div className="h-64">
            <Radar 
              data={radarData} 
              options={{
                ...chartOptions,
                scales: {
                  r: {
                    grid: {
                      color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                      color: '#9ca3af',
                      backdropColor: 'transparent'
                    },
                    pointLabels: {
                      color: '#9ca3af',
                      font: {
                        size: 11
                      }
                    }
                  }
                },
                plugins: {
                  ...chartOptions.plugins,
                  legend: {
                    display: true,
                    position: 'bottom',
                    labels: {
                      color: '#9ca3af',
                      padding: 15,
                      font: {
                        size: 12
                      }
                    }
                  }
                }
              }}
            />
          </div>
        </motion.div>

        {/* Recent Activity */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.3 }}
          className="bg-gray-900/50 rounded-xl p-6 border border-gray-800"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Recent Activity</h3>
            <Clock className="w-5 h-5 text-gray-400" />
          </div>
          <div className="space-y-3">
            {[
              { type: 'critical', message: 'SQL Injection detected in /api/users', time: '2 min ago' },
              { type: 'high', message: 'XSS vulnerability in search parameter', time: '15 min ago' },
              { type: 'scan', message: 'Deep scan completed for example.com', time: '1 hour ago' },
              { type: 'medium', message: 'CSRF token missing in forms', time: '2 hours ago' },
            ].map((activity, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                className="flex items-center space-x-3 p-3 bg-gray-800/50 rounded-lg"
              >
                <div className={`w-2 h-2 rounded-full ${
                  activity.type === 'critical' ? 'bg-red-500' :
                  activity.type === 'high' ? 'bg-orange-500' :
                  activity.type === 'medium' ? 'bg-yellow-500' :
                  'bg-blue-500'
                }`} />
                <div className="flex-1">
                  <p className="text-sm text-gray-300">{activity.message}</p>
                  <p className="text-xs text-gray-500">{activity.time}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* Quick Actions */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="grid grid-cols-2 md:grid-cols-4 gap-4"
      >
        {[
          { icon: Target, label: 'New Scan', color: 'from-purple-500 to-pink-500' },
          { icon: FileText, label: 'Generate Report', color: 'from-blue-500 to-cyan-500' },
          { icon: Shield, label: 'Security Audit', color: 'from-green-500 to-emerald-500' },
          { icon: Users, label: 'Team Overview', color: 'from-orange-500 to-red-500' },
        ].map((action, index) => {
          const Icon = action.icon;
          return (
            <motion.button
              key={index}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className={`p-4 rounded-xl bg-gradient-to-r ${action.color} shadow-lg flex flex-col items-center space-y-2`}
            >
              <Icon className="w-6 h-6 text-white" />
              <span className="text-white font-medium">{action.label}</span>
            </motion.button>
          );
        })}
      </motion.div>
    </div>
  );
};

export default EnhancedDashboard;

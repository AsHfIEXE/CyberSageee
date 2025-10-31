import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Activity, Target, AlertTriangle, RefreshCw, Link2, Tool,
  Shield, Menu, X, Home, FileText, Settings, HelpCircle,
  Sun, Moon, ChevronRight, Zap, Globe, Lock, Code,
  BarChart3, Users, Bell, Search, Command
} from 'lucide-react';
import { clsx } from 'clsx';

const ProfessionalNavigation = ({ currentPage, setCurrentPage, stats, scanStatus }) => {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [theme, setTheme] = useState('dark');

  const navigation = [
    { 
      id: 'dashboard', 
      label: 'Dashboard', 
      icon: Activity, 
      desc: 'Overview & Analytics',
      color: 'from-blue-500 to-cyan-500'
    },
    { 
      id: 'scanner', 
      label: 'Scanner', 
      icon: Target, 
      desc: 'Security Scanning',
      color: 'from-purple-500 to-pink-500'
    },
    { 
      id: 'vulnerabilities', 
      label: 'Vulnerabilities', 
      icon: AlertTriangle, 
      desc: 'Security Findings',
      badge: stats.critical + stats.high + stats.medium + stats.low,
      color: 'from-red-500 to-orange-500'
    },
    { 
      id: 'repeater', 
      label: 'HTTP Repeater', 
      icon: RefreshCw, 
      desc: 'Request Testing',
      color: 'from-green-500 to-teal-500'
    },
    { 
      id: 'chains', 
      label: 'Attack Chains', 
      icon: Link2, 
      desc: 'Vulnerability Links',
      color: 'from-yellow-500 to-amber-500'
    },
    { 
      id: 'tools', 
      label: 'Pro Tools', 
      icon: Tool, 
      desc: 'Advanced Toolkit',
      color: 'from-indigo-500 to-purple-500'
    },
  ];

  const bottomNavigation = [
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'settings', label: 'Settings', icon: Settings },
    { id: 'help', label: 'Help', icon: HelpCircle },
  ];

  const getScanStatusColor = () => {
    switch (scanStatus) {
      case 'running': return 'bg-green-500';
      case 'completed': return 'bg-blue-500';
      case 'failed': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

  return (
    <>
      {/* Mobile Menu Button */}
      <button
        className="lg:hidden fixed top-4 left-4 z-50 p-2 bg-gray-900 rounded-lg shadow-lg"
        onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
      >
        {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
      </button>

      {/* Desktop Navigation */}
      <motion.nav
        initial={false}
        animate={{ width: collapsed ? 80 : 280 }}
        className={clsx(
          'hidden lg:flex flex-col fixed top-0 left-0 h-full',
          'bg-gradient-to-b from-gray-900 via-gray-900 to-black',
          'border-r border-gray-800 shadow-2xl'
        )}
      >
        {/* Header */}
        <div className="p-6 border-b border-gray-800">
          <div className="flex items-center justify-between">
            <motion.div
              animate={{ opacity: collapsed ? 0 : 1 }}
              className="flex items-center space-x-3"
            >
              <div className="relative">
                <div className="w-12 h-12 bg-gradient-to-br from-purple-600 to-pink-600 rounded-xl flex items-center justify-center shadow-lg">
                  <Shield className="w-7 h-7 text-white" />
                </div>
                {scanStatus === 'running' && (
                  <div className="absolute -top-1 -right-1 w-3 h-3 bg-green-500 rounded-full animate-pulse" />
                )}
              </div>
              {!collapsed && (
                <div>
                  <h1 className="text-2xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">
                    CyberSage
                  </h1>
                  <p className="text-xs text-gray-500">Enterprise Security</p>
                </div>
              )}
            </motion.div>
            
            <button
              onClick={() => setCollapsed(!collapsed)}
              className="p-2 hover:bg-gray-800 rounded-lg transition-colors"
            >
              <ChevronRight className={clsx(
                'w-5 h-5 text-gray-400 transition-transform',
                collapsed ? 'rotate-0' : 'rotate-180'
              )} />
            </button>
          </div>

          {/* Scan Status */}
          {scanStatus !== 'idle' && !collapsed && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="mt-4"
            >
              <div className={clsx(
                'px-3 py-2 rounded-lg flex items-center space-x-2',
                scanStatus === 'running' ? 'bg-green-500/10 border border-green-500/30' :
                scanStatus === 'completed' ? 'bg-blue-500/10 border border-blue-500/30' :
                'bg-red-500/10 border border-red-500/30'
              )}>
                <div className={clsx('w-2 h-2 rounded-full', getScanStatusColor())} />
                <span className="text-xs font-medium">
                  {scanStatus === 'running' ? 'Scan in Progress' :
                   scanStatus === 'completed' ? 'Scan Complete' :
                   'Scan Failed'}
                </span>
              </div>
            </motion.div>
          )}
        </div>

        {/* Search Bar */}
        {!collapsed && (
          <div className="p-4 border-b border-gray-800">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input
                type="text"
                placeholder="Search..."
                className="w-full pl-10 pr-10 py-2 bg-gray-800 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
              <div className="absolute right-3 top-1/2 transform -translate-y-1/2 flex items-center space-x-1">
                <Command className="w-3 h-3 text-gray-500" />
                <span className="text-xs text-gray-500">K</span>
              </div>
            </div>
          </div>
        )}

        {/* Main Navigation */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          {navigation.map((item) => {
            const Icon = item.icon;
            const isActive = currentPage === item.id;
            
            return (
              <motion.button
                key={item.id}
                onClick={() => setCurrentPage(item.id)}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className={clsx(
                  'w-full group relative overflow-hidden rounded-xl transition-all duration-300',
                  isActive
                    ? 'bg-gradient-to-r ' + item.color + ' shadow-lg'
                    : 'bg-gray-800/50 hover:bg-gray-800'
                )}
              >
                {/* Hover Effect */}
                {!isActive && (
                  <div className="absolute inset-0 bg-gradient-to-r from-purple-600/0 to-pink-600/0 group-hover:from-purple-600/10 group-hover:to-pink-600/10 transition-all duration-300" />
                )}

                <div className="relative p-4 flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className={clsx(
                      'p-2 rounded-lg',
                      isActive ? 'bg-white/20' : 'bg-gray-700/50 group-hover:bg-gray-700'
                    )}>
                      <Icon className={clsx(
                        'w-5 h-5',
                        isActive ? 'text-white' : 'text-gray-400 group-hover:text-white'
                      )} />
                    </div>
                    
                    {!collapsed && (
                      <div className="text-left">
                        <p className={clsx(
                          'font-semibold',
                          isActive ? 'text-white' : 'text-gray-300'
                        )}>
                          {item.label}
                        </p>
                        <p className={clsx(
                          'text-xs',
                          isActive ? 'text-white/70' : 'text-gray-500'
                        )}>
                          {item.desc}
                        </p>
                      </div>
                    )}
                  </div>

                  {!collapsed && item.badge && item.badge > 0 && (
                    <motion.span
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      className="px-2 py-1 bg-red-500 text-white text-xs font-bold rounded-full"
                    >
                      {item.badge > 99 ? '99+' : item.badge}
                    </motion.span>
                  )}
                </div>
              </motion.button>
            );
          })}
        </div>

        {/* Bottom Navigation */}
        <div className="p-4 border-t border-gray-800 space-y-2">
          {bottomNavigation.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onClick={() => setCurrentPage(item.id)}
                className="w-full p-3 flex items-center space-x-3 text-gray-400 hover:text-white hover:bg-gray-800 rounded-lg transition-all"
              >
                <Icon className="w-4 h-4" />
                {!collapsed && <span className="text-sm">{item.label}</span>}
              </button>
            );
          })}

          {/* Theme Toggle */}
          <button
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            className="w-full p-3 flex items-center space-x-3 text-gray-400 hover:text-white hover:bg-gray-800 rounded-lg transition-all"
          >
            {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            {!collapsed && <span className="text-sm">Toggle Theme</span>}
          </button>
        </div>

        {/* Footer */}
        {!collapsed && (
          <div className="p-4 border-t border-gray-800">
            <div className="flex items-center justify-between text-xs text-gray-500">
              <span>v3.0 Elite</span>
              <div className="flex items-center space-x-2">
                <div className="flex items-center space-x-1">
                  <Zap className="w-3 h-3 text-green-500" />
                  <span>Online</span>
                </div>
                <div className="flex items-center space-x-1">
                  <Globe className="w-3 h-3" />
                  <span>Global</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </motion.nav>

      {/* Mobile Navigation */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="lg:hidden fixed inset-0 z-40 bg-black/50"
            onClick={() => setMobileMenuOpen(false)}
          >
            <motion.nav
              initial={{ x: -300 }}
              animate={{ x: 0 }}
              exit={{ x: -300 }}
              className="w-72 h-full bg-gradient-to-b from-gray-900 to-black"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Mobile nav content - similar to desktop */}
              <div className="p-6">
                <div className="flex items-center space-x-3 mb-6">
                  <Shield className="w-10 h-10 text-purple-500" />
                  <h1 className="text-2xl font-bold text-white">CyberSage</h1>
                </div>
                
                <div className="space-y-2">
                  {navigation.map((item) => {
                    const Icon = item.icon;
                    const isActive = currentPage === item.id;
                    
                    return (
                      <button
                        key={item.id}
                        onClick={() => {
                          setCurrentPage(item.id);
                          setMobileMenuOpen(false);
                        }}
                        className={clsx(
                          'w-full p-4 rounded-lg flex items-center space-x-3',
                          isActive
                            ? 'bg-purple-600 text-white'
                            : 'text-gray-300 hover:bg-gray-800'
                        )}
                      >
                        <Icon className="w-5 h-5" />
                        <span>{item.label}</span>
                        {item.badge && item.badge > 0 && (
                          <span className="ml-auto px-2 py-1 bg-red-500 text-white text-xs rounded-full">
                            {item.badge}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>
            </motion.nav>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
};

export default ProfessionalNavigation;

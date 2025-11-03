import React, { useState, useEffect } from 'react';

const ProfessionalFormAnalysisViewer = ({ scanId }) => {
  const [forms, setForms] = useState([]);
  const [selectedForm, setSelectedForm] = useState(null);
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadingAI, setLoadingAI] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  
  const backendUrl = process.env.REACT_APP_BACKEND_URL || `${window.location.protocol}//${window.location.hostname}:5000`;

  useEffect(() => {
    if (scanId) {
      loadForms();
    }
  }, [scanId]);

  const loadForms = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${backendUrl}/api/scan/${scanId}/forms`);
      const data = await response.json();
      setForms(data.forms || []);
    } catch (error) {
      console.error('Error loading forms:', error);
    } finally {
      setLoading(false);
    }
  };

  const requestAIAnalysis = async (form) => {
    setLoadingAI(true);
    try {
      const response = await fetch(`${backendUrl}/api/forms/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ form_data: form })
      });
      const data = await response.json();
      setAiAnalysis(data);
    } catch (error) {
      console.error('Error getting AI analysis:', error);
    } finally {
      setLoadingAI(false);
    }
  };

  const getRiskColor = (level) => {
    const colors = {
      critical: 'bg-red-500',
      high: 'bg-orange-500',
      medium: 'bg-yellow-500',
      low: 'bg-blue-500'
    };
    return colors[level] || 'bg-gray-500';
  };

  const getFieldIcon = (type) => {
    const icons = {
      text: '📝',
      email: '📧',
      password: '🔒',
      file: '📎',
      number: '🔢',
      tel: '📞',
      url: '🔗',
      textarea: '📄',
      select: '📋',
      checkbox: '☑️',
      radio: '⭕',
      hidden: '👁️'
    };
    return icons[type] || '📝';
  };

  if (!scanId) {
    return (
      <div className="bg-gray-900 rounded-xl border border-gray-700 p-8">
        <div className="text-center">
          <div className="text-6xl mb-4">📝</div>
          <h3 className="text-white text-xl font-bold mb-2">Form Security Analysis</h3>
          <p className="text-gray-400">Start a scan with form discovery to analyze forms</p>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="bg-gray-900 rounded-xl border border-gray-700 p-8">
        <div className="text-center">
          <div className="animate-spin text-4xl mb-4">⚙️</div>
          <p className="text-gray-400">Analyzing forms...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-900 rounded-xl border border-gray-700">
      {/* Header */}
      <div className="p-6 border-b border-gray-700">
        <div className="flex justify-between items-center">
          <div className="flex items-center space-x-3">
            <div className="text-3xl">📝</div>
            <div>
              <h3 className="text-white text-xl font-bold">Form Security Analysis</h3>
              <p className="text-gray-400 text-sm">AI-Powered Professional Analysis with Remediation</p>
            </div>
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold text-white">{forms.length}</div>
            <div className="text-gray-400 text-sm">Forms Found</div>
          </div>
        </div>
      </div>

      {forms.length === 0 ? (
        <div className="p-12 text-center">
          <div className="text-6xl mb-4">🔍</div>
          <h4 className="text-white text-lg font-bold mb-2">No Forms Discovered</h4>
          <p className="text-gray-400 mb-4">The scanner didn't find any forms on this site.</p>
          <p className="text-gray-500 text-sm">Enable form discovery in scan settings to detect forms.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-0">
          {/* Forms List */}
          <div className="border-r border-gray-700 p-4 max-h-[600px] overflow-y-auto">
            <h4 className="text-white font-bold mb-4">Discovered Forms</h4>
            <div className="space-y-2">
              {forms.map((form, index) => (
                <button
                  key={index}
                  onClick={() => {
                    setSelectedForm(form);
                    setAiAnalysis(null);
                    setActiveTab('overview');
                  }}
                  className={`w-full text-left p-4 rounded-lg transition ${
                    selectedForm === form
                      ? 'bg-purple-600 text-white'
                      : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold text-sm">
                      {form.form_purpose?.toUpperCase() || 'UNKNOWN'} Form
                    </span>
                    <span className={`px-2 py-1 rounded text-xs ${getRiskColor(form.security_analysis?.risk_level || 'low')}`}>
                      {form.security_analysis?.risk_level?.toUpperCase() || 'LOW'}
                    </span>
                  </div>
                  <div className="text-xs opacity-75 truncate">
                    {form.page_url}
                  </div>
                  <div className="flex items-center space-x-3 mt-2 text-xs">
                    <span>📝 {form.fields?.length || 0} fields</span>
                    <span>⚠️ {form.security_analysis?.total_issues || 0} issues</span>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Form Details */}
          <div className="lg:col-span-2 p-6">
            {!selectedForm ? (
              <div className="text-center py-12">
                <div className="text-4xl mb-4">👈</div>
                <p className="text-gray-400">Select a form to view details</p>
              </div>
            ) : (
              <div className="space-y-6">
                {/* Tabs */}
                <div className="flex space-x-2 border-b border-gray-700">
                  {['overview', 'fields', 'security', 'ai-analysis', 'remediation'].map(tab => (
                    <button
                      key={tab}
                      onClick={() => setActiveTab(tab)}
                      className={`px-4 py-2 text-sm font-medium transition ${
                        activeTab === tab
                          ? 'text-purple-400 border-b-2 border-purple-400'
                          : 'text-gray-400 hover:text-white'
                      }`}
                    >
                      {tab.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}
                    </button>
                  ))}
                </div>

                {/* Tab Content */}
                {activeTab === 'overview' && (
                  <div className="space-y-4">
                    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                      <h4 className="text-white font-bold mb-3">Form Information</h4>
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-400">Purpose:</span>
                          <span className="text-white font-semibold">{selectedForm.form_purpose?.toUpperCase()}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Method:</span>
                          <span className="text-white">{selectedForm.method}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Action:</span>
                          <span className="text-purple-400 font-mono text-xs truncate max-w-xs">{selectedForm.action}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Fields:</span>
                          <span className="text-white">{selectedForm.fields?.length || 0}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Sensitive Fields:</span>
                          <span className="text-yellow-400">{selectedForm.sensitive_fields?.length || 0}</span>
                        </div>
                      </div>
                    </div>

                    <div className={`rounded-lg p-4 border-2 ${
                      selectedForm.security_analysis?.risk_level === 'critical' ? 'bg-red-900/20 border-red-500' :
                      selectedForm.security_analysis?.risk_level === 'high' ? 'bg-orange-900/20 border-orange-500' :
                      selectedForm.security_analysis?.risk_level === 'medium' ? 'bg-yellow-900/20 border-yellow-500' :
                      'bg-blue-900/20 border-blue-500'
                    }`}>
                      <div className="flex justify-between items-center mb-3">
                        <h4 className="text-white font-bold">Security Risk</h4>
                        <span className={`px-3 py-1 rounded ${getRiskColor(selectedForm.security_analysis?.risk_level)} text-white font-bold`}>
                          {selectedForm.security_analysis?.risk_level?.toUpperCase() || 'LOW'}
                        </span>
                      </div>
                      <div className="mb-3">
                        <div className="flex justify-between text-sm mb-1">
                          <span className="text-gray-300">Risk Score</span>
                          <span className="text-white font-bold">{selectedForm.security_analysis?.risk_score || 0}/100</span>
                        </div>
                        <div className="w-full bg-gray-700 rounded-full h-3">
                          <div
                            className={`h-3 rounded-full ${getRiskColor(selectedForm.security_analysis?.risk_level)}`}
                            style={{ width: `${selectedForm.security_analysis?.risk_score || 0}%` }}
                          ></div>
                        </div>
                      </div>
                      <div className="text-sm text-gray-300">
                        {selectedForm.security_analysis?.total_issues || 0} security issues identified
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === 'fields' && (
                  <div className="space-y-3">
                    <h4 className="text-white font-bold">Form Fields ({selectedForm.fields?.length || 0})</h4>
                    {selectedForm.fields?.map((field, index) => (
                      <div key={index} className={`bg-gray-800 rounded-lg p-4 border ${
                        field.is_sensitive ? 'border-yellow-500' : 'border-gray-700'
                      }`}>
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex items-center space-x-2">
                            <span className="text-2xl">{getFieldIcon(field.type)}</span>
                            <div>
                              <div className="text-white font-semibold">{field.name || 'Unnamed'}</div>
                              <div className="text-gray-400 text-xs">{field.type}</div>
                            </div>
                          </div>
                          <div className="flex flex-wrap gap-1">
                            {field.required && <span className="px-2 py-1 bg-red-600 text-white text-xs rounded">Required</span>}
                            {field.is_sensitive && <span className="px-2 py-1 bg-yellow-600 text-white text-xs rounded">Sensitive</span>}
                            {field.readonly && <span className="px-2 py-1 bg-gray-600 text-white text-xs rounded">Read-only</span>}
                          </div>
                        </div>
                        {field.placeholder && (
                          <div className="text-sm text-gray-400 mt-2">
                            Placeholder: {field.placeholder}
                          </div>
                        )}
                        {field.pattern && (
                          <div className="text-sm text-purple-400 font-mono mt-2">
                            Pattern: {field.pattern}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {activeTab === 'security' && (
                  <div className="space-y-4">
                    <h4 className="text-white font-bold">Security Issues</h4>
                    {selectedForm.security_analysis?.issues?.length === 0 ? (
                      <div className="text-center py-8">
                        <div className="text-4xl mb-2">✅</div>
                        <p className="text-green-400">No automated security issues detected</p>
                      </div>
                    ) : (
                      selectedForm.security_analysis?.issues?.map((issue, index) => (
                        <div key={index} className={`rounded-lg p-4 border ${
                          issue.severity === 'critical' ? 'bg-red-900/20 border-red-500' :
                          issue.severity === 'high' ? 'bg-orange-900/20 border-orange-500' :
                          issue.severity === 'medium' ? 'bg-yellow-900/20 border-yellow-500' :
                          'bg-blue-900/20 border-blue-500'
                        }`}>
                          <div className="flex justify-between items-start mb-2">
                            <h5 className="text-white font-bold">{issue.issue}</h5>
                            <span className={`px-2 py-1 rounded text-xs ${
                              issue.severity === 'critical' ? 'bg-red-500' :
                              issue.severity === 'high' ? 'bg-orange-500' :
                              issue.severity === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'
                            } text-white font-bold`}>
                              {issue.severity.toUpperCase()}
                            </span>
                          </div>
                          <div className="text-gray-300 text-sm mb-2">{issue.description}</div>
                          <div className="text-gray-400 text-xs">Affected Field: <span className="text-purple-400 font-mono">{issue.field}</span></div>
                        </div>
                      ))
                    )}
                  </div>
                )}

                {activeTab === 'ai-analysis' && (
                  <div className="space-y-4">
                    {!aiAnalysis ? (
                      <div className="text-center py-8">
                        <div className="text-6xl mb-4">🤖</div>
                        <h4 className="text-white font-bold mb-2">AI-Powered Security Analysis</h4>
                        <p className="text-gray-400 mb-6">Get professional security analysis from AI</p>
                        <button
                          onClick={() => requestAIAnalysis(selectedForm)}
                          disabled={loadingAI}
                          className="px-6 py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white rounded-lg font-bold disabled:opacity-50"
                        >
                          {loadingAI ? '🤖 Analyzing...' : '🚀 Start AI Analysis'}
                        </button>
                      </div>
                    ) : (
                      <div className="bg-gray-800 rounded-lg p-6 border border-purple-500">
                        <div className="flex items-center justify-between mb-4">
                          <h4 className="text-white font-bold flex items-center">
                            <span className="mr-2">🤖</span>
                            AI Security Analysis
                          </h4>
                          <span className="px-3 py-1 bg-purple-600 text-white text-xs rounded-full">
                            {aiAnalysis.model_used}
                          </span>
                        </div>
                        <pre className="text-gray-300 text-sm whitespace-pre-wrap leading-relaxed">
{aiAnalysis.ai_analysis}
                        </pre>
                      </div>
                    )}
                  </div>
                )}

                {activeTab === 'remediation' && (
                  <div className="space-y-4">
                    <h4 className="text-white font-bold">Remediation Steps</h4>
                    {selectedForm.security_analysis?.recommendations?.length === 0 ? (
                      <div className="text-center py-8">
                        <div className="text-4xl mb-2">✅</div>
                        <p className="text-green-400">No remediation needed - form is secure</p>
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {selectedForm.security_analysis?.recommendations?.map((rec, index) => (
                          <div key={index} className="bg-gray-800 rounded-lg p-4 border border-green-500/50">
                            <div className="flex items-start space-x-3">
                              <div className="text-green-400 font-bold text-lg">{index + 1}</div>
                              <div className="flex-1">
                                <p className="text-gray-300">{rec}</p>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default ProfessionalFormAnalysisViewer;
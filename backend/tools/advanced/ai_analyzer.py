import os
import json
import requests

class AIAnalyzer:
    """
    AI-powered vulnerability analysis and insights
    """
    
    def __init__(self, database, broadcaster):
        self.db = database
        self.broadcaster = broadcaster
        self.api_key = os.environ.get('OPENROUTER_API_KEY', '')
        self.api_base = 'https://openrouter.ai/api/v1'
    
    def analyze(self, scan_id, scan_data):
        """
        Perform AI analysis on scan results
        """
        insights = []
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        chains = scan_data.get('chains', [])
        recon_data = scan_data.get('recon_data', {})
        
        if not vulnerabilities:
            print("[AI Analyzer] No vulnerabilities to analyze")
            return insights
        
        print(f"[AI Analyzer] Analyzing {len(vulnerabilities)} vulnerabilities...")
        
        # Severity prioritization insight
        severity_insight = self._analyze_severity_distribution(vulnerabilities)
        if severity_insight:
            insights.append(severity_insight)
        
        # Attack surface analysis
        surface_insight = self._analyze_attack_surface(recon_data, vulnerabilities)
        if surface_insight:
            insights.append(surface_insight)
        
        # Risk assessment
        risk_insight = self._calculate_overall_risk(vulnerabilities, chains)
        if risk_insight:
            insights.append(risk_insight)
        
        # AI-powered recommendations (if API key available)
        if self.api_key and self.api_key != 'YOUR_API_KEY':
            ai_recommendations = self._get_ai_recommendations(vulnerabilities, chains)
            insights.extend(ai_recommendations)
        
        print(f"[AI Analyzer] Generated {len(insights)} insights")
        
        return insights
    
    def _analyze_severity_distribution(self, vulnerabilities):
        """
        Analyze vulnerability severity distribution
        """
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        total = sum(severity_counts.values())
        critical_high_percent = ((severity_counts['critical'] + severity_counts['high']) / total * 100) if total > 0 else 0
        
        if critical_high_percent > 50:
            severity_level = 'critical'
            message = f"⚠️ CRITICAL: {critical_high_percent:.0f}% of vulnerabilities are Critical or High severity. Immediate action required!"
        elif critical_high_percent > 25:
            severity_level = 'high'
            message = f"⚠️ {critical_high_percent:.0f}% of vulnerabilities are Critical or High severity. Prompt remediation recommended."
        else:
            severity_level = 'medium'
            message = f"ℹ️ Most vulnerabilities are Medium or Low severity. Prioritize based on business impact."
        
        return {
            'type': 'severity_analysis',
            'severity': severity_level,
            'message': message,
            'confidence': 100,
            'data': severity_counts
        }
    
    def _analyze_attack_surface(self, recon_data, vulnerabilities):
        """
        Analyze attack surface exposure
        """
        subdomains = len(recon_data.get('subdomains', []))
        live_hosts = len(recon_data.get('live_hosts', []))
        endpoints = len(recon_data.get('endpoints', []))
        
        # Calculate exposure score
        exposure_score = min(100, (subdomains * 2) + (live_hosts * 5) + (endpoints * 1))
        
        if exposure_score > 70:
            severity = 'high'
            message = f"🌐 Large attack surface detected: {subdomains} subdomains, {live_hosts} live hosts, {endpoints} endpoints. Consider reducing exposure."
        elif exposure_score > 40:
            severity = 'medium'
            message = f"🌐 Moderate attack surface: {subdomains} subdomains, {live_hosts} live hosts, {endpoints} endpoints."
        else:
            severity = 'low'
            message = f"🌐 Limited attack surface: {subdomains} subdomains, {live_hosts} live hosts."
        
        return {
            'type': 'attack_surface',
            'severity': severity,
            'message': message,
            'confidence': 90,
            'data': {
                'subdomains': subdomains,
                'live_hosts': live_hosts,
                'endpoints': endpoints,
                'exposure_score': exposure_score
            }
        }
    
    def _calculate_overall_risk(self, vulnerabilities, chains):
        """
        Calculate overall security risk score
        """
        # Risk calculation
        risk_score = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            confidence = vuln.get('confidence', 50)
            
            # Weight by severity and confidence
            severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
            risk_score += severity_weights.get(severity, 1) * (confidence / 100)
        
        # Add extra risk for chains
        risk_score += len(chains) * 15
        
        # Normalize to 0-100
        normalized_risk = min(100, int(risk_score))
        
        if normalized_risk >= 80:
            risk_level = 'critical'
            message = f"🔴 CRITICAL RISK ({normalized_risk}/100): Multiple severe vulnerabilities detected. Immediate remediation required!"
        elif normalized_risk >= 60:
            risk_level = 'high'
            message = f"🟠 HIGH RISK ({normalized_risk}/100): Significant vulnerabilities present. Prioritize fixes."
        elif normalized_risk >= 40:
            risk_level = 'medium'
            message = f"🟡 MEDIUM RISK ({normalized_risk}/100): Some vulnerabilities detected. Plan remediation."
        else:
            risk_level = 'low'
            message = f"🟢 LOW RISK ({normalized_risk}/100): Minimal vulnerabilities detected."
        
        return {
            'type': 'overall_risk',
            'severity': risk_level,
            'message': message,
            'confidence': 95,
            'data': {
                'risk_score': normalized_risk,
                'vulnerability_count': len(vulnerabilities),
                'chain_count': len(chains)
            }
        }
    
    def _get_ai_recommendations(self, vulnerabilities, chains):
        """
        Get AI-powered remediation recommendations
        """
        insights = []
        
        try:
            # Prepare summary for AI
            vuln_summary = self._prepare_vulnerability_summary(vulnerabilities, chains)
            
            prompt = f"""You are an elite cybersecurity expert analyzing scan results.

Vulnerabilities Found:
{vuln_summary}

Provide 3 concise, actionable security recommendations focusing on:
1. Highest priority fixes
2. Quick wins for risk reduction
3. Long-term security improvements

Format each recommendation as a single paragraph (2-3 sentences max).
Be specific and technical."""

            # Call OpenRouter API
            response = requests.post(
                f'{self.api_base}/chat/completions',
                headers={
                    'Authorization': f'Bearer {self.api_key}',
                    'Content-Type': 'application/json',
                    'HTTP-Referer': 'http://localhost:5000',
                    'X-Title': 'CyberSage v2.0'
                },
                json={
                    'model': 'mistralai/mistral-7b-instruct',
                    'messages': [
                        {'role': 'user', 'content': prompt}
                    ],
                    'max_tokens': 500,
                    'temperature': 0.7
                },
                timeout=30
            )
            
            if response.status_code == 200:
                ai_response = response.json()
                recommendations_text = ai_response['choices'][0]['message']['content']
                
                insights.append({
                    'type': 'ai_recommendations',
                    'severity': 'info',
                    'message': f"🤖 AI-Powered Recommendations:\n\n{recommendations_text}",
                    'confidence': 85,
                    'data': {'source': 'ai_analysis'}
                })
            else:
                print(f"[AI Analyzer] API call failed: {response.status_code}")
        
        except Exception as e:
            print(f"[AI Analyzer] Error getting AI recommendations: {str(e)}")
        
        return insights
    
    def _prepare_vulnerability_summary(self, vulnerabilities, chains):
        """
        Prepare concise vulnerability summary for AI
        """
        summary_lines = []
        
        # Group by severity
        by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln.get('type', 'Unknown'))
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in by_severity:
                types = list(set(by_severity[severity]))[:5]  # Unique types, max 5
                summary_lines.append(f"- {severity.upper()}: {', '.join(types)}")
        
        if chains:
            summary_lines.append(f"\nAttack Chains Detected: {len(chains)}")
            for chain in chains[:3]:
                summary_lines.append(f"  - {chain.get('name', 'Unknown chain')}")
        
        return "\n".join(summary_lines)
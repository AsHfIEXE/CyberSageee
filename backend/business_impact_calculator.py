"""
Business Impact Calculator
Calculates financial impact, ROI, and compliance status
"""

from typing import Dict, List, Any

class BusinessImpactCalculator:
    """
    Calculate business impact of vulnerabilities
    - Financial impact (data breach, downtime, regulatory fines)
    - ROI analysis
    - Compliance assessment
    """
    
    def __init__(self):
        self.industry_multipliers = {
            'finance': 2.5,
            'healthcare': 2.0,
            'retail': 1.5,
            'technology': 1.2,
            'manufacturing': 1.0,
            'education': 0.8
        }
        
        self.compliance_thresholds = {
            'pci_dss': {'max_high': 0, 'max_critical': 0},
            'gdpr': {'max_high': 0, 'max_critical': 0},
            'hipaa': {'max_high': 0, 'max_critical': 0},
            'soc2': {'max_high': 1, 'max_critical': 0}
        }
    
    def calculate_impact(self, vulnerabilities: List[Dict], business_inputs: Dict) -> Dict[str, Any]:
        """
        Calculate comprehensive business impact
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            business_inputs: {
                'annual_revenue': int,
                'employee_count': int,
                'industry': str,
                'data_records': int,
                'compliance_required': List[str]
            }
        
        Returns:
            Dictionary with risk score, financial impact, ROI, and compliance status
        """
        
        # Extract vulnerability counts by severity
        critical_count = sum(1 for v in vulnerabilities if v.get('severity') == 'critical')
        high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'high')
        medium_count = sum(1 for v in vulnerabilities if v.get('severity') == 'medium')
        low_count = sum(1 for v in vulnerabilities if v.get('severity') == 'low')
        
        # Calculate overall risk score (0-100)
        risk_score = min(100, (critical_count * 25) + (high_count * 15) + (medium_count * 5) + (low_count * 1))
        
        # Get industry multiplier
        industry = business_inputs.get('industry', 'technology').lower()
        multiplier = self.industry_multipliers.get(industry, 1.0)
        
        # Calculate financial impacts
        financial_impact = self._calculate_financial_impact(
            business_inputs,
            risk_score,
            multiplier
        )
        
        # Calculate ROI analysis
        roi_analysis = self._calculate_roi(
            financial_impact['total_potential_loss'],
            critical_count,
            high_count
        )
        
        # Assess compliance status
        compliance_status = self._assess_compliance(
            business_inputs.get('compliance_required', []),
            critical_count,
            high_count
        )
        
        return {
            'total_risk_score': risk_score,
            'financial_impact': financial_impact,
            'roi_analysis': roi_analysis,
            'compliance_status': compliance_status,
            'vulnerability_breakdown': {
                'critical': critical_count,
                'high': high_count,
                'medium': medium_count,
                'low': low_count
            }
        }
    
    def _calculate_financial_impact(self, inputs: Dict, risk_score: int, multiplier: float) -> Dict:
        """Calculate potential financial losses"""
        
        annual_revenue = inputs.get('annual_revenue', 10000000)
        data_records = inputs.get('data_records', 10000)
        
        # Data breach cost (industry average: $150 per record)
        data_breach_cost = data_records * 150 * multiplier
        
        # Downtime cost (3 days average, scaled by risk)
        daily_revenue = annual_revenue / 365
        downtime_days = 3 * (risk_score / 100)
        downtime_cost = daily_revenue * downtime_days
        
        # Regulatory fines (up to 4% of annual revenue for GDPR-style regulations)
        compliance_required = inputs.get('compliance_required', [])
        if compliance_required:
            regulatory_fines = annual_revenue * 0.04 * multiplier
        else:
            regulatory_fines = 0
        
        total_potential_loss = data_breach_cost + downtime_cost + regulatory_fines
        
        return {
            'data_breach_cost': int(data_breach_cost),
            'downtime_cost': int(downtime_cost),
            'regulatory_fines': int(regulatory_fines),
            'total_potential_loss': int(total_potential_loss)
        }
    
    def _calculate_roi(self, total_loss: int, critical_count: int, high_count: int) -> Dict:
        """Calculate ROI for remediation investment"""
        
        # Estimate remediation cost (typically 5-10% of potential loss)
        remediation_cost = int(total_loss * 0.08)
        
        # Risk reduction percentage (more critical vulns = harder to fully mitigate)
        base_reduction = 85
        reduction_penalty = (critical_count * 2) + (high_count * 1)
        risk_reduction = max(50, min(95, base_reduction - reduction_penalty))
        
        # Cost-benefit ratio
        if remediation_cost > 0:
            cost_benefit_ratio = int(total_loss / remediation_cost)
        else:
            cost_benefit_ratio = 1
        
        return {
            'remediation_cost': remediation_cost,
            'risk_reduction': risk_reduction,
            'cost_benefit_ratio': max(1, cost_benefit_ratio)
        }
    
    def _assess_compliance(self, required_standards: List[str], critical: int, high: int) -> Dict:
        """Assess compliance status for required standards"""
        
        status = {}
        
        # Default all to compliant
        for standard in ['pci_dss', 'gdpr', 'hipaa', 'soc2']:
            status[standard] = True
        
        # Mark as non-compliant if high/critical vulns exist and standard is required
        has_high_risk = (critical > 0 or high > 0)
        
        for required in required_standards:
            standard_key = required.lower().replace(' ', '_').replace('-', '_')
            if standard_key in status and has_high_risk:
                threshold = self.compliance_thresholds.get(standard_key, {})
                if critical > threshold.get('max_critical', 0) or high > threshold.get('max_high', 0):
                    status[standard_key] = False
        
        return status

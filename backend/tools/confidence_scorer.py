"""
Confidence Scorer for vulnerability findings
"""

class ConfidenceScorer:
    """
    Calculate confidence scores for vulnerability findings
    """
    
    def __init__(self):
        self.scoring_factors = {
            'xss': {
                'reflected': 0.8,
                'stored': 0.9,
                'dom': 0.7,
                'blind': 0.6
            },
            'sqli': {
                'error_based': 0.9,
                'boolean_based': 0.8,
                'time_based': 0.7,
                'union_based': 0.85
            },
            'lfi': {
                'direct': 0.9,
                'traversal': 0.8,
                'wrapper': 0.7
            },
            'rce': {
                'direct': 0.95,
                'blind': 0.8
            }
        }
        
    def calculate_score(self, vuln_type, detection_method, additional_factors=None):
        """
        Calculate confidence score for a vulnerability
        
        Args:
            vuln_type: Type of vulnerability (xss, sqli, lfi, etc.)
            detection_method: Method used to detect (reflected, error_based, etc.)
            additional_factors: Dict of additional scoring factors
            
        Returns:
            Float between 0 and 1 representing confidence
        """
        base_score = 0.5
        
        # Get base score from vulnerability type and detection method
        if vuln_type in self.scoring_factors:
            if detection_method in self.scoring_factors[vuln_type]:
                base_score = self.scoring_factors[vuln_type][detection_method]
        
        # Apply additional factors
        if additional_factors:
            if additional_factors.get('multiple_confirmations'):
                base_score = min(1.0, base_score + 0.1)
            if additional_factors.get('payload_complexity_low'):
                base_score = min(1.0, base_score + 0.05)
            if additional_factors.get('consistent_behavior'):
                base_score = min(1.0, base_score + 0.05)
            if additional_factors.get('error_message_present'):
                base_score = min(1.0, base_score + 0.1)
                
        return round(base_score, 2)
    
    def get_confidence_label(self, score):
        """
        Get human-readable confidence label
        """
        if score >= 0.9:
            return "Very High"
        elif score >= 0.8:
            return "High"
        elif score >= 0.7:
            return "Medium-High"
        elif score >= 0.6:
            return "Medium"
        elif score >= 0.5:
            return "Medium-Low"
        else:
            return "Low"

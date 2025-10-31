"""
Parameter Fuzzer for vulnerability testing
"""

import itertools
import string

class ParameterFuzzer:
    """
    Fuzzer for generating test payloads for parameters
    """
    
    def __init__(self):
        self.basic_payloads = [
            "test",
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "1; ls -la",
            "${7*7}",
            "{{7*7}}",
            "%00",
            "null",
            "undefined"
        ]
        
    def generate_payloads(self, param_type="string"):
        """
        Generate fuzzing payloads based on parameter type
        """
        if param_type == "number":
            return ["0", "-1", "999999999", "1.5", "NaN", "Infinity"]
        elif param_type == "email":
            return ["test@test.com", "invalid-email", "@test.com", "test@", "test@test.com<script>"]
        else:
            return self.basic_payloads
            
    def mutate_payload(self, payload):
        """
        Create mutations of a payload
        """
        mutations = [payload]
        
        # Case variations
        mutations.append(payload.upper())
        mutations.append(payload.lower())
        
        # Encoding variations
        mutations.append(payload.replace(" ", "%20"))
        mutations.append(payload.replace("<", "&lt;"))
        
        return mutations

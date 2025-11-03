"""
Enhanced Form Discovery Engine for CyberSage v2.0
Professional form extraction, analysis, and vulnerability detection
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import json


class EnhancedFormDiscovery:
    """
    Advanced form discovery engine with detailed field extraction
    """
    
    def __init__(self, database, broadcaster):
        self.db = database
        self.broadcaster = broadcaster
        self.session = requests.Session()
        self.session.verify = False
        
    def discover_forms(self, scan_id, target, endpoints):
        """
        Discover all forms across the application
        Returns detailed form information with security analysis
        """
        print(f"\n[Form Discovery] Starting comprehensive form discovery...")
        print(f"[Form Discovery] Target: {target}")
        print(f"[Form Discovery] Endpoints to scan: {len(endpoints)}")
        
        discovered_forms = []
        forms_by_page = {}
        
        # Scan all endpoints for forms
        for endpoint in endpoints[:50]:  # Limit to 50 endpoints
            try:
                print(f"[Form Discovery] Scanning: {endpoint}")
                response = self.session.get(endpoint, timeout=10)
                
                if response.status_code != 200:
                    continue
                
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                
                if forms:
                    print(f"[Form Discovery] Found {len(forms)} forms on {endpoint}")
                    forms_by_page[endpoint] = len(forms)
                
                for form_index, form in enumerate(forms):
                    form_data = self._extract_form_details(form, endpoint, form_index)
                    
                    if form_data:
                        # Analyze form security
                        security_analysis = self._analyze_form_security(form_data, response.text)
                        form_data['security_analysis'] = security_analysis
                        
                        discovered_forms.append(form_data)
                        
                        # Log to database
                        self._store_form_data(scan_id, form_data)
                        
            except Exception as e:
                print(f"[Form Discovery] Error scanning {endpoint}: {str(e)}")
                continue
        
        print(f"\n[Form Discovery] Discovery complete!")
        print(f"[Form Discovery] Total forms found: {len(discovered_forms)}")
        print(f"[Form Discovery] Pages with forms: {len(forms_by_page)}")
        
        return discovered_forms
    
    def _extract_form_details(self, form, page_url, form_index):
        """
        Extract comprehensive details from a form element
        """
        # Basic form attributes
        form_data = {
            'page_url': page_url,
            'form_index': form_index,
            'action': form.get('action', ''),
            'method': form.get('method', 'GET').upper(),
            'id': form.get('id', ''),
            'name': form.get('name', ''),
            'class': ' '.join(form.get('class', [])),
            'enctype': form.get('enctype', ''),
            'autocomplete': form.get('autocomplete', ''),
            'fields': [],
            'buttons': [],
            'hidden_fields': [],
            'sensitive_fields': []
        }
        
        # Make action URL absolute
        if form_data['action']:
            form_data['action'] = urljoin(page_url, form_data['action'])
        else:
            form_data['action'] = page_url
        
        # Extract all input fields
        inputs = form.find_all(['input', 'textarea', 'select'])
        
        for input_elem in inputs:
            field_data = self._extract_field_details(input_elem)
            
            if field_data:
                form_data['fields'].append(field_data)
                
                # Categorize special fields
                if field_data['type'] == 'hidden':
                    form_data['hidden_fields'].append(field_data)
                
                if field_data['is_sensitive']:
                    form_data['sensitive_fields'].append(field_data)
        
        # Extract buttons
        buttons = form.find_all(['button', 'input'])
        for button in buttons:
            if button.name == 'input' and button.get('type') in ['submit', 'button']:
                form_data['buttons'].append({
                    'type': button.get('type'),
                    'value': button.get('value', ''),
                    'name': button.get('name', '')
                })
            elif button.name == 'button':
                form_data['buttons'].append({
                    'type': 'button',
                    'text': button.get_text(strip=True),
                    'name': button.get('name', '')
                })
        
        # Detect form purpose
        form_data['form_purpose'] = self._detect_form_purpose(form_data)
        
        return form_data
    
    def _extract_field_details(self, input_elem):
        """
        Extract detailed information about a form field
        """
        tag_name = input_elem.name
        
        field_data = {
            'tag': tag_name,
            'type': input_elem.get('type', 'text').lower() if tag_name == 'input' else tag_name,
            'name': input_elem.get('name', ''),
            'id': input_elem.get('id', ''),
            'value': input_elem.get('value', ''),
            'placeholder': input_elem.get('placeholder', ''),
            'required': input_elem.has_attr('required'),
            'readonly': input_elem.has_attr('readonly'),
            'disabled': input_elem.has_attr('disabled'),
            'pattern': input_elem.get('pattern', ''),
            'minlength': input_elem.get('minlength', ''),
            'maxlength': input_elem.get('maxlength', ''),
            'autocomplete': input_elem.get('autocomplete', ''),
            'class': ' '.join(input_elem.get('class', [])),
            'is_sensitive': False
        }
        
        # Detect sensitive fields
        sensitive_indicators = [
            'password', 'pass', 'pwd', 'secret',
            'credit', 'card', 'cvv', 'ssn',
            'account', 'pin', 'token'
        ]
        
        name_lower = field_data['name'].lower()
        id_lower = field_data['id'].lower()
        
        if any(indicator in name_lower or indicator in id_lower for indicator in sensitive_indicators):
            field_data['is_sensitive'] = True
        
        if field_data['type'] == 'password':
            field_data['is_sensitive'] = True
        
        # Extract select options
        if tag_name == 'select':
            options = input_elem.find_all('option')
            field_data['options'] = [
                {
                    'value': opt.get('value', ''),
                    'text': opt.get_text(strip=True),
                    'selected': opt.has_attr('selected')
                }
                for opt in options
            ]
        
        return field_data
    
    def _detect_form_purpose(self, form_data):
        """
        Detect the purpose of the form based on fields and context
        """
        field_names = [f['name'].lower() for f in form_data['fields']]
        field_types = [f['type'] for f in form_data['fields']]
        action_lower = form_data['action'].lower()
        
        # Login forms
        if 'password' in field_types and any(kw in ' '.join(field_names) for kw in ['user', 'email', 'login']):
            return 'login'
        
        # Registration forms
        if 'password' in field_types and any(kw in ' '.join(field_names) for kw in ['confirm', 'register', 'signup']):
            return 'registration'
        
        # Search forms
        if any(kw in ' '.join(field_names) for kw in ['search', 'query', 'q']):
            return 'search'
        
        # Contact forms
        if any(kw in ' '.join(field_names) for kw in ['message', 'subject', 'email', 'contact']):
            return 'contact'
        
        # Upload forms
        if 'file' in field_types or any(kw in action_lower for kw in ['upload', 'file']):
            return 'upload'
        
        # Payment forms
        if any(kw in ' '.join(field_names) for kw in ['card', 'payment', 'billing', 'cvv']):
            return 'payment'
        
        # Comment/feedback forms
        if 'textarea' in [f['tag'] for f in form_data['fields']]:
            return 'comment'
        
        return 'generic'
    
    def _analyze_form_security(self, form_data, page_html):
        """
        Analyze form for security issues and vulnerabilities
        """
        issues = []
        recommendations = []
        risk_score = 0
        
        # Check CSRF protection
        has_csrf = any(
            'csrf' in field['name'].lower() or 'token' in field['name'].lower()
            for field in form_data['fields']
        )
        
        if not has_csrf and form_data['method'] == 'POST':
            issues.append({
                'severity': 'high',
                'issue': 'Missing CSRF Protection',
                'description': 'Form does not include a CSRF token. This makes it vulnerable to Cross-Site Request Forgery attacks.',
                'field': 'N/A'
            })
            recommendations.append('Implement CSRF tokens for all state-changing POST requests')
            risk_score += 30
        
        # Check autocomplete on sensitive fields
        for field in form_data['sensitive_fields']:
            if field['autocomplete'] != 'off' and field['type'] == 'password':
                issues.append({
                    'severity': 'medium',
                    'issue': 'Autocomplete Enabled on Password Field',
                    'description': f'Password field "{field['name']}" allows browser autocomplete, which could expose credentials.',
                    'field': field['name']
                })
                recommendations.append(f'Set autocomplete="off" on password field: {field["name"]}')
                risk_score += 15
        
        # Check for action over HTTP (not HTTPS)
        if form_data['action'].startswith('http://'):
            issues.append({
                'severity': 'critical',
                'issue': 'Form Submits Over HTTP',
                'description': 'Form action URL uses HTTP instead of HTTPS. Sensitive data will be transmitted in cleartext.',
                'field': 'form action'
            })
            recommendations.append('Use HTTPS for all form submissions, especially those containing sensitive data')
            risk_score += 40
        
        # Check for default/example values in sensitive fields
        for field in form_data['sensitive_fields']:
            if field['value'] and not field['type'] == 'hidden':
                issues.append({
                    'severity': 'low',
                    'issue': 'Pre-filled Sensitive Field',
                    'description': f'Sensitive field "{field["name"]}" has a pre-filled value. This is a security risk.',
                    'field': field['name']
                })
                recommendations.append(f'Remove default value from sensitive field: {field["name"]}')
                risk_score += 10
        
        # Check for weak validation patterns
        for field in form_data['fields']:
            if field['type'] == 'email' and not field['pattern']:
                issues.append({
                    'severity': 'low',
                    'issue': 'Missing Email Validation Pattern',
                    'description': f'Email field "{field["name"]}" lacks client-side validation pattern.',
                    'field': field['name']
                })
                recommendations.append('Add regex pattern validation for email inputs')
                risk_score += 5
        
        # Check for file upload security
        if form_data['form_purpose'] == 'upload':
            if form_data['enctype'] != 'multipart/form-data':
                issues.append({
                    'severity': 'medium',
                    'issue': 'Incorrect Enctype for File Upload',
                    'description': 'File upload form should use enctype="multipart/form-data"',
                    'field': 'form enctype'
                })
                recommendations.append('Set enctype="multipart/form-data" on file upload forms')
                risk_score += 15
            
            # Check for file type restrictions
            file_fields = [f for f in form_data['fields'] if f['type'] == 'file']
            for file_field in file_fields:
                if not file_field.get('accept'):
                    issues.append({
                        'severity': 'medium',
                        'issue': 'No File Type Restrictions',
                        'description': f'File input "{file_field["name"]}" accepts any file type. This could allow malicious file uploads.',
                        'field': file_field['name']
                    })
                    recommendations.append(f'Add accept attribute to restrict file types on: {file_field["name"]}')
                    risk_score += 20
        
        # Calculate overall risk level
        if risk_score >= 70:
            risk_level = 'critical'
        elif risk_score >= 40:
            risk_level = 'high'
        elif risk_score >= 20:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'issues': issues,
            'recommendations': recommendations,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'total_issues': len(issues)
        }
    
    def _store_form_data(self, scan_id, form_data):
        """
        Store form data in database for later analysis
        """
        try:
            # Store in a forms table (you may need to create this table)
            # For now, we'll store as JSON in scan statistics or a custom table
            pass
        except Exception as e:
            print(f"[Form Discovery] Error storing form data: {str(e)}")


class AIFormAnalyzer:
    """
    AI-powered form analysis and remediation advisor
    Uses OpenRouter API to provide professional security analysis
    """
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.api_base = 'https://openrouter.ai/api/v1'
    
    def analyze_form_security(self, form_data):
        """
        Use AI to provide professional security analysis and remediation
        """
        if not self.api_key or self.api_key == 'YOUR_API_KEY':
            return self._fallback_analysis(form_data)
        
        # Prepare form context for AI
        form_context = self._prepare_form_context(form_data)
        
        prompt = f"""You are an elite web application security analyst specializing in form security and OWASP Top 10 vulnerabilities.

Analyze the following web form and provide a professional security assessment:

{form_context}

Provide your analysis in the following format:

1. SECURITY ASSESSMENT:
   - Overall risk level (Critical/High/Medium/Low)
   - Key security concerns (list 3-5 most important)

2. VULNERABILITIES IDENTIFIED:
   For each vulnerability:
   - Vulnerability name
   - Severity (Critical/High/Medium/Low)
   - Technical explanation (2-3 sentences)
   - Potential impact

3. REMEDIATION STEPS:
   Provide step-by-step technical remediation for each vulnerability:
   - Immediate fixes (what to do right now)
   - Code examples where applicable
   - Best practices to prevent recurrence

4. COMPLIANCE NOTES:
   - OWASP Top 10 mappings
   - PCI DSS considerations (if payment form)
   - GDPR considerations (if handling personal data)

Be specific, technical, and actionable. Focus on practical fixes a developer can implement immediately."""

        try:
            response = requests.post(
                f'{self.api_base}/chat/completions',
                headers={
                    'Authorization': f'Bearer {self.api_key}',
                    'Content-Type': 'application/json',
                    'HTTP-Referer': 'http://localhost:5000',
                    'X-Title': 'CyberSage v2.0'
                },
                json={
                    'model': 'anthropic/claude-3.5-sonnet',  # Using best available model
                    'messages': [
                        {
                            'role': 'user',
                            'content': prompt
                        }
                    ],
                    'max_tokens': 2000,
                    'temperature': 0.3  # Lower temperature for more consistent security advice
                },
                timeout=60
            )
            
            if response.status_code == 200:
                ai_response = response.json()
                analysis_text = ai_response['choices'][0]['message']['content']
                
                # Parse and structure the AI response
                return self._parse_ai_analysis(analysis_text, form_data)
            else:
                print(f"[AI Analyzer] API call failed: {response.status_code}")
                return self._fallback_analysis(form_data)
                
        except Exception as e:
            print(f"[AI Analyzer] Error: {str(e)}")
            return self._fallback_analysis(form_data)
    
    def _prepare_form_context(self, form_data):
        """
        Prepare form data as context for AI analysis
        """
        context = f"""Form Details:
- URL: {form_data['page_url']}
- Action: {form_data['action']}
- Method: {form_data['method']}
- Form Purpose: {form_data['form_purpose']}
- Enctype: {form_data.get('enctype', 'N/A')}

Fields ({len(form_data['fields'])} total):
"""
        
        for i, field in enumerate(form_data['fields'][:20], 1):  # Limit to 20 fields
            context += f"\n{i}. {field['name']} ({field['type']})"
            if field['required']:
                context += " [Required]"
            if field['is_sensitive']:
                context += " [SENSITIVE]"
            if field['pattern']:
                context += f" [Pattern: {field['pattern']}]"
        
        # Add security analysis results
        if 'security_analysis' in form_data:
            sec = form_data['security_analysis']
            context += f"\n\nAutomated Security Scan Results:"
            context += f"\n- Risk Score: {sec['risk_score']}/100"
            context += f"\n- Risk Level: {sec['risk_level']}"
            context += f"\n- Issues Found: {sec['total_issues']}"
            
            if sec['issues']:
                context += f"\n\nIdentified Issues:"
                for issue in sec['issues'][:5]:  # Top 5 issues
                    context += f"\n  - [{issue['severity'].upper()}] {issue['issue']}"
        
        return context
    
    def _parse_ai_analysis(self, ai_text, form_data):
        """
        Parse AI response and structure it
        """
        return {
            'ai_analysis': ai_text,
            'form_purpose': form_data['form_purpose'],
            'automated_issues': form_data.get('security_analysis', {}).get('issues', []),
            'ai_powered': True,
            'model_used': 'anthropic/claude-3.5-sonnet'
        }
    
    def _fallback_analysis(self, form_data):
        """
        Fallback analysis when AI is not available
        """
        sec = form_data.get('security_analysis', {})
        
        analysis = f"""Security Analysis for {form_data['form_purpose'].title()} Form

RISK ASSESSMENT:
Overall Risk: {sec.get('risk_level', 'unknown').upper()}
Risk Score: {sec.get('risk_score', 0)}/100
Total Issues: {sec.get('total_issues', 0)}

IDENTIFIED VULNERABILITIES:
"""
        
        for issue in sec.get('issues', []):
            analysis += f"""
[{issue['severity'].upper()}] {issue['issue']}
Field: {issue['field']}
Description: {issue['description']}
"""
        
        analysis += f"""

REMEDIATION RECOMMENDATIONS:
"""
        
        for i, rec in enumerate(sec.get('recommendations', []), 1):
            analysis += f"{i}. {rec}\n"
        
        analysis += """

GENERAL SECURITY BEST PRACTICES:
1. Always use HTTPS for form submissions
2. Implement CSRF tokens for all POST requests
3. Validate all input server-side (never trust client-side validation)
4. Use parameterized queries to prevent SQL injection
5. Sanitize and encode all output to prevent XSS
6. Implement rate limiting on form submissions
7. Use strong password policies for authentication forms
8. Log all form submissions for security monitoring

For AI-powered detailed analysis, configure your OpenRouter API key in settings.
"""
        
        return {
            'ai_analysis': analysis,
            'form_purpose': form_data['form_purpose'],
            'automated_issues': sec.get('issues', []),
            'ai_powered': False,
            'model_used': 'rule-based'
        }
    
    def generate_code_fixes(self, form_data, language='python'):
        """
        Generate code examples for fixing identified issues
        """
        if not self.api_key or self.api_key == 'YOUR_API_KEY':
            return self._generate_basic_fixes(form_data, language)
        
        issues_text = '\n'.join([
            f"- {issue['issue']}: {issue['description']}"
            for issue in form_data.get('security_analysis', {}).get('issues', [])
        ])
        
        prompt = f"""As a senior application security engineer, provide code examples to fix these form security issues:

Form: {form_data['form_purpose']} form
Technology: {language}
Issues:
{issues_text}

Provide:
1. Server-side validation code
2. CSRF protection implementation
3. Input sanitization examples
4. Secure configuration snippets

Use {language} with common frameworks (Flask/Django for Python, Express for Node.js, etc.)
Code should be production-ready and follow security best practices."""

        try:
            response = requests.post(
                f'{self.api_base}/chat/completions',
                headers={
                    'Authorization': f'Bearer {self.api_key}',
                    'Content-Type': 'application/json'
                },
                json={
                    'model': 'anthropic/claude-3.5-sonnet',
                    'messages': [{'role': 'user', 'content': prompt}],
                    'max_tokens': 1500,
                    'temperature': 0.2
                },
                timeout=60
            )
            
            if response.status_code == 200:
                return response.json()['choices'][0]['message']['content']
            
        except Exception as e:
            print(f"[AI Code Generator] Error: {str(e)}")
        
        return self._generate_basic_fixes(form_data, language)
    
    def _generate_basic_fixes(self, form_data, language):
        """
        Generate basic code fixes without AI
        """
        if language == 'python':
            return """# Python/Flask Example - Secure Form Handling

from flask import Flask, request, render_template, session
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, Length
import bleach

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
csrf = CSRFProtect(app)

class SecureLoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=50)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8)
    ])

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = SecureLoginForm()
    
    if form.validate_on_submit():
        # Sanitize input
        username = bleach.clean(form.username.data)
        
        # Your authentication logic here
        # Use password hashing (bcrypt/argon2)
        
        return "Login successful"
    
    return render_template('login.html', form=form)

# In template, include CSRF token:
# {{ form.csrf_token }}
"""
        
        return "Code examples require AI API key configuration."
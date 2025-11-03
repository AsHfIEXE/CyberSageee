# core/pdf_generator.py
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, KeepTogether
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.pdfgen import canvas
from datetime import datetime
import os

class PDFReportGenerator:
    """
    Generate professional PDF reports for scan results
    """
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Check if style exists before adding to prevent KeyError
        
        # Title style
        if 'CustomTitle' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='CustomTitle',
                parent=self.styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                alignment=TA_CENTER,
                textColor=colors.HexColor('#8B5CF6')
            ))
        
        # Subtitle style
        if 'CustomSubtitle' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='CustomSubtitle',
                parent=self.styles['Heading2'],
                fontSize=16,
                spaceAfter=12,
                textColor=colors.HexColor('#6B7280')
            ))
        
        # Vulnerability title style
        if 'VulnTitle' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='VulnTitle',
                parent=self.styles['Heading3'],
                fontSize=14,
                spaceAfter=6,
                textColor=colors.HexColor('#EF4444')
            ))
        
        # Code style
        if 'Code' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='Code',
                parent=self.styles['Normal'],
                fontSize=9,
                fontName='Courier',
                backColor=colors.HexColor('#1F2937'),
                textColor=colors.HexColor('#10B981'),
                leftIndent=10,
                rightIndent=10,
                spaceBefore=6,
                spaceAfter=6
            ))
        
        # Remediation style
        if 'Remediation' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='Remediation',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#059669'),
                leftIndent=15,
                spaceBefore=6,
                spaceAfter=6
            ))
        
        # AI Advice style
        if 'AIAdvice' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='AIAdvice',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#8B5CF6'),
                leftIndent=15,
                spaceBefore=6,
                spaceAfter=6,
                fontName='Helvetica-Oblique'
            ))
        
        # Warning style
        if 'Warning' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='Warning',
                parent=self.styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#F59E0B'),
                leftIndent=15,
                backColor=colors.HexColor('#FEF3C7'),
                spaceBefore=6,
                spaceAfter=6
            ))
    
    def generate_scan_report(self, scan_data, vulnerabilities, chains, statistics, output_path):
        """
        Generate comprehensive PDF report for scan results
        """
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        story = []
        
        # Title page
        story.extend(self._create_title_page(scan_data))
        story.append(PageBreak())
        
        # Executive summary
        story.extend(self._create_executive_summary(scan_data, vulnerabilities, statistics))
        story.append(PageBreak())
        
        # Vulnerability summary
        story.extend(self._create_vulnerability_summary(vulnerabilities))
        story.append(PageBreak())
        
        # Detailed vulnerabilities
        story.extend(self._create_detailed_vulnerabilities(vulnerabilities))
        
        # Attack chains (if any)
        if chains:
            story.append(PageBreak())
            story.extend(self._create_attack_chains(chains))
        
        # Statistics and metrics
        story.append(PageBreak())
        story.extend(self._create_statistics_section(statistics))
        
        # Build PDF
        doc.build(story)
        return output_path
    
    def _create_title_page(self, scan_data):
        """Create title page"""
        elements = []
        
        # Main title
        elements.append(Paragraph("CyberSage v2.0", self.styles['CustomTitle']))
        elements.append(Paragraph("Security Assessment Report", self.styles['CustomTitle']))
        elements.append(Spacer(1, 0.5*inch))
        
        # Scan information
        scan_info = [
            ['Target:', scan_data.get('target', 'N/A')],
            ['Scan Mode:', scan_data.get('scan_mode', 'N/A').upper()],
            ['Status:', scan_data.get('status', 'N/A').upper()],
            ['Started:', str(scan_data.get('started_at', 'N/A'))],
        ]
        
        if scan_data.get('duration_seconds'):
            scan_info.append(['Duration:', f"{scan_data.get('duration_seconds', 0):.1f} seconds"])
        
        if scan_data.get('completed_at'):
            scan_info.append(['Completed:', str(scan_data.get('completed_at', 'N/A'))])
        
        scan_table = Table(scan_info, colWidths=[1.5*inch, 4*inch])
        scan_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(scan_table)
        elements.append(Spacer(1, 0.5*inch))
        
        # Generated timestamp
        elements.append(Paragraph(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                                 self.styles['Normal']))
        
        return elements
    
    def _create_executive_summary(self, scan_data, vulnerabilities, statistics):
        """Create executive summary section"""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['CustomSubtitle']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Vulnerability counts
        vuln_counts = {
            'critical': len([v for v in vulnerabilities if v.get('severity') == 'critical']),
            'high': len([v for v in vulnerabilities if v.get('severity') == 'high']),
            'medium': len([v for v in vulnerabilities if v.get('severity') == 'medium']),
            'low': len([v for v in vulnerabilities if v.get('severity') == 'low'])
        }
        
        total_vulns = sum(vuln_counts.values())
        
        # Summary text
        summary_text = f"""
        This security assessment was conducted on {scan_data.get('target', 'the target')} 
        using CyberSage v2.0's {scan_data.get('scan_mode', 'elite')} scanning mode. 
        The scan identified {total_vulns} total vulnerabilities across all severity levels.
        """
        
        if vuln_counts['critical'] > 0:
            summary_text += f" {vuln_counts['critical']} critical vulnerabilities require immediate attention."
        
        if vuln_counts['high'] > 0:
            summary_text += f" {vuln_counts['high']} high-severity issues should be prioritized for remediation."
        
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Vulnerability summary table
        vuln_summary_data = [
            ['Severity', 'Count', 'Percentage'],
            ['Critical', str(vuln_counts['critical']), f"{(vuln_counts['critical']/total_vulns*100):.1f}%" if total_vulns > 0 else "0%"],
            ['High', str(vuln_counts['high']), f"{(vuln_counts['high']/total_vulns*100):.1f}%" if total_vulns > 0 else "0%"],
            ['Medium', str(vuln_counts['medium']), f"{(vuln_counts['medium']/total_vulns*100):.1f}%" if total_vulns > 0 else "0%"],
            ['Low', str(vuln_counts['low']), f"{(vuln_counts['low']/total_vulns*100):.1f}%" if total_vulns > 0 else "0%"],
        ]
        
        vuln_table = Table(vuln_summary_data, colWidths=[1.5*inch, 1*inch, 1*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#374151')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(vuln_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Add pie chart visualization
        if total_vulns > 0:
            chart = self._create_vulnerability_pie_chart(vuln_counts)
            elements.append(chart)
        
        return elements
    
    def _create_vulnerability_pie_chart(self, vuln_counts):
        """Create a pie chart showing vulnerability distribution"""
        drawing = Drawing(400, 200)
        pie = Pie()
        pie.x = 150
        pie.y = 50
        pie.width = 150
        pie.height = 150
        
        # Data
        pie.data = [vuln_counts['critical'], vuln_counts['high'], vuln_counts['medium'], vuln_counts['low']]
        pie.labels = ['Critical', 'High', 'Medium', 'Low']
        
        # Colors matching severity
        pie.slices.strokeWidth = 0.5
        pie.slices[0].fillColor = colors.HexColor('#DC2626')  # Critical - Red
        pie.slices[1].fillColor = colors.HexColor('#F59E0B')  # High - Orange
        pie.slices[2].fillColor = colors.HexColor('#F59E0B')  # Medium - Yellow
        pie.slices[3].fillColor = colors.HexColor('#10B981')  # Low - Green
        
        drawing.add(pie)
        return drawing
    
    def _create_vulnerability_summary(self, vulnerabilities):
        """Create vulnerability summary section"""
        elements = []
        
        elements.append(Paragraph("Vulnerability Summary", self.styles['CustomSubtitle']))
        elements.append(Spacer(1, 0.2*inch))
        
        if not vulnerabilities:
            elements.append(Paragraph("No vulnerabilities were identified during this scan.", self.styles['Normal']))
            return elements
        
        # Group vulnerabilities by type
        vuln_by_type = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
        
        # Create summary table
        summary_data = [['Vulnerability Type', 'Count', 'Critical', 'High', 'Medium', 'Low']]
        
        for vuln_type, vulns in vuln_by_type.items():
            counts = {
                'critical': len([v for v in vulns if v.get('severity') == 'critical']),
                'high': len([v for v in vulns if v.get('severity') == 'high']),
                'medium': len([v for v in vulns if v.get('severity') == 'medium']),
                'low': len([v for v in vulns if v.get('severity') == 'low'])
            }
            
            summary_data.append([
                vuln_type,
                str(len(vulns)),
                str(counts['critical']),
                str(counts['high']),
                str(counts['medium']),
                str(counts['low'])
            ])
        
        summary_table = Table(summary_data, colWidths=[2*inch, 0.8*inch, 0.8*inch, 0.8*inch, 0.8*inch, 0.8*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#374151')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(summary_table)
        
        return elements
    
    def _create_detailed_vulnerabilities(self, vulnerabilities):
        """Create detailed vulnerability section with enhanced visuals and AI advice"""
        elements = []
        
        elements.append(Paragraph("Detailed Vulnerabilities", self.styles['CustomSubtitle']))
        elements.append(Spacer(1, 0.2*inch))
        
        for i, vuln in enumerate(vulnerabilities, 1):
            # Get vulnerability name - try multiple fields
            vuln_name = (vuln.get('title') or vuln.get('type') or 
                        vuln.get('name') or 'Security Issue')
            
            # Create colored severity badge
            severity = vuln.get('severity', 'medium').lower()
            severity_colors = {
                'critical': ('#DC2626', '🔴'),
                'high': ('#F59E0B', '🟠'),
                'medium': ('#F59E0B', '🟡'),
                'low': ('#10B981', '🟢'),
                'info': ('#3B82F6', '🔵')
            }
            severity_color, severity_icon = severity_colors.get(severity, ('#6B7280', '⚪'))
            
            # Vulnerability header with colored background
            header_table = Table([[f"{severity_icon} {i}. {vuln_name}"]], colWidths=[5.5*inch])
            header_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor(severity_color)),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 12),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ]))
            elements.append(header_table)
            elements.append(Spacer(1, 0.1*inch))
            
            # Vulnerability details in a highlighted table
            details_data = [
                ['Severity:', f"{severity.upper()} (CVSS: {vuln.get('cvss_score', 'N/A')})"],
                ['Confidence:', f"{vuln.get('confidence', vuln.get('confidence_score', 0))}%"],
                ['Affected URL:', vuln.get('url', vuln.get('affected_url', 'N/A'))],
                ['Detection Tool:', vuln.get('detection_tool', vuln.get('tool', 'CyberSage'))],
            ]
            
            if vuln.get('affected_parameter'):
                details_data.append(['Vulnerable Parameter:', vuln.get('affected_parameter')])
            
            if vuln.get('cwe_id'):
                details_data.append(['CWE ID:', vuln.get('cwe_id')])
            
            details_table = Table(details_data, colWidths=[1.5*inch, 4*inch])
            details_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F3F4F6')),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#D1D5DB'))
            ]))
            elements.append(details_table)
            elements.append(Spacer(1, 0.15*inch))
            
            # Description
            if vuln.get('description'):
                elements.append(Paragraph("📋 <b>Description:</b>", self.styles['Heading4']))
                elements.append(Paragraph(vuln.get('description'), self.styles['Normal']))
                elements.append(Spacer(1, 0.1*inch))
            
            # Proof of concept with syntax highlighting effect
            if vuln.get('proof_of_concept') or vuln.get('poc') or vuln.get('payload'):
                elements.append(Paragraph("🔍 <b>Proof of Concept:</b>", self.styles['Heading4']))
                poc_text = (vuln.get('proof_of_concept') or vuln.get('poc') or 
                           vuln.get('payload', 'See vulnerability details'))
                
                # Truncate if too long
                if isinstance(poc_text, str) and len(poc_text) > 500:
                    poc_text = poc_text[:500] + "..."
                
                poc_paragraph = Paragraph(f"<font name='Courier' color='#10B981'>{self._escape_html(str(poc_text))}</font>", 
                                         self.styles['Code'])
                elements.append(poc_paragraph)
                elements.append(Spacer(1, 0.1*inch))
            
            # AI-Powered Remediation Advice
            elements.append(Paragraph("🛠️ <b>Remediation Steps:</b>", self.styles['Heading4']))
            remediation_advice = self._get_ai_remediation_advice(vuln)
            elements.append(Paragraph(remediation_advice, self.styles['Remediation']))
            elements.append(Spacer(1, 0.1*inch))
            
            # Code Example for Fix
            code_example = self._get_code_remediation_example(vuln)
            if code_example:
                elements.append(Paragraph("💻 <b>Secure Code Example:</b>", self.styles['Heading4']))
                code_paragraph = Paragraph(f"<font name='Courier' color='#10B981'>{self._escape_html(code_example)}</font>",
                                          self.styles['Code'])
                elements.append(code_paragraph)
                elements.append(Spacer(1, 0.1*inch))
            
            # AI Security Best Practices
            ai_advice = self._get_ai_security_advice(vuln)
            if ai_advice:
                elements.append(Paragraph("🤖 <b>AI Security Insight:</b>", self.styles['Heading4']))
                elements.append(Paragraph(ai_advice, self.styles['AIAdvice']))
                elements.append(Spacer(1, 0.1*inch))
            
            # References
            references = self._get_vulnerability_references(vuln)
            if references:
                elements.append(Paragraph("📚 <b>References:</b>", self.styles['Heading4']))
                for ref in references:
                    elements.append(Paragraph(f"• {ref}", self.styles['Normal']))
            
            elements.append(Spacer(1, 0.3*inch))
            
            # Add separator line
            separator = Table([['']], colWidths=[5.5*inch])
            separator.setStyle(TableStyle([
                ('LINEABOVE', (0, 0), (-1, -1), 2, colors.HexColor('#E5E7EB'))
            ]))
            elements.append(separator)
            elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _create_attack_chains(self, chains):
        """Create attack chains section"""
        elements = []
        
        elements.append(Paragraph("Attack Chains", self.styles['CustomSubtitle']))
        elements.append(Spacer(1, 0.2*inch))
        
        for i, chain in enumerate(chains, 1):
            elements.append(Paragraph(f"Chain {i}: {chain.get('name', 'Unknown Chain')}", self.styles['Heading3']))
            elements.append(Paragraph(f"Impact: {chain.get('impact', 'Unknown')}", self.styles['Normal']))
            elements.append(Paragraph(f"Confidence: {chain.get('confidence', 0)}%", self.styles['Normal']))
            
            if chain.get('steps'):
                elements.append(Paragraph("Exploitation Steps:", self.styles['Heading4']))
                steps = chain.get('steps', [])
                for j, step in enumerate(steps, 1):
                    if isinstance(step, (list, tuple)) and len(step) >= 2:
                        elements.append(Paragraph(f"{j}. {step[1]}", self.styles['Normal']))
                    else:
                        elements.append(Paragraph(f"{j}. {step}", self.styles['Normal']))
            
            elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _create_statistics_section(self, statistics):
        """Create statistics section"""
        elements = []
        
        elements.append(Paragraph("Scan Statistics", self.styles['CustomSubtitle']))
        elements.append(Spacer(1, 0.2*inch))
        
        if not statistics:
            elements.append(Paragraph("No statistics available for this scan.", self.styles['Normal']))
            return elements
        
        # Statistics table
        stats_data = []
        for key, value in statistics.items():
            if value is not None:
                stats_data.append([key.replace('_', ' ').title(), str(value)])
        
        if stats_data:
            stats_table = Table(stats_data, colWidths=[3*inch, 2*inch])
            stats_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(stats_table)
        
        return elements
    
    # ============================================================================
    # AI-POWERED REMEDIATION AND CODE EXAMPLES
    # ============================================================================
    
    def _escape_html(self, text):
        """Escape HTML special characters for PDF"""
        if not isinstance(text, str):
            text = str(text)
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        return text
    
    def _get_ai_remediation_advice(self, vuln):
        """Get AI-powered remediation advice based on vulnerability type"""
        vuln_type = (vuln.get('type') or vuln.get('title', '')).lower()
        
        remediation_advice = {
            'xss': """
                1. Implement Content Security Policy (CSP) headers<br/>
                2. Use context-aware output encoding (HTML, JavaScript, URL, CSS)<br/>
                3. Validate and sanitize ALL user inputs on server-side<br/>
                4. Use modern frameworks with built-in XSS protection (React, Angular)<br/>
                5. Never use innerHTML or eval() with user data<br/>
                6. Implement HTTPOnly and Secure flags on sensitive cookies
            """,
            'sql': """
                1. Use parameterized queries (prepared statements) EXCLUSIVELY<br/>
                2. Never concatenate user input into SQL queries<br/>
                3. Apply principle of least privilege to database accounts<br/>
                4. Use ORM frameworks with built-in SQL injection prevention<br/>
                5. Validate and whitelist all user inputs<br/>
                6. Implement Web Application Firewall (WAF) rules<br/>
                7. Regular security audits and penetration testing
            """,
            'command': """
                1. NEVER pass user input directly to system commands<br/>
                2. Use allowlists for valid input values<br/>
                3. Avoid shell execution functions (exec, system, popen)<br/>
                4. Use language-specific APIs instead of shell commands<br/>
                5. Implement strict input validation with regex patterns<br/>
                6. Run applications with minimal OS privileges<br/>
                7. Use sandboxing and containerization
            """,
            'file inclusion': """
                1. Never use user input in file paths or includes<br/>
                2. Use allowlists for file access<br/>
                3. Implement strict file path validation<br/>
                4. Disable remote file inclusion in PHP (allow_url_include=Off)<br/>
                5. Use absolute paths and validate against base directory<br/>
                6. Set proper file permissions (read-only where possible)<br/>
                7. Implement Web Application Firewall rules
            """,
            'directory traversal': """
                1. Never use user input directly in file system operations<br/>
                2. Validate and sanitize file paths rigorously<br/>
                3. Use allowlists for accessible files/directories<br/>
                4. Implement chroot jails or similar restrictions<br/>
                5. Normalize paths and check for traversal sequences (../, ..\\)<br/>
                6. Use secure frameworks that handle path validation<br/>
                7. Apply principle of least privilege to file system access
            """,
            'security headers': """
                1. Implement Content-Security-Policy (CSP)<br/>
                2. Add X-Content-Type-Options: nosniff<br/>
                3. Set X-Frame-Options: DENY or SAMEORIGIN<br/>
                4. Enable Strict-Transport-Security (HSTS)<br/>
                5. Add X-XSS-Protection: 1; mode=block<br/>
                6. Set Referrer-Policy appropriately<br/>
                7. Use Permissions-Policy to restrict features
            """,
            'sensitive file': """
                1. Remove or restrict access to sensitive files immediately<br/>
                2. Configure web server to deny access to hidden files (.git, .env)<br/>
                3. Move configuration files outside web root<br/>
                4. Implement proper .htaccess or web.config rules<br/>
                5. Use environment variables for sensitive configuration<br/>
                6. Regular security scans to detect exposed files<br/>
                7. Implement least privilege file permissions (chmod 600)
            """
        }
        
        # Match vulnerability type to advice
        for key, advice in remediation_advice.items():
            if key in vuln_type:
                return advice
        
        # Default generic advice
        return vuln.get('remediation', """
            1. Review and validate the vulnerability finding<br/>
            2. Follow OWASP best practices for your technology stack<br/>
            3. Implement input validation and output encoding<br/>
            4. Apply principle of least privilege<br/>
            5. Keep all software and dependencies up to date<br/>
            6. Conduct regular security testing
        """)
    
    def _get_code_remediation_example(self, vuln):
        """Get secure code examples based on vulnerability type"""
        vuln_type = (vuln.get('type') or vuln.get('title', '')).lower()
        
        code_examples = {
            'xss': """# Python (Flask) - Secure Output Encoding
from flask import escape

# VULNERABLE:
return f"&lt;h1&gt;Hello {username}&lt;/h1&gt;"

# SECURE:
return f"&lt;h1&gt;Hello {escape(username)}&lt;/h1&gt;"

# Or use Jinja2 templates (auto-escaping):
return render_template('page.html', username=username)
""",
            'sql': """# Python - Secure Parameterized Query
# VULNERABLE:
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# SECURE:
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))

# Or use ORM:
user = User.query.filter_by(id=user_id).first()
""",
            'command': """# Python - Secure Alternative to Shell Execution
# VULNERABLE:
os.system(f"ping {user_input}")

# SECURE:
import subprocess
import shlex

# Use list format (no shell=True)
subprocess.run(['ping', '-c', '4', user_input], 
              capture_output=True, timeout=5)

# Or validate against allowlist:
if user_input in ALLOWED_HOSTS:
    subprocess.run(['ping', '-c', '4', user_input])
""",
            'file inclusion': """# PHP - Secure File Inclusion
// VULNERABLE:
include($_GET['page'] . '.php');

# SECURE:
$allowed_pages = ['home', 'about', 'contact'];
$page = $_GET['page'] ?? 'home';

if (in_array($page, $allowed_pages, true)) {
    include($page . '.php');
} else {
    die('Invalid page');
}
""",
            'security headers': """# Python (Flask) - Security Headers
from flask import Flask, make_response

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
"""
        }
        
        for key, example in code_examples.items():
            if key in vuln_type:
                return example
        
        return None
    
    def _get_ai_security_advice(self, vuln):
        """Get AI-powered security insights"""
        vuln_type = (vuln.get('type') or vuln.get('title', '')).lower()
        severity = vuln.get('severity', 'medium').lower()
        
        insights = {
            'xss': "⚡ XSS vulnerabilities are among OWASP Top 10. They can lead to session hijacking, credential theft, and malware distribution. Modern browsers have some built-in protection, but server-side validation is essential.",
            'sql': "⚡ SQL Injection remains one of the most dangerous vulnerabilities. It can result in complete database compromise, data theft, and unauthorized access. Always use parameterized queries - never trust user input.",
            'command': "⚡ Command Injection can lead to complete server compromise. Attackers can execute arbitrary commands, install backdoors, and pivot to internal networks. Avoid shell execution entirely when possible.",
            'file inclusion': "⚡ File Inclusion vulnerabilities can expose sensitive files, execute malicious code, and compromise the entire server. They're especially dangerous when combined with file upload features.",
            'directory traversal': "⚡ Path Traversal allows attackers to access files outside the intended directory. This can expose credentials, source code, and sensitive data. Always validate and normalize file paths.",
            'security headers': "⚡ Missing security headers leave applications vulnerable to various attacks. Modern browsers rely on these headers for protection. Implementation is straightforward and provides significant security benefits."
        }
        
        for key, insight in insights.items():
            if key in vuln_type:
                if severity in ['critical', 'high']:
                    insight += " <b>CRITICAL: Address this vulnerability immediately.</b>"
                return insight
        
        return None
    
    def _get_vulnerability_references(self, vuln):
        """Get relevant security references"""
        references = []
        
        # CWE Reference
        if vuln.get('cwe_id'):
            cwe_id = vuln.get('cwe_id').replace('CWE-', '')
            references.append(f"CWE-{cwe_id}: https://cwe.mitre.org/data/definitions/{cwe_id}.html")
        
        # OWASP References
        vuln_type = (vuln.get('type') or vuln.get('title', '')).lower()
        owasp_mapping = {
            'xss': 'A03:2021 – Injection',
            'sql': 'A03:2021 – Injection',
            'command': 'A03:2021 – Injection',
            'file inclusion': 'A01:2021 – Broken Access Control',
            'directory traversal': 'A01:2021 – Broken Access Control',
            'security headers': 'A05:2021 – Security Misconfiguration'
        }
        
        for key, owasp_cat in owasp_mapping.items():
            if key in vuln_type:
                references.append(f"OWASP Top 10: {owasp_cat}")
                break
        
        # Generic references
        references.append("OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/")
        
        if vuln.get('cvss_score'):
            references.append(f"CVSS Calculator: https://www.first.org/cvss/calculator/3.1")
        
        return references
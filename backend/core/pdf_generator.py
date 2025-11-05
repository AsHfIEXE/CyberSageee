# core/pdf_generator.py
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing, Rect
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
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
                textColor=colors.HexColor('#F3F4F6'),
                leftIndent=10,
                rightIndent=10,
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
        
        return elements
    
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
        """Create detailed vulnerability section"""
        elements = []
        
        elements.append(Paragraph("Detailed Vulnerabilities", self.styles['CustomSubtitle']))
        elements.append(Spacer(1, 0.2*inch))
        
        for i, vuln in enumerate(vulnerabilities, 1):
            # Vulnerability header
            elements.append(Paragraph(f"{i}. {vuln.get('type', 'Unknown Vulnerability')}", self.styles['VulnTitle']))
            
            # Vulnerability details
            details_data = [
                ['Severity:', vuln.get('severity', 'Unknown').upper()],
                ['Confidence:', f"{vuln.get('confidence', 0)}%"],
                ['URL:', vuln.get('url', vuln.get('affected_url', 'N/A'))],
                ['Tool:', vuln.get('tool', vuln.get('detection_tool', 'Unknown'))],
            ]
            
            if vuln.get('affected_parameter'):
                details_data.append(['Parameter:', vuln.get('affected_parameter')])
            
            details_table = Table(details_data, colWidths=[1.2*inch, 4.3*inch])
            details_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            
            elements.append(details_table)
            
            # Description
            if vuln.get('description'):
                elements.append(Paragraph("Description:", self.styles['Heading4']))
                elements.append(Paragraph(vuln.get('description'), self.styles['Normal']))
            
            # Proof of concept
            if vuln.get('proof_of_concept') or vuln.get('poc'):
                elements.append(Paragraph("Proof of Concept:", self.styles['Heading4']))
                poc_text = vuln.get('proof_of_concept') or vuln.get('poc')
                elements.append(Paragraph(str(poc_text)[:500], self.styles['Code']))
            
            # Remediation
            if vuln.get('remediation'):
                elements.append(Paragraph("Remediation:", self.styles['Heading4']))
                elements.append(Paragraph(vuln.get('remediation'), self.styles['Normal']))
            
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
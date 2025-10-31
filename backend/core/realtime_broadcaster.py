import time

class RealTimeBroadcaster:
    """
    Broadcasts real-time scan events to connected WebSocket clients
    """
    
    def __init__(self, socketio):
        self.socketio = socketio
    
    def broadcast_event(self, event_type, data):
        """Generic event broadcaster"""
        data['timestamp'] = time.time()
        self.socketio.emit(event_type, data, namespace='/scan')
    
    def broadcast_scan_progress(self, scan_id, progress, phase):
        """Broadcast scan progress update"""
        self.socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'progress': progress,
            'phase': phase,
            'timestamp': time.time()
        }, namespace='/scan')
    
    def broadcast_tool_started(self, scan_id, tool_name, target):
        """Broadcast when a tool starts"""
        self.socketio.emit('tool_started', {
            'scan_id': scan_id,
            'tool': tool_name,
            'target': target,
            'status': 'running',
            'timestamp': time.time()
        }, namespace='/scan')
    
    def broadcast_tool_completed(self, scan_id, tool_name, status, findings_count=0):
        """Broadcast when a tool completes"""
        self.socketio.emit('tool_completed', {
            'scan_id': scan_id,
            'tool': tool_name,
            'status': status,
            'findings_count': findings_count,
            'timestamp': time.time()
        }, namespace='/scan')
    
    def broadcast_vulnerability_found(self, scan_id, vuln_data):
        """Broadcast new vulnerability discovery with complete data"""
        self.socketio.emit('vulnerability_found', {
            'id': vuln_data.get('id'),  # CRITICAL: Real database ID for fetching details
            'scan_id': scan_id,
            'type': vuln_data.get('type'),
            'severity': vuln_data.get('severity'),
            'title': vuln_data.get('title'),
            'description': vuln_data.get('description'),
            'confidence': vuln_data.get('confidence_score', vuln_data.get('confidence', 50)),
            'url': vuln_data.get('url'),
            'affected_parameter': vuln_data.get('affected_parameter'),
            'payload': vuln_data.get('payload'),
            'cwe_id': vuln_data.get('cwe_id'),
            'cvss_score': vuln_data.get('cvss_score'),
            'detection_tool': vuln_data.get('detection_tool', vuln_data.get('tool')),
            'preview': vuln_data.get('description', '')[:150],
            'timestamp': time.time()
        }, namespace='/scan')
    
    def broadcast_chain_detected(self, scan_id, chain_data):
        """Broadcast attack chain detection - HIGH PRIORITY"""
        self.socketio.emit('chain_detected', {
            'scan_id': scan_id,
            'name': chain_data.get('name'),
            'severity': 'critical',
            'impact': chain_data.get('impact'),
            'steps': chain_data.get('steps', []),
            'confidence': chain_data.get('confidence', 50),
            'animation': 'pulse',  # Trigger special UI effect
            'timestamp': time.time()
        }, namespace='/scan')
    
    def broadcast_ai_insight(self, scan_id, insight_data):
        """Broadcast AI-generated insights"""
        self.socketio.emit('ai_insight', {
            'scan_id': scan_id,
            'insight_type': insight_data.get('type'),
            'message': insight_data.get('message'),
            'severity': insight_data.get('severity'),
            'confidence': insight_data.get('confidence', 50),
            'timestamp': time.time()
        }, namespace='/scan')
    
    def broadcast_phase_complete(self, scan_id, phase_name, summary):
        """Broadcast completion of a scan phase"""
        self.socketio.emit('phase_completed', {
            'scan_id': scan_id,
            'phase': phase_name,
            'summary': summary,
            'timestamp': time.time()
        }, namespace='/scan')
    
    def broadcast_log(self, scan_id, message, level='info'):
        """Broadcast real-time log messages"""
        self.socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': message,
            'level': level,
            'timestamp': time.time()
        }, namespace='/scan')
    
    def broadcast_endpoint_discovered(self, scan_id, endpoint_data):
        """Broadcast when a new endpoint is discovered"""
        self.socketio.emit('endpoint_discovered', {
            'scan_id': scan_id,
            'url': endpoint_data.get('url'),
            'method': endpoint_data.get('method'),
            'params': endpoint_data.get('params'),
            'timestamp': time.time()
        }, namespace='/scan')
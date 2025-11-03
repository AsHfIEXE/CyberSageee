from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import os
import sys
import json
import time
from datetime import datetime
from typing import Dict, List, Any

# Import AI modules
sys.path.append(os.path.dirname(__file__))
from ai_smart_prioritizer import AISmartPrioritizer
from exploit_verifier import ExploitVerifier
from business_impact_calculator import BusinessImpactCalculator
from security_testing_engine import SecurityTestingEngine

app = Flask(__name__, static_folder='../frontend/dist', static_url_path='')
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize AI modules
OPENROUTER_API_KEY = os.environ.get('OPENROUTER_API_KEY', '')

# Simple in-memory database (replace with real DB in production)
scans_db = {}
ai_analysis_db = {}
verification_db = {}

class Broadcaster:
    """Socket.IO broadcaster for real-time updates"""
    def __init__(self, socketio_instance):
        self.socketio = socketio_instance
    
    def broadcast_log(self, scan_id, message):
        self.socketio.emit('scan_log', {
            'scan_id': scan_id,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
    
    def broadcast_event(self, event_name, data):
        self.socketio.emit(event_name, data)

broadcaster = Broadcaster(socketio)

# Initialize AI components with fallback
try:
    ai_prioritizer = AISmartPrioritizer(OPENROUTER_API_KEY) if OPENROUTER_API_KEY else None
    exploit_verifier = ExploitVerifier(database=None, broadcaster=broadcaster)
    business_calculator = BusinessImpactCalculator()
except Exception as e:
    print(f"Warning: AI module initialization error: {e}")
    ai_prioritizer = None
    exploit_verifier = None
    business_calculator = None

# Initialize security testing engine
security_tester = SecurityTestingEngine()

# Serve frontend
@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    if os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

# API: Health check
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'ai_enabled': ai_prioritizer is not None,
        'timestamp': datetime.now().isoformat()
    })

# API: AI Analysis
@app.route('/api/ai/analyze', methods=['POST'])
def ai_analyze():
    """AI-powered vulnerability analysis"""
    data = request.json
    scan_id = data.get('scan_id')
    vulnerabilities = data.get('vulnerabilities', [])
    scan_context = data.get('context', {})
    
    if not ai_prioritizer:
        return jsonify({
            'error': 'AI service not available. Please configure OPENROUTER_API_KEY',
            'status': 'error'
        }), 503
    
    try:
        broadcaster.broadcast_log(scan_id, '🤖 Starting AI-powered analysis...')
        
        # Run AI analysis
        result = ai_prioritizer.prioritize_vulnerabilities(vulnerabilities, scan_context)
        
        if result.get('status') == 'success':
            # Store analysis
            ai_analysis_db[scan_id] = {
                'id': f"ai-{scan_id}-{int(time.time())}",
                'scan_id': scan_id,
                'analysis': result,
                'created_at': datetime.now().isoformat()
            }
            
            broadcaster.broadcast_event('ai_analysis_complete', {
                'scan_id': scan_id,
                'status': 'success'
            })
            
            return jsonify(result)
        else:
            return jsonify(result), 500
            
    except Exception as e:
        broadcaster.broadcast_log(scan_id, f'❌ AI analysis error: {str(e)}')
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

# API: Exploit Verification
@app.route('/api/verify/exploit', methods=['POST'])
def verify_exploit():
    """Verify if vulnerability is exploitable"""
    data = request.json
    vulnerability = data.get('vulnerability')
    scan_id = data.get('scan_id', 'unknown')
    
    if not exploit_verifier:
        return jsonify({
            'error': 'Exploit verifier not available',
            'verified': False
        }), 503
    
    try:
        vuln_type = vulnerability.get('type', vulnerability.get('title', '')).lower()
        
        broadcaster.broadcast_log(scan_id, f'🔍 Verifying: {vulnerability.get("title")}')
        
        # Determine verification method
        if 'sql' in vuln_type:
            result = exploit_verifier.verify_sql_injection(vulnerability)
        elif 'xss' in vuln_type:
            result = exploit_verifier.verify_xss(vulnerability)
        elif 'command' in vuln_type or 'rce' in vuln_type:
            result = exploit_verifier.verify_command_injection(vulnerability)
        elif 'file' in vuln_type or 'lfi' in vuln_type:
            result = exploit_verifier.verify_file_inclusion(vulnerability)
        else:
            result = {
                'verified': False,
                'confidence': vulnerability.get('confidence', 70),
                'note': 'Verification not available for this vulnerability type'
            }
        
        # Generate PoC if verified
        if result.get('verified') and exploit_verifier:
            result['exploit_poc'] = exploit_verifier.generate_exploit_poc(vulnerability, result)
        
        # Generate remediation code if AI available
        if result.get('verified') and ai_prioritizer:
            result['remediation_code'] = ai_prioritizer.generate_remediation_code(vulnerability)
        
        # Store verification result
        verification_id = f"verify-{vulnerability.get('id', 'unknown')}-{int(time.time())}"
        verification_db[verification_id] = {
            'id': verification_id,
            'vulnerability_id': vulnerability.get('id'),
            'result': result,
            'timestamp': datetime.now().isoformat()
        }
        
        status = 'verified' if result.get('verified') else 'not_verified'
        broadcaster.broadcast_event('verification_complete', {
            'vulnerability_id': vulnerability.get('id'),
            'verified': result.get('verified'),
            'confidence': result.get('confidence')
        })
        
        return jsonify(result)
        
    except Exception as e:
        broadcaster.broadcast_log(scan_id, f'❌ Verification error: {str(e)}')
        return jsonify({
            'error': str(e),
            'verified': False
        }), 500

# API: Business Impact Calculation
@app.route('/api/business/impact', methods=['POST'])
def calculate_business_impact():
    """Calculate business impact and ROI"""
    data = request.json
    scan_id = data.get('scan_id')
    vulnerabilities = data.get('vulnerabilities', [])
    business_inputs = data.get('inputs', {})
    
    if not business_calculator:
        return jsonify({
            'error': 'Business calculator not available'
        }), 503
    
    try:
        result = business_calculator.calculate_impact(vulnerabilities, business_inputs)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

# API: Batch verify all vulnerabilities
@app.route('/api/verify/batch', methods=['POST'])
def batch_verify():
    """Batch verify multiple vulnerabilities"""
    data = request.json
    scan_id = data.get('scan_id')
    vulnerabilities = data.get('vulnerabilities', [])
    
    if not exploit_verifier:
        return jsonify({
            'error': 'Exploit verifier not available'
        }), 503
    
    try:
        results = []
        for vuln in vulnerabilities:
            # Verify each vulnerability
            vuln_data = {'vulnerability': vuln, 'scan_id': scan_id}
            # Use internal verification logic
            result = verify_exploit_internal(vuln, scan_id)
            results.append({
                'vulnerability_id': vuln.get('id'),
                'result': result
            })
            
            # Small delay between verifications
            time.sleep(0.5)
        
        return jsonify({
            'results': results,
            'total': len(results),
            'verified': sum(1 for r in results if r['result'].get('verified'))
        })
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

def verify_exploit_internal(vulnerability, scan_id):
    """Internal verification helper"""
    vuln_type = vulnerability.get('type', vulnerability.get('title', '')).lower()
    
    broadcaster.broadcast_log(scan_id, f'🔍 Verifying: {vulnerability.get("title")}')
    
    if 'sql' in vuln_type:
        result = exploit_verifier.verify_sql_injection(vulnerability)
    elif 'xss' in vuln_type:
        result = exploit_verifier.verify_xss(vulnerability)
    elif 'command' in vuln_type or 'rce' in vuln_type:
        result = exploit_verifier.verify_command_injection(vulnerability)
    elif 'file' in vuln_type or 'lfi' in vuln_type:
        result = exploit_verifier.verify_file_inclusion(vulnerability)
    else:
        result = {
            'verified': False,
            'confidence': vulnerability.get('confidence', 70)
        }
    
    return result

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('connected', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('subscribe_scan')
def handle_subscribe(data):
    scan_id = data.get('scan_id')
    print(f'Client subscribed to scan: {scan_id}')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5002))
    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║  CyberSage AI Backend - Starting                             ║
    ║  Port: {port}                                                    ║
    ║  AI Enabled: {ai_prioritizer is not None}                                            ║
    ║  Socket.IO: Enabled                                          ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)

# ===== SECURITY TESTING ENDPOINTS =====

@app.route('/api/testing/execute', methods=['POST'])
def execute_security_test():
    """Execute HTTP request with full control"""
    data = request.json
    request_config = data.get('request', {})
    
    try:
        result = security_tester.execute_request(request_config)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/testing/vulnerability-scan', methods=['POST'])
def vulnerability_scan():
    """Run comprehensive vulnerability scan"""
    data = request.json
    url = data.get('url')
    params = data.get('params', {})
    method = data.get('method', 'GET')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        broadcaster.broadcast_log('vuln_scan', f'Starting vulnerability scan on {url}')
        result = security_tester.comprehensive_vulnerability_scan(url, params, method)
        broadcaster.broadcast_event('vulnerability_scan_complete', {
            'url': url,
            'results': result
        })
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/api/testing/sql-injection', methods=['POST'])
def test_sql_injection():
    """Test for SQL injection vulnerabilities"""
    data = request.json
    url = data.get('url')
    params = data.get('params', {})
    method = data.get('method', 'GET')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        result = security_tester.test_sql_injection(url, params, method)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/api/testing/xss', methods=['POST'])
def test_xss():
    """Test for XSS vulnerabilities"""
    data = request.json
    url = data.get('url')
    params = data.get('params', {})
    method = data.get('method', 'GET')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        result = security_tester.test_xss(url, params, method)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/api/testing/command-injection', methods=['POST'])
def test_command_injection():
    """Test for command injection vulnerabilities"""
    data = request.json
    url = data.get('url')
    params = data.get('params', {})
    method = data.get('method', 'GET')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        result = security_tester.test_command_injection(url, params, method)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/api/testing/path-traversal', methods=['POST'])
def test_path_traversal():
    """Test for path traversal vulnerabilities"""
    data = request.json
    url = data.get('url')
    params = data.get('params', {})
    method = data.get('method', 'GET')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        result = security_tester.test_path_traversal(url, params, method)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/api/testing/payloads/<vuln_type>', methods=['GET'])
def get_payloads(vuln_type):
    """Get payload library for vulnerability type"""
    try:
        payloads = security_tester.generate_payloads(vuln_type)
        return jsonify({
            'type': vuln_type,
            'payloads': payloads
        })
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/api/testing/history', methods=['GET'])
def get_test_history():
    """Get testing history"""
    try:
        limit = request.args.get('limit', 50, type=int)
        history = security_tester.test_history[-limit:]
        return jsonify({
            'history': history,
            'total': len(security_tester.test_history)
        })
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

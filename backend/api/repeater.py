"""
HTTP Repeater API - Proxy endpoint for making HTTP requests
"""

from flask import Blueprint, request, jsonify
import requests
import time
import json
from urllib.parse import urlparse

repeater_bp = Blueprint('repeater', __name__)

@repeater_bp.route('/api/repeater/proxy', methods=['POST'])
def proxy_request():
    """
    Proxy HTTP requests from the repeater tool
    """
    try:
        data = request.json
        target_url = data.get('url')
        method = data.get('method', 'GET')
        headers = data.get('headers', {})
        body = data.get('body', None)
        
        # Validate URL
        if not target_url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Parse URL
        parsed = urlparse(target_url)
        if not parsed.scheme:
            target_url = 'http://' + target_url
        
        # Remove any proxy-specific headers
        headers.pop('Host', None)
        headers.pop('Content-Length', None)
        
        # Make the request
        start_time = time.time()
        
        try:
            if method in ['POST', 'PUT', 'PATCH']:
                # Try to parse body as JSON if Content-Type is JSON
                if headers.get('Content-Type') == 'application/json' and body:
                    try:
                        body = json.loads(body) if isinstance(body, str) else body
                    except:
                        pass
                
                response = requests.request(
                    method=method,
                    url=target_url,
                    headers=headers,
                    json=body if headers.get('Content-Type') == 'application/json' else None,
                    data=body if headers.get('Content-Type') != 'application/json' else None,
                    timeout=30,
                    verify=False,
                    allow_redirects=False
                )
            else:
                response = requests.request(
                    method=method,
                    url=target_url,
                    headers=headers,
                    timeout=30,
                    verify=False,
                    allow_redirects=False
                )
            
            elapsed_time = (time.time() - start_time) * 1000  # Convert to ms
            
            # Build response data
            response_data = {
                'status': response.status_code,
                'statusText': response.reason,
                'headers': dict(response.headers),
                'body': None,
                'time': elapsed_time,
                'size': len(response.content)
            }
            
            # Try to parse response as JSON
            try:
                response_data['body'] = response.json()
            except:
                # If not JSON, return as text
                try:
                    response_data['body'] = response.text
                except:
                    response_data['body'] = response.content.decode('utf-8', errors='ignore')
            
            return jsonify(response_data)
            
        except requests.exceptions.Timeout:
            return jsonify({
                'error': True,
                'message': 'Request timed out after 30 seconds',
                'status': 0
            }), 408
            
        except requests.exceptions.ConnectionError:
            return jsonify({
                'error': True,
                'message': 'Failed to connect to the target server',
                'status': 0
            }), 502
            
        except Exception as e:
            return jsonify({
                'error': True,
                'message': str(e),
                'status': 0
            }), 500
            
    except Exception as e:
        return jsonify({
            'error': True,
            'message': f'Invalid request: {str(e)}'
        }), 400

@repeater_bp.route('/api/repeater/collections', methods=['GET'])
def get_collections():
    """
    Get saved request collections
    """
    # TODO: Implement database storage for collections
    return jsonify([])

@repeater_bp.route('/api/repeater/collections', methods=['POST'])
def save_collection():
    """
    Save a request to collections
    """
    # TODO: Implement database storage for collections
    data = request.json
    return jsonify({'success': True, 'id': 1})

@repeater_bp.route('/api/repeater/history', methods=['GET'])
def get_history():
    """
    Get request history
    """
    # TODO: Implement database storage for history
    return jsonify([])

@repeater_bp.route('/api/repeater/environments', methods=['GET'])
def get_environments():
    """
    Get environment variables
    """
    return jsonify({
        'dev': {
            'baseUrl': 'http://localhost:3000',
            'token': '',
            'apiKey': ''
        },
        'staging': {
            'baseUrl': 'https://staging.example.com',
            'token': '',
            'apiKey': ''
        },
        'prod': {
            'baseUrl': 'https://api.example.com',
            'token': '',
            'apiKey': ''
        }
    })

@repeater_bp.route('/api/repeater/environments', methods=['POST'])
def save_environment():
    """
    Save environment variables
    """
    data = request.json
    # TODO: Implement database storage for environments
    return jsonify({'success': True})

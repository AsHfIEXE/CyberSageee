# 🔌 CyberSage 2.0 - API Documentation

> **Complete API reference for the CyberSage 2.0 cybersecurity vulnerability scanner**

## 📋 Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Base URLs](#base-urls)
4. [REST API Endpoints](#rest-api-endpoints)
5. [WebSocket Events](#websocket-events)
6. [Request/Response Examples](#requestresponse-examples)
7. [Error Handling](#error-handling)
8. [Rate Limiting](#rate-limiting)
9. [SDK Reference](#sdk-reference)
10. [Webhooks](#webhooks)

---

## 🔍 Overview

The CyberSage 2.0 API provides comprehensive endpoints for cybersecurity vulnerability scanning, security tool integration, and real-time monitoring. The API supports both REST endpoints for traditional HTTP requests and WebSocket connections for real-time updates.

### Key Features
- ✅ **RESTful Design**: Standard HTTP methods and status codes
- ✅ **Real-time Updates**: WebSocket connections for live scanning
- ✅ **Multiple Formats**: JSON responses with CSV, PDF export options
- ✅ **Authentication**: Token-based API authentication
- ✅ **Rate Limiting**: Built-in rate limiting for API protection
- ✅ **Pagination**: Cursor-based pagination for large datasets
- ✅ **Filtering**: Advanced query parameters for data filtering

---

## 🔐 Authentication

### API Key Authentication
Include your API key in the request header:

```http
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json
```

### Generating API Keys
```bash
POST /api/auth/generate-key
Authorization: Bearer admin_token
Content-Type: application/json

{
  "user_id": "user123",
  "permissions": ["scan", "read", "write"],
  "expires_in": "30d"
}
```

**Response:**
```json
{
  "api_key": "cybs_1a2b3c4d5e6f7g8h9i0j",
  "expires_at": "2025-11-30T23:55:06Z",
  "permissions": ["scan", "read", "write"]
}
```

### API Key Verification
```bash
GET /api/auth/verify
Authorization: Bearer YOUR_API_KEY
```

**Response:**
```json
{
  "valid": true,
  "user_id": "user123",
  "permissions": ["scan", "read"],
  "expires_at": "2025-11-30T23:55:06Z"
}
```

---

## 🌐 Base URLs

### Development
- **REST API**: `http://localhost:5000/api`
- **WebSocket**: `ws://localhost:5000/socket.io`
- **Admin API**: `http://localhost:5000/admin`

### Production
- **REST API**: `https://your-domain.com/api`
- **WebSocket**: `wss://your-domain.com/socket.io`
- **Admin API**: `https://your-domain.com/admin`

---

## 🛠️ REST API Endpoints

### 1. Health & Status

#### Get System Health
```bash
GET /api/health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-10-31T23:55:06Z",
  "version": "2.0.0",
  "uptime": "2h 15m",
  "services": {
    "database": "connected",
    "websocket": "active",
    "scanner": "ready"
  },
  "tools_available": 15,
  "active_scans": 3
}
```

#### Get System Statistics
```bash
GET /api/stats
```

**Response:**
```json
{
  "total_scans": 1247,
  "vulnerabilities_found": 8934,
  "critical_issues": 127,
  "high_issues": 341,
  "medium_issues": 892,
  "low_issues": 1567,
  "info_issues": 5913,
  "average_scan_time": "8m 23s",
  "success_rate": "98.7%"
}
```

### 2. Scan Management

#### Create New Scan
```bash
POST /api/scans
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json

{
  "name": "Website Security Assessment",
  "target": "https://example.com",
  "scan_type": "comprehensive",
  "tools": ["vulnerability_scanner", "security_headers", "nmap"],
  "options": {
    "depth": "deep",
    "timeout": 3600,
    "concurrency": 5
  },
  "schedule": {
    "enabled": false,
    "cron": "0 2 * * *"
  }
}
```

**Response:**
```json
{
  "scan_id": "scan_1a2b3c4d5e6f7g8h9i0j",
  "status": "queued",
  "created_at": "2025-10-31T23:55:06Z",
  "estimated_duration": "15m 30s",
  "queue_position": 1
}
```

#### Get Scan Status
```bash
GET /api/scans/{scan_id}
Authorization: Bearer YOUR_API_KEY
```

**Response:**
```json
{
  "scan_id": "scan_1a2b3c4d5e6f7g8h9i0j",
  "name": "Website Security Assessment",
  "status": "running",
  "progress": 45,
  "target": "https://example.com",
  "scan_type": "comprehensive",
  "tools": [
    {
      "name": "vulnerability_scanner",
      "status": "completed",
      "progress": 100
    },
    {
      "name": "security_headers",
      "status": "running",
      "progress": 75
    }
  ],
  "start_time": "2025-10-31T23:55:06Z",
  "estimated_completion": "2025-10-31T00:10:36Z"
}
```

#### List All Scans
```bash
GET /api/scans?page=1&limit=20&status=running&sort=created_at&order=desc
Authorization: Bearer YOUR_API_KEY
```

**Response:**
```json
{
  "scans": [
    {
      "scan_id": "scan_1a2b3c4d5e6f7g8h9i0j",
      "name": "Website Security Assessment",
      "status": "running",
      "progress": 45,
      "target": "https://example.com",
      "created_at": "2025-10-31T23:55:06Z"
    }
  ],
  "pagination": {
    "current_page": 1,
    "total_pages": 5,
    "total_scans": 95,
    "per_page": 20
  }
}
```

#### Cancel Scan
```bash
DELETE /api/scans/{scan_id}
Authorization: Bearer YOUR_API_KEY
```

**Response:**
```json
{
  "scan_id": "scan_1a2b3c4d5e6f7g8h9i0j",
  "status": "cancelled",
  "cancelled_at": "2025-10-31T23:58:12Z"
}
```

### 3. Scan Results

#### Get Scan Results
```bash
GET /api/scans/{scan_id}/results
Authorization: Bearer YOUR_API_KEY
```

**Response:**
```json
{
  "scan_id": "scan_1a2b3c4d5e6f7g8h9i0j",
  "summary": {
    "total_vulnerabilities": 23,
    "critical": 2,
    "high": 5,
    "medium": 8,
    "low": 8,
    "scan_duration": "12m 45s",
    "tools_executed": 8
  },
  "vulnerabilities": [
    {
      "id": "vuln_1a2b3c4d5e6f7g8h9i0j",
      "title": "SQL Injection Vulnerability",
      "severity": "critical",
      "cvss_score": 9.8,
      "description": "Potential SQL injection in login form",
      "affected_url": "https://example.com/login",
      "parameter": "username",
      "proof_of_concept": "POST /login with malicious payload",
      "remediation": "Use parameterized queries and input validation",
      "cwe_id": "CWE-89",
      "tool_source": "sqlmap",
      "discovered_at": "2025-10-31T23:58:12Z"
    }
  ],
  "technical_details": {
    "network_scan": {
      "open_ports": [80, 443, 22, 3306],
      "services": [
        {
          "port": 80,
          "service": "http",
          "version": "Apache 2.4.41",
          "vulnerabilities": []
        }
      ]
    },
    "web_analysis": {
      "forms_discovered": 12,
      "inputs_analyzed": 47,
      "security_headers": {
        "missing": ["X-Frame-Options", "X-XSS-Protection"],
        "present": ["Content-Security-Policy", "Strict-Transport-Security"]
      }
    }
  }
}
```

#### Export Scan Results
```bash
GET /api/scans/{scan_id}/export?format=pdf&template=executive
Authorization: Bearer YOUR_API_KEY
```

**Response:**
- **Content-Type**: `application/pdf`
- **Content-Disposition**: `attachment; filename="scan_report_1a2b3c4d5e6f7g8h9i0j.pdf"`

### 4. Tools Management

#### Get Available Tools
```bash
GET /api/tools
Authorization: Bearer YOUR_API_KEY
```

**Response:**
```json
{
  "tools": [
    {
      "id": "nmap",
      "name": "Nmap Scanner",
      "description": "Network discovery and port scanning",
      "version": "7.94",
      "category": "network",
      "supported_targets": ["ip", "cidr", "domain"],
      "parameters": [
        {
          "name": "scan_type",
          "type": "string",
          "options": ["tcp", "udp", "syn", "ack"],
          "required": true
        },
        {
          "name": "port_range",
          "type": "string",
          "default": "1-1000",
          "required": false
        }
      ],
      "estimated_duration": "2-10 minutes"
    }
  ],
  "categories": ["network", "web", "database", "wireless", "analysis"]
}
```

#### Execute Tool Directly
```bash
POST /api/tools/nmap/execute
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json

{
  "target": "192.168.1.1",
  "parameters": {
    "scan_type": "tcp",
    "port_range": "1-1000",
    "timing": "T4"
  }
}
```

**Response:**
```json
{
  "execution_id": "exec_1a2b3c4d5e6f7g8h9i0j",
  "status": "running",
  "estimated_duration": "3m 15s",
  "progress": 0,
  "results_endpoint": "/api/tools/nmap/results/exec_1a2b3c4d5e6f7g8h9i0j"
}
```

#### Get Tool Results
```bash
GET /api/tools/nmap/results/{execution_id}
Authorization: Bearer YOUR_API_KEY
```

**Response:**
```json
{
  "execution_id": "exec_1a2b3c4d5e6f7g8h9i0j",
  "status": "completed",
  "progress": 100,
  "results": {
    "target": "192.168.1.1",
    "open_ports": [
      {
        "port": 22,
        "protocol": "tcp",
        "service": "ssh",
        "version": "OpenSSH 8.2p1",
        "state": "open"
      },
      {
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "version": "Apache 2.4.41",
        "state": "open"
      }
    ],
    "host_info": {
      "os": "Linux 4.15.0",
      "uptime": "15 days",
      "mac_address": "00:1B:44:11:3A:B7"
    }
  }
}
```

### 5. Vulnerability Management

#### Get Vulnerabilities
```bash
GET /api/vulnerabilities?scan_id=scan_1a2b3c4d5e6f7g8h9i0j&severity=critical&page=1&limit=10
Authorization: Bearer YOUR_API_KEY
```

**Response:**
```json
{
  "vulnerabilities": [
    {
      "id": "vuln_1a2b3c4d5e6f7g8h9i0j",
      "title": "SQL Injection Vulnerability",
      "severity": "critical",
      "cvss_score": 9.8,
      "status": "open",
      "affected_url": "https://example.com/login",
      "parameter": "username",
      "discovered_at": "2025-10-31T23:58:12Z",
      "scan_id": "scan_1a2b3c4d5e6f7g8h9i0j"
    }
  ],
  "pagination": {
    "current_page": 1,
    "total_pages": 3,
    "total_vulnerabilities": 23
  },
  "filters_applied": {
    "severity": "critical",
    "scan_id": "scan_1a2b3c4d5e6f7g8h9i0j"
  }
}
```

#### Update Vulnerability Status
```bash
PATCH /api/vulnerabilities/{vulnerability_id}
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json

{
  "status": "fixed",
  "notes": "Applied input validation and parameterized queries",
  "assignee": "security@company.com"
}
```

### 6. Reports

#### Generate Report
```bash
POST /api/reports
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json

{
  "name": "Monthly Security Report",
  "scan_ids": ["scan_1a2b3c4d5e6f7g8h9i0j", "scan_2b3c4d5e6f7g8h9i0j"],
  "template": "executive",
  "format": "pdf",
  "include_raw_data": false,
  "sections": ["summary", "vulnerabilities", "recommendations"]
}
```

**Response:**
```json
{
  "report_id": "report_1a2b3c4d5e6f7g8h9i0j",
  "status": "generating",
  "estimated_completion": "2025-10-31T00:03:36Z",
  "download_url": "/api/reports/report_1a2b3c4d5e6f7g8h9i0j/download"
}
```

#### Get Report
```bash
GET /api/reports/{report_id}
Authorization: Bearer YOUR_API_KEY
```

**Response:**
```json
{
  "report_id": "report_1a2b3c4d5e6f7g8h9i0j",
  "name": "Monthly Security Report",
  "status": "completed",
  "created_at": "2025-10-31T23:58:12Z",
  "download_url": "/api/reports/report_1a2b3c4d5e6f7g8h9i0j/download",
  "format": "pdf",
  "size": "2.4 MB",
  "expires_at": "2025-11-07T23:58:12Z"
}
```

---

## 🔄 WebSocket Events

### Connection
```javascript
const socket = io('ws://localhost:5000', {
  auth: {
    token: 'YOUR_API_KEY'
  }
});
```

### Event Types

#### Scan Progress Updates
```javascript
socket.on('scan_progress', (data) => {
  console.log('Scan Progress:', data);
});

// Data format:
{
  "scan_id": "scan_1a2b3c4d5e6f7g8h9i0j",
  "progress": 45,
  "current_tool": "vulnerability_scanner",
  "tools_completed": 2,
  "total_tools": 5,
  "estimated_remaining": "8m 23s"
}
```

#### Scan Completion
```javascript
socket.on('scan_complete', (data) => {
  console.log('Scan Completed:', data);
});

// Data format:
{
  "scan_id": "scan_1a2b3c4d5e6f7g8h9i0j",
  "status": "completed",
  "summary": {
    "total_vulnerabilities": 23,
    "critical": 2,
    "high": 5,
    "medium": 8,
    "low": 8
  },
  "completion_time": "2025-10-31T00:10:36Z"
}
```

#### Vulnerability Discovered
```javascript
socket.on('vulnerability_discovered', (data) => {
  console.log('New Vulnerability:', data);
});

// Data format:
{
  "scan_id": "scan_1a2b3c4d5e6f7g8h9i0j",
  "vulnerability": {
    "id": "vuln_1a2b3c4d5e6f7g8h9i0j",
    "title": "SQL Injection Vulnerability",
    "severity": "critical",
    "cvss_score": 9.8,
    "description": "Potential SQL injection in login form"
  },
  "timestamp": "2025-10-31T23:58:12Z"
}
```

#### Tool Status Updates
```javascript
socket.on('tool_status', (data) => {
  console.log('Tool Status:', data);
});

// Data format:
{
  "scan_id": "scan_1a2b3c4d5e6f7g8h9i0j",
  "tool_name": "nmap",
  "status": "running",
  "progress": 65,
  "current_stage": "Port scanning",
  "estimated_completion": "2025-10-31T00:05:12Z"
}
```

### WebSocket Event Types

| Event | Direction | Description |
|-------|-----------|-------------|
| `scan_progress` | Server → Client | Real-time scan progress updates |
| `scan_complete` | Server → Client | Scan completion notification |
| `scan_error` | Server → Client | Scan error notification |
| `vulnerability_discovered` | Server → Client | New vulnerability found |
| `tool_status` | Server → Client | Tool execution status |
| `subscribe_scan` | Client → Server | Subscribe to scan updates |
| `unsubscribe_scan` | Client → Server | Unsubscribe from scan updates |

---

## 📝 Request/Response Examples

### Complete Scan Workflow

#### 1. Create Scan
```bash
curl -X POST http://localhost:5000/api/scans \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Security Assessment",
    "target": "https://example.com",
    "scan_type": "comprehensive",
    "tools": ["vulnerability_scanner", "security_headers", "nmap"]
  }'
```

#### 2. Monitor Progress (WebSocket)
```javascript
const socket = io('ws://localhost:5000', {
  auth: { token: 'YOUR_API_KEY' }
});

socket.on('connect', () => {
  socket.emit('subscribe_scan', { scan_id: 'scan_1a2b3c4d5e6f7g8h9i0j' });
});

socket.on('scan_progress', (data) => {
  console.log(`Progress: ${data.progress}%`);
});

socket.on('scan_complete', (data) => {
  console.log('Scan completed with', data.summary.total_vulnerabilities, 'vulnerabilities');
});
```

#### 3. Get Results
```bash
curl -X GET http://localhost:5000/api/scans/scan_1a2b3c4d5e6f7g8h9i0j/results \
  -H "Authorization: Bearer YOUR_API_KEY"
```

#### 4. Export Report
```bash
curl -X GET "http://localhost:5000/api/scans/scan_1a2b3c4d5e6f7g8h9i0j/export?format=pdf&template=executive" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  --output report.pdf
```

### Error Handling Example
```javascript
fetch('/api/scans', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer YOUR_API_KEY',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    "target": "https://example.com",
    "scan_type": "comprehensive"
  })
})
.then(response => {
  if (!response.ok) {
    return response.json().then(error => {
      throw new Error(error.message || 'API request failed');
    });
  }
  return response.json();
})
.then(data => {
  console.log('Scan created:', data.scan_id);
})
.catch(error => {
  console.error('Error:', error.message);
});
```

---

## ❌ Error Handling

### HTTP Status Codes

| Code | Status | Description |
|------|--------|-------------|
| 200 | OK | Request successful |
| 201 | Created | Resource created successfully |
| 400 | Bad Request | Invalid request parameters |
| 401 | Unauthorized | Invalid or missing API key |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error |

### Error Response Format
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid target URL provided",
    "details": {
      "field": "target",
      "value": "not-a-valid-url",
      "expected_format": "http(s)://domain.com or IP address"
    },
    "request_id": "req_1a2b3c4d5e6f7g8h9i0j",
    "timestamp": "2025-10-31T23:55:06Z"
  }
}
```

### Common Error Codes

| Code | Description | Resolution |
|------|-------------|------------|
| `INVALID_TARGET` | Target URL/IP is malformed | Check target format |
| `TARGET_UNREACHABLE` | Cannot connect to target | Verify network connectivity |
| `TOOL_NOT_AVAILABLE` | Required security tool missing | Install required tools |
| `RATE_LIMIT_EXCEEDED` | Too many requests | Wait before retrying |
| `INSUFFICIENT_PERMISSIONS` | API key lacks required permissions | Check API key permissions |
| `SCAN_ALREADY_RUNNING` | Scan already in progress | Wait for completion or cancel |

---

## ⚡ Rate Limiting

### Rate Limits
- **Standard Tier**: 100 requests per hour
- **Professional Tier**: 1,000 requests per hour
- **Enterprise Tier**: 10,000 requests per hour

### Rate Limit Headers
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 995
X-RateLimit-Reset: 1635724800
X-RateLimit-Window: 3600
```

### Rate Limit Exceeded Response
```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Try again in 15 minutes.",
    "retry_after": 900
  }
}
```

---

## 💻 SDK Reference

### JavaScript SDK

#### Installation
```bash
npm install cybersage-api
```

#### Basic Usage
```javascript
import CyberSageAPI from 'cybersage-api';

const client = new CyberSageAPI({
  apiKey: 'YOUR_API_KEY',
  baseURL: 'http://localhost:5000/api'
});

// Create scan
const scan = await client.scans.create({
  name: 'Security Assessment',
  target: 'https://example.com',
  scanType: 'comprehensive'
});

// Monitor progress
client.scans.onProgress(scan.id, (data) => {
  console.log(`Progress: ${data.progress}%`);
});

// Get results
const results = await client.scans.getResults(scan.id);
```

#### Full SDK Example
```javascript
import CyberSageAPI from 'cybersage-api';

class SecurityMonitor {
  constructor(apiKey, baseURL = 'http://localhost:5000/api') {
    this.client = new CyberSageAPI({ apiKey, baseURL });
    this.websocket = new CyberSageWebSocket({
      apiKey,
      url: 'ws://localhost:5000'
    });
  }

  async runSecurityAssessment(target) {
    try {
      // Create comprehensive scan
      const scan = await this.client.scans.create({
        name: `Security Assessment for ${target}`,
        target: target,
        scanType: 'comprehensive',
        tools: ['vulnerability_scanner', 'security_headers', 'nmap', 'sqlmap']
      });

      console.log(`Scan created: ${scan.id}`);
      
      // Subscribe to real-time updates
      this.websocket.subscribeToScan(scan.id);
      
      this.websocket.on('scan_complete', async (data) => {
        if (data.scan_id === scan.id) {
          const results = await this.client.scans.getResults(scan.id);
          this.generateReport(results);
        }
      });

      return scan;
    } catch (error) {
      console.error('Security assessment failed:', error);
      throw error;
    }
  }

  generateReport(results) {
    const report = {
      summary: results.summary,
      critical_vulnerabilities: results.vulnerabilities.filter(v => v.severity === 'critical'),
      recommendations: this.generateRecommendations(results)
    };
    
    console.log('Security Report Generated:', report);
  }

  generateRecommendations(results) {
    // AI-powered recommendations based on findings
    return results.vulnerabilities.map(vuln => ({
      vulnerability: vuln.title,
      priority: vuln.severity,
      action: vuln.remediation,
      timeline: vuln.severity === 'critical' ? 'immediate' : 'within_7_days'
    }));
  }
}

// Usage
const monitor = new SecurityMonitor('YOUR_API_KEY');
monitor.runSecurityAssessment('https://example.com');
```

### Python SDK

#### Installation
```bash
pip install cybersage-api
```

#### Basic Usage
```python
from cybersage import CyberSageClient

client = CyberSageClient(
    api_key='YOUR_API_KEY',
    base_url='http://localhost:5000/api'
)

# Create scan
scan = client.scans.create({
    'name': 'Security Assessment',
    'target': 'https://example.com',
    'scan_type': 'comprehensive'
})

# Monitor progress
for progress in client.scans.stream_progress(scan['scan_id']):
    print(f"Progress: {progress['progress']}%")

# Get results
results = client.scans.get_results(scan['scan_id'])
print(f"Found {results['summary']['total_vulnerabilities']} vulnerabilities")
```

---

## 🔗 Webhooks

### Webhook Configuration
```bash
POST /api/webhooks
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json

{
  "url": "https://your-app.com/webhooks/cybersage",
  "events": ["scan_complete", "vulnerability_discovered"],
  "secret": "your-webhook-secret",
  "active": true
}
```

### Webhook Events

#### Scan Complete
```json
{
  "event": "scan_complete",
  "timestamp": "2025-10-31T23:55:06Z",
  "data": {
    "scan_id": "scan_1a2b3c4d5e6f7g8h9i0j",
    "status": "completed",
    "summary": {
      "total_vulnerabilities": 23,
      "critical": 2
    }
  }
}
```

#### Vulnerability Discovered
```json
{
  "event": "vulnerability_discovered",
  "timestamp": "2025-10-31T23:58:12Z",
  "data": {
    "scan_id": "scan_1a2b3c4d5e6f7g8h9i0j",
    "vulnerability": {
      "id": "vuln_1a2b3c4d5e6f7g8h9i0j",
      "title": "SQL Injection",
      "severity": "critical",
      "cvss_score": 9.8
    }
  }
}
```

### Webhook Security
```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, f"sha256={expected_signature}")
```

---

## 🚀 Getting Started

### 1. Get Your API Key
```bash
POST /api/auth/generate-key
Authorization: Bearer admin_token
Content-Type: application/json

{
  "user_id": "your-user-id",
  "permissions": ["scan", "read", "write"],
  "expires_in": "30d"
}
```

### 2. Test Connection
```bash
curl -X GET http://localhost:5000/api/health \
  -H "Authorization: Bearer YOUR_API_KEY"
```

### 3. Run Your First Scan
```bash
curl -X POST http://localhost:5000/api/scans \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My First Scan",
    "target": "https://httpbin.org",
    "scan_type": "quick"
  }'
```

### 4. Monitor Progress
Use WebSocket connection or poll the scan status endpoint for real-time updates.

---

**📞 Support**: For API support, visit our [GitHub Issues](https://github.com/your-username/CyberSage-2.0/issues) or contact [api-support@cybersage.com](mailto:api-support@cybersage.com)

**🔗 Documentation**: [GitHub Repository](https://github.com/your-username/CyberSage-2.0) | [API Playground](https://api-docs.cybersage.com)
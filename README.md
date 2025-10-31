# CyberSage 2.0 - Advanced Cybersecurity Vulnerability Scanner

![CyberSage](https://img.shields.io/badge/CyberSage-2.0-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Node.js](https://img.shields.io/badge/Node.js-18+-green)

**CyberSage 2.0** is a comprehensive, enterprise-grade cybersecurity vulnerability scanner that provides advanced network analysis, security assessment, and vulnerability detection capabilities. Built with modern web technologies and powered by industry-standard security tools.

## 🚀 Quick Start

### One-Command Installation

```bash
# Clone the repository
git clone https://github.com/your-username/CyberSage-2.0.git
cd CyberSage-2.0

# Run the automated installer
chmod +x setup.sh && ./setup.sh
```

The setup script will automatically:
- ✅ Detect your operating system (Linux/macOS)
- ✅ Install all required dependencies
- ✅ Set up the Python backend with virtual environment
- ✅ Configure the React frontend
- ✅ Install security tools (Nmap, Nikto, SQLMap, Gobuster, etc.)
- ✅ Start all services automatically
- ✅ Launch the web interface in your browser

**That's it!** CyberSage will be running at `http://localhost:3000`

## 🌟 Features

### Core Capabilities
- **🔍 Network Discovery**: Advanced port scanning and network topology analysis
- **🛡️ Vulnerability Assessment**: Comprehensive security vulnerability detection
- **🌐 Web Security Analysis**: HTTP security headers, SSL/TLS analysis, and web application testing
- **🤖 AI-Powered Analysis**: Machine learning-based threat detection and pattern recognition
- **📊 Real-time Reporting**: Live scan results with detailed technical reports
- **🔄 Continuous Monitoring**: Scheduled scans and automated security assessments

### Security Tools Integration
- **Nmap**: Network discovery and security auditing
- **Nikto**: Web vulnerability scanner
- **SQLMap**: Automatic SQL injection detection
- **Gobuster**: Directory/file brute-forcing
- **Dirb**: Web content scanner
- **WPScan**: WordPress security scanner
- **Subfinder**: Subdomain discovery
- **Amass**: Network mapping and subdomain enumeration
- **Hydra**: Password brute-forcing
- **John the Ripper**: Password cracking
- **Metasploit Framework**: Penetration testing
- **Aircrack-ng**: Wireless network auditing
- **Burp Suite**: Web application security testing
- **OWASP ZAP**: Web application security scanner
- **Nessus**: Vulnerability assessment (professional edition)

## 🏗️ Architecture

```
CyberSage 2.0/
├── backend/                 # Flask + SocketIO backend
│   ├── app.py              # Main application server
│   ├── models/             # Data models
│   ├── routes/             # API endpoints
│   ├── utils/              # Security tool wrappers
│   └── requirements.txt    # Python dependencies
├── frontend/               # React 18 frontend
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── pages/          # Application pages
│   │   ├── hooks/          # Custom React hooks
│   │   └── utils/          # Frontend utilities
│   └── package.json        # Node.js dependencies
├── tools/                  # Security tools integration
├── setup.sh               # Automated installation script
├── README.md              # This file
├── INSTALLATION.md        # Detailed installation guide
├── TOOLS.md               # Comprehensive tools documentation
└── QUICK-START.md         # 30-second quick start guide
```

## 🛠️ System Requirements

### Minimum Requirements
- **Operating System**: Linux (Ubuntu 20.04+, CentOS 8+, Debian 10+) or macOS (10.15+)
- **Python**: 3.10 or higher
- **Node.js**: 18.0 or higher
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 2GB free space
- **Network**: Internet connection for tool downloads

### Recommended Specifications
- **RAM**: 16GB for optimal performance
- **CPU**: Multi-core processor (4+ cores)
- **Storage**: SSD for faster scan performance
- **Network**: High-speed internet for cloud-based scans

## 📋 Detailed Installation

### Step 1: Prerequisites

**Install required system packages:**

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y curl wget git python3 python3-pip python3-venv

# CentOS/RHEL
sudo yum update -y
sudo yum install -y curl wget git python3 python3-pip

# macOS (requires Homebrew)
brew install python3 git
```

**Install Node.js:**

```bash
# Using NodeSource repository (recommended)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# macOS
brew install node@18
```

### Step 2: Clone and Install

```bash
# Clone the repository
git clone https://github.com/your-username/CyberSage-2.0.git
cd CyberSage-2.0

# Make setup script executable
chmod +x setup.sh

# Run the automated installer
./setup.sh
```

### Step 3: Manual Security Tools Installation

The setup script will automatically install most tools, but you can manually install additional tools:

```bash
# Install security tools
sudo apt install -y nmap nikto dirb gobuster wpscan hydra

# Install additional Python packages
pip3 install -r requirements.txt
```

### Step 4: Configure Environment

```bash
# Backend configuration
cp backend/.env.example backend/.env
# Edit backend/.env with your settings

# Frontend configuration  
cp frontend/.env.example frontend/.env
# Edit frontend/.env with your settings
```

### Step 5: Start Services

```bash
# Start backend server
cd backend && python3 app.py

# In a new terminal, start frontend
cd frontend && npm start
```

CyberSage will be available at `http://localhost:3000`

## 🎯 Usage Examples

### Basic Network Scan

```javascript
// Using the web interface
1. Navigate to http://localhost:3000
2. Select "Network Scanner"
3. Enter target IP or range (e.g., 192.168.1.0/24)
4. Click "Start Scan"
5. View real-time results in the dashboard
```

### Vulnerability Assessment

```python
# Python API usage
from cybersage import VulnerabilityScanner

scanner = VulnerabilityScanner()
results = scanner.scan_target("https://example.com")
print(results.get_vulnerabilities())
```

### Web Application Testing

```bash
# Command line usage
python3 tools/web_scanner.py --target "https://example.com" --scan-type full
```

### Automated Scanning

```bash
# Schedule regular scans
crontab -e
# Add: 0 2 * * * /path/to/cybersage/tools/scheduled_scan.py
```

## 📊 API Documentation

### REST Endpoints

#### Scan Management
- `POST /api/scans/start` - Start a new scan
- `GET /api/scans/{scan_id}` - Get scan status and results
- `DELETE /api/scans/{scan_id}` - Cancel ongoing scan
- `GET /api/scans` - List all scans

#### Tool Execution
- `POST /api/tools/nmap` - Execute Nmap scan
- `POST /api/tools/nikto` - Run Nikto vulnerability scan
- `POST /api/tools/sqlmap` - Perform SQL injection test
- `POST /api/tools/gobuster` - Directory brute-forcing

#### Reports
- `GET /api/reports/{scan_id}` - Get scan report
- `POST /api/reports/export` - Export report (PDF/JSON/CSV)

### WebSocket Events

```javascript
// Real-time scan updates
const socket = io('http://localhost:5000');

socket.on('scan_progress', (data) => {
    console.log(`Scan progress: ${data.progress}%`);
});

socket.on('scan_complete', (data) => {
    console.log('Scan completed:', data.results);
});
```

### Python SDK

```python
from cybersage import CyberSage

# Initialize client
client = CyberSage(api_key="your-api-key")

# Create scan
scan = client.scans.create(
    target="192.168.1.1",
    scan_type="network_discovery",
    tools=["nmap", "nikto"]
)

# Monitor progress
for update in scan.stream():
    print(f"Progress: {update.progress}%")
```

## 🔧 Configuration

### Environment Variables

#### Backend Configuration
```bash
# backend/.env
FLASK_ENV=production
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///cybersage.db
CORS_ORIGINS=http://localhost:3000
WEBSOCKET_PATH=/socket.io
MAX_SCAN_DURATION=3600
THREAD_POOL_SIZE=10
LOG_LEVEL=INFO
```

#### Frontend Configuration
```bash
# frontend/.env
REACT_APP_API_URL=http://localhost:5000
REACT_APP_WEBSOCKET_URL=http://localhost:5000
REACT_APP_MAX_FILE_SIZE=50MB
REACT_APP_SCAN_TIMEOUT=3600
GENERATE_SOURCEMAP=false
```

### Security Configuration

```bash
# tools/security_config.yaml
nmap:
  timing: T4
  ports: "1-65535"
  scripts: "vuln,safe"

nikto:
  plugins: "ssl,cookies,errors"
  maxtime: "1h"

sqlmap:
  risk: 3
  level: 5
  threads: 10
```

## 📈 Performance Optimization

### Scan Optimization
```bash
# Optimize Nmap for speed
nmap -T4 -F --min-rate 1000 target

# Parallel scanning
python3 tools/parallel_scanner.py --targets targets.txt --tools nmap,nikto
```

### Resource Management
```bash
# Limit memory usage
export MAX_MEMORY_USAGE=4GB

# CPU throttling
export CPU_LIMIT=80
```

### Database Optimization
```sql
-- Index frequently queried columns
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at);
CREATE INDEX idx_results_scan_id ON scan_results(scan_id);
```

## 🐛 Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Check what's using the port
sudo netstat -tulpn | grep :3000

# Kill the process
sudo kill -9 <PID>
```

#### Permission Denied
```bash
# Fix script permissions
chmod +x setup.sh
sudo chown -R $USER:$USER /path/to/cybersage
```

#### Module Not Found
```bash
# Recreate virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Nmap Not Found
```bash
# Install Nmap
sudo apt install nmap

# Verify installation
which nmap
nmap --version
```

### Debug Mode

```bash
# Enable debug logging
export FLASK_ENV=development
export LOG_LEVEL=DEBUG

# Run with verbose output
python3 app.py --verbose
```

### Log Analysis

```bash
# View application logs
tail -f logs/cybersage.log

# Monitor real-time logs
tail -f logs/access.log | grep ERROR
```

## 🔐 Security Considerations

### Production Deployment
1. **Change default passwords** and API keys
2. **Enable HTTPS** with proper SSL certificates
3. **Implement authentication** and authorization
4. **Use environment variables** for sensitive data
5. **Regular security updates** for all components
6. **Network segmentation** for scanning isolated networks
7. **Audit logging** for all security activities

### Compliance
- **OWASP Top 10** vulnerability coverage
- **NIST Cybersecurity Framework** alignment
- **ISO 27001** security management standards
- **SOC 2 Type II** compliance ready

## 🚀 Advanced Features

### Custom Tool Integration
```python
# Add custom security tool
from cybersage.tools import BaseTool

class CustomScanner(BaseTool):
    def __init__(self):
        super().__init__("custom_scanner", "1.0.0")
    
    def scan(self, target):
        # Your custom scanning logic
        return {"vulnerabilities": []}
```

### Scheduled Scanning
```bash
# Create automated scan schedules
python3 tools/scheduler.py --add "nightly_scan" --time "02:00" --targets "192.168.1.0/24"
```

### Report Automation
```python
# Generate automated reports
from cybersage.reports import ReportGenerator

generator = ReportGenerator()
pdf_report = generator.generate_pdf(scan_id="123", template="executive")
```

## 📚 Additional Documentation

- **[INSTALLATION.md](INSTALLATION.md)** - Detailed installation guide with troubleshooting
- **[TOOLS.md](TOOLS.md)** - Comprehensive documentation for all security tools
- **[QUICK-START.md](QUICK-START.md)** - 30-second quick start guide
- **[API_DOCS.md](API_DOCS.md)** - Complete API reference documentation

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone for development
git clone https://github.com/your-username/CyberSage-2.0.git
cd CyberSage-2.0

# Install development dependencies
pip install -r requirements-dev.txt
npm install

# Run tests
npm test
python3 -m pytest tests/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Community Support
- **GitHub Issues**: [Report bugs and feature requests](https://github.com/your-username/CyberSage-2.0/issues)
- **Discussions**: [Community forum and Q&A](https://github.com/your-username/CyberSage-2.0/discussions)
- **Wiki**: [Documentation and tutorials](https://github.com/your-username/CyberSage-2.0/wiki)

### Professional Support
- **Enterprise Support**: [Contact us for enterprise solutions](mailto:support@cybersage.com)
- **Training**: [Professional training and certification programs](https://cybersage.com/training)
- **Consulting**: [Security consulting and penetration testing services](https://cybersage.com/consulting)

## 🏆 Acknowledgments

- **Nmap Team** - For the industry-standard network scanner
- **Nikto Team** - For web vulnerability scanning capabilities
- **OWASP Community** - For security best practices and guidelines
- **Python Community** - For the robust backend framework
- **React Team** - For the modern frontend framework
- **All Contributors** - For their valuable contributions to the project

---

**CyberSage 2.0** - Empowering cybersecurity professionals with advanced vulnerability scanning capabilities.

*Built with ❤️ by the @ashfiexe*

**Version**: 2.0.0  
**Last Updated**: October 2025  
**Documentation Version**: 1.0
# 🚀 CyberSage 2.0 - Quick Start Guide

> **Get your professional cybersecurity scanner running in under 30 seconds!**

## ⚡ One-Command Installation

### Linux/Mac
```bash
git clone <your-repo-url> CyberSage-2.0
cd CyberSage-2.0
chmod +x setup.sh && ./setup.sh
```

**🎯 That's it! Your scanner will be running at `http://localhost:3000`**

---

## 🛠️ Professional Security Tools Included

| 🔍 **Tool** | ⚡ **Purpose** | ⏱️ **Scan Time** |
|-------------|----------------|-------------------|
| **Nmap Scanner** | Network Discovery | 2-10 min |
| **Vulnerability Scanner** | Security Assessment | 5-60 min |
| **Security Header Scanner** | HTTP Security | 1-3 min |
| **Web Crawler** | Site Discovery | 3-15 min |
| **Form Discovery** | Input Analysis | 2-5 min |
| **Fuzzer** | Input Testing | 5-30 min |
| **Chain Detector** | Attack Analysis | 1-10 min |
| **Payload Generator** | Exploit Creation | 1-5 min |
| **Reconnaissance** | Info Gathering | 2-20 min |
| **AI Analyzer** | Smart Analysis | 1-5 min |

**+ 5 More Advanced Tools:** API Security, Business Logic, SSL/TLS, Professional Testing

---

## 📊 What You'll Get

### 🌐 **Modern Web Interface**
- **📊 Dashboard**: Real-time scan monitoring
- **🎛️ Scanner**: 15+ professional tools
- **🚨 Vulnerabilities**: Detailed security analysis
- **🔗 Attack Chains**: Vulnerability correlation
- **📈 Reports**: Professional PDF/JSON exports

### ⚡ **Performance Features**
- **Real-time Updates**: WebSocket-powered live scanning
- **AI-Powered**: Intelligent vulnerability scoring
- **Dark/Light Theme**: Professional UI with accessibility
- **Mobile Responsive**: Works on all devices
- **Export Ready**: Multiple report formats

---

## 🎯 Installation Methods (Choose One)

### Method 1: Automated Setup Scripts ⭐ **RECOMMENDED**
```bash
# Linux/Mac
chmod +x setup.sh
./setup.sh
```
**✨ Features**: Professional installation, health checks, automatic startup, security tools setup

### Method 2: Docker (Instant)
```bash
docker-compose up --build -d
```
**✨ Features**: Zero configuration, isolated environment

### Method 3: Manual Installation
```bash
# Backend
cd backend && pip install -r requirements.txt && python app.py &

# Frontend (new terminal)
cd frontend && npm install && npm run dev
```
**✨ Features**: Full control, custom configuration

---

## 🏃‍♂️ Post-Installation

### 1. **Open Your Browser**
Navigate to: **http://localhost:3000**

### 2. **Quick Test Scan**
- Click "New Scan"
- Enter target URL (e.g., `https://example.com`)
- Select scan type (Quick/Standard/Deep)
- Click "Start Scan"

### 3. **View Results**
- Real-time progress in dashboard
- Detailed vulnerability analysis
- Professional export options

---

## 🔧 System Requirements

### **Minimum**
- **OS**: Linux (Ubuntu 18.04+, CentOS 8+, Debian 10+) or macOS (10.15+)
- **RAM**: 4GB
- **Storage**: 2GB free space
- **Network**: Internet for dependencies

### **Recommended**
- **OS**: Ubuntu 20.04+ or macOS 11+
- **RAM**: 8GB
- **Storage**: SSD recommended
- **CPU**: Multi-core processor

### **Software**
- **Python**: 3.10+ (auto-installed by setup)
- **Node.js**: 18+ (auto-installed by setup)
- **Git**: For cloning repository
- **Homebrew**: For macOS (auto-installed by setup)

---

## 🛡️ Security Tools Auto-Installed

The setup script automatically installs and configures:

### **Network Security**
- **Nmap**: Port scanning and network discovery
- **Netcat**: Network utility and debugging

### **Web Application Security**
- **Nikto**: Web vulnerability scanner
- **Dirb**: Web content scanner
- **Gobuster**: Directory/file brute-forcing

### **Database Security**
- **SQLMap**: Automatic SQL injection detection

### **Password Security**
- **Hydra**: Network login brute-forcing
- **John**: Password hash cracking

### **WordPress Security**
- **WPScan**: WordPress security scanner

---

## 🆘 Quick Troubleshooting

### Port Issues
```bash
# Kill processes on ports 3000/5000
lsof -ti:3000 | xargs kill -9
lsof -ti:5000 | xargs kill -9

# Alternative method
fuser -k 3000/tcp 5000/tcp
```

### Permission Issues
```bash
# Make scripts executable
chmod +x setup.sh

# Fix ownership (if needed)
sudo chown -R $USER:$USER .
```

### Dependencies Issues
```bash
# Clear and reinstall
rm -rf node_modules backend/venv
./setup.sh

# Force clean installation
./setup.sh --clean-install
```

### Service Management
```bash
# Check running processes
ps aux | grep -E "(node|python)" | grep -v grep

# Stop all services
kill $(cat backend.pid frontend.pid 2>/dev/null) 2>/dev/null || true

# Restart services
./setup.sh
```

### Health Check
```bash
# Verify backend
curl http://localhost:5000/api/health

# Verify frontend
curl http://localhost:3000

# View logs
tail -f backend.log frontend.log
```

---

## 📈 Professional Features

### 🔒 **Security Capabilities**
- ✅ **Vulnerability Assessment**: SQLi, XSS, CSRF, File Inclusion
- ✅ **Network Discovery**: Port scanning, service enumeration
- ✅ **SSL/TLS Analysis**: Certificate validation, cipher analysis
- ✅ **API Security**: REST/GraphQL security testing
- ✅ **Business Logic**: Workflow bypass detection
- ✅ **Attack Chains**: Vulnerability correlation

### 🤖 **AI-Powered Features**
- ✅ **Smart Scoring**: ML-based vulnerability assessment
- ✅ **False Positive Reduction**: Intelligent filtering
- ✅ **Attack Pattern Recognition**: Behavioral analysis
- ✅ **Trend Analysis**: Historical data insights

### 📊 **Professional Reporting**
- ✅ **Multiple Formats**: PDF, JSON, CSV, XML
- ✅ **CVSS Scoring**: Industry-standard vulnerability scoring
- ✅ **Executive Summaries**: Business-focused reports
- ✅ **Technical Details**: In-depth analysis for developers

---

## 🎯 Next Steps

### 1. **Explore the Interface**
- Dashboard overview and navigation
- Tool configuration and settings
- Scan history and management
- Reports section and exports

### 2. **Run Your First Scan**
- Choose a safe target (your own website)
- Start with "Quick Scan" for testing
- Monitor real-time progress
- Review detailed results

### 3. **Customize Settings**
- Adjust scan parameters and timing
- Configure notification preferences
- Set up export formats and templates
- Customize UI theme and layout

### 4. **Advanced Usage**
- API integration for automation
- Batch scanning for multiple targets
- Custom payload development
- Report automation and scheduling

---

## 🔍 Quick Scan Examples

### Network Discovery
```bash
# Basic network scan (via web interface)
Target: 192.168.1.0/24
Scan Type: Network Discovery
Tools: Nmap, Port Scanner
Duration: 5-15 minutes
```

### Web Application Testing
```bash
# Web application scan (via web interface)
Target: https://example.com
Scan Type: Web Application Security
Tools: Vulnerability Scanner, Security Headers
Duration: 10-30 minutes
```

### Comprehensive Security Assessment
```bash
# Full security audit (via web interface)
Target: https://target.com
Scan Type: Comprehensive Security Audit
Tools: All 15+ security tools
Duration: 30-120 minutes
```

---

## 📞 Support & Resources

### 📖 **Documentation**
- **[Installation Guide](./INSTALLATION.md)**: Detailed setup instructions
- **[Tools Documentation](./TOOLS.md)**: Complete tool reference
- **[API Documentation](./README.md)**: Developer resources

### 🔧 **Quick Commands**
```bash
# View real-time logs
tail -f backend.log frontend.log

# Check service status
ps aux | grep -E "(node|python)" | grep -v grep

# Stop services gracefully
kill $(cat backend.pid frontend.pid)

# Restart with setup script
./setup.sh

# Health check endpoints
curl http://localhost:5000/api/health
curl http://localhost:3000

# Resource monitoring
top -p $(pgrep -f "python|node")
```

### 🌐 **Online Resources**
- **GitHub Repository**: [Project source and issues](https://github.com/your-username/CyberSage-2.0)
- **Community Discussions**: [Q&A and support](https://github.com/your-username/CyberSage-2.0/discussions)
- **Documentation Wiki**: [Extended documentation](https://github.com/your-username/CyberSage-2.0/wiki)

### 📧 **Getting Help**
1. Check the troubleshooting section above
2. Review installation logs for errors
3. Verify system requirements are met
4. Consult the detailed documentation
5. Create a GitHub issue with system details

---

## 🎉 Success Indicators

After successful installation, you should see:

- ✅ **Browser loads**: http://localhost:3000 displays the CyberSage dashboard
- ✅ **Backend responds**: http://localhost:5000/api/health returns JSON
- ✅ **No console errors**: Clean browser developer console
- ✅ **Tools accessible**: All 15+ security tools are available in the interface
- ✅ **Real-time updates**: WebSocket connection established for live scanning

**🎊 Congratulations! Your professional cybersecurity scanner is ready to use!**

---

**🛡️ Remember**: Always scan only systems you own or have explicit permission to test.

**⚡ Ready to secure your digital assets? Start your first scan now!**
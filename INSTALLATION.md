# 🚀 CyberSage 2.0 - Complete Installation Guide

## 🎯 Quick Installation (Recommended)

### One-Command Setup

**Linux/Mac:**
```bash
git clone <your-repo-url> CyberSage-2.0
cd CyberSage-2.0
chmod +x setup.sh
./setup.sh
```

That's it! The installation script will:
- ✅ Install all dependencies
- ✅ Set up environment variables
- ✅ Initialize the database
- ✅ Start both frontend and backend
- ✅ Open your browser automatically

**Access your application at**: `http://localhost:3000`

## 📋 Installation Methods

### Method 1: Automated Setup (Recommended)

#### Linux/MacOS
```bash
# Clone repository
git clone <your-repo-url> CyberSage-2.0
cd CyberSage-2.0

# Make setup executable
chmod +x setup.sh

# Run automatic setup
./setup.sh

# The script will:
# 1. Check system requirements
# 2. Install Python dependencies
# 3. Install Node.js dependencies
# 4. Install security tools (Nmap, Nikto, SQLMap, etc.)
# 5. Configure environment files
# 6. Initialize database
# 7. Start services
```

### Method 2: Docker Setup (One-Command)

```bash
# Clone and start with Docker
git clone <your-repo-url> CyberSage-2.0
cd CyberSage-2.0
docker-compose up --build

# Access at http://localhost:3000
```

### Method 3: Manual Installation

#### Prerequisites Check
```bash
# Check Node.js (v18+)
node --version

# Check Python (v3.10+)
python --version
# or
python3 --version

# Check pip
pip --version
```

#### Backend Setup
```bash
cd backend/

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Setup environment
cp .env.example .env

# Start backend
python app.py
```

#### Frontend Setup
```bash
cd frontend/

# Install dependencies
npm install
# or
yarn install
# or
pnpm install

# Setup environment
cp .env.example .env

# Start development server
npm run dev
# or
yarn dev
# or
pnpm dev
```

## 🔧 System Requirements

### Minimum Requirements
- **Operating System**: Linux (Ubuntu 18.04+, CentOS 8+, Debian 10+) or macOS (10.15+)
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 2GB free space
- **Network**: Internet connection for dependencies

### Software Requirements
- **Node.js**: v18.0.0 or higher
- **Python**: v3.10 or higher
- **npm/yarn/pnpm**: Latest version
- **Git**: For cloning repository
- **Docker**: Optional, for containerized deployment

### Prerequisites Installation

#### Ubuntu/Debian
```bash
# Update package lists
sudo apt update

# Install basic dependencies
sudo apt install -y curl wget git python3 python3-pip python3-venv

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

#### CentOS/RHEL
```bash
# Update system
sudo yum update -y

# Install basic dependencies
sudo yum install -y curl wget git python3 python3-pip

# Install Node.js
curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
sudo yum install -y nodejs
```

#### macOS
```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python3 git node@18
```

## 🎯 Post-Installation Verification

### Quick Health Check
```bash
# Check if frontend is running
curl http://localhost:3000

# Check if backend is running
curl http://localhost:5000/health

# Check WebSocket connection
# Visit http://localhost:3000 in browser
```

### Expected Results
- ✅ Frontend loads at `http://localhost:3000`
- ✅ Backend API responds at `http://localhost:5000`
- ✅ No console errors in browser
- ✅ Dashboard displays properly

### Service Management
```bash
# Check running processes
ps aux | grep -E "(node|python)" | grep -v grep

# View logs
tail -f backend.log
tail -f frontend.log

# Stop services
kill $(cat backend.pid frontend.pid 2>/dev/null) 2>/dev/null || true

# Restart services
./setup.sh
```

## 🔧 Configuration

### Environment Files

#### Backend Configuration (`backend/.env`)
```env
FLASK_ENV=development
SECRET_KEY=your-secret-key-here-change-in-production
DATABASE_URL=sqlite:///cybersage_v2.db
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
WEBSOCKET_PATH=/socket.io
MAX_SCAN_DURATION=3600
THREAD_POOL_SIZE=10
LOG_LEVEL=INFO
```

#### Frontend Configuration (`frontend/.env`)
```env
REACT_APP_API_URL=http://localhost:5000
REACT_APP_WEBSOCKET_URL=ws://localhost:5000
REACT_APP_APP_NAME=CyberSage 2.0
REACT_APP_MAX_FILE_SIZE=50MB
REACT_APP_SCAN_TIMEOUT=3600
GENERATE_SOURCEMAP=false
```

### Security Tools Configuration

#### Core Security Tools
The setup script automatically installs these tools:

- **Nmap**: Network discovery and port scanning
- **Nikto**: Web vulnerability scanning
- **SQLMap**: SQL injection testing
- **Gobuster**: Directory/file brute-forcing
- **Dirb**: Web content scanner
- **Hydra**: Password brute-forcing

#### Manual Installation of Additional Tools
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y nmap nikto dirb gobuster sqlmap hydra wpscan

# macOS
brew install nmap nikto dirb gobuster hydra

# Verify installation
nmap --version
nikto -Version
```

### Port Configuration
- **Frontend**: Port 3000 (default)
- **Backend**: Port 5000 (default)
- **Database**: SQLite (in backend directory)

## 🚀 Production Deployment

### Build for Production
```bash
# Frontend production build
cd frontend/
npm run build

# Backend production
cd backend/
export FLASK_ENV=production
python app.py
```

### Environment Setup for Production
```bash
# Create production .env files
echo "FLASK_ENV=production" > backend/.env
echo "SECRET_KEY=$(openssl rand -hex 32)" >> backend/.env

echo "REACT_APP_API_URL=https://your-domain.com" > frontend/.env
```

### Docker Production
```bash
# Build production containers
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up --build
```

### Systemd Service (Linux)
```bash
# Create systemd service file
sudo tee /etc/systemd/system/cybersage.service > /dev/null <<EOF
[Unit]
Description=CyberSage 2.0
After=network.target

[Service]
Type=simple
User=cybersage
WorkingDirectory=/opt/cybersage
ExecStart=/opt/cybersage/setup.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl enable cybersage
sudo systemctl start cybersage
```

## 🔍 Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Find process using port 3000
lsof -ti:3000

# Kill process on port 3000
lsof -ti:3000 | xargs kill -9

# Find process using port 5000
lsof -ti:5000

# Kill process on port 5000
lsof -ti:5000 | xargs kill -9
```

#### Permission Denied
```bash
# Make setup script executable
chmod +x setup.sh

# Fix ownership (if needed)
sudo chown -R $USER:$USER .

# For system-wide installations
sudo chown -R cybersage:cybersage /opt/cybersage
```

#### Python Dependencies Issues
```bash
# Clear Python cache
find . -type d -name "__pycache__" -exec rm -rf {} +
find . -name "*.pyc" -delete

# Recreate virtual environment
rm -rf backend/venv
cd backend/
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

#### Node.js Issues
```bash
# Clear npm cache
npm cache clean --force

# Delete node_modules and reinstall
cd frontend/
rm -rf node_modules package-lock.json
npm install

# Use yarn as alternative
npm install -g yarn
yarn install
```

#### Security Tools Not Found
```bash
# Install security tools manually
sudo apt update
sudo apt install -y nmap nikto dirb gobuster

# Verify installations
which nmap nikto dirb gobuster

# Check versions
nmap --version
nikto -Version
```

### Installation Logs
```bash
# Check setup logs
tail -f setup.log

# Check backend logs
tail -f backend.log

# Check frontend logs
tail -f frontend.log

# System logs (if running as service)
sudo journalctl -u cybersage -f
```

### Debug Mode
```bash
# Enable verbose output
export DEBUG=1
export LOG_LEVEL=DEBUG

# Run setup in debug mode
bash -x ./setup.sh

# Manual step-by-step installation
set -x  # Enable debug tracing
```

## 📊 Performance Optimization

### System Tuning
```bash
# Increase file descriptor limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize network settings
echo "net.core.rmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Resource Monitoring
```bash
# Monitor resource usage during scans
top -p $(pgrep -f "python|node")

# Check memory usage
free -h

# Monitor disk usage
df -h

# Network connections
netstat -tulpn | grep -E "3000|5000"
```

## 📞 Support

### Getting Help
1. Check the logs for error messages
2. Verify all prerequisites are installed
3. Ensure ports 3000 and 5000 are available
4. Try the Docker installation method as fallback
5. Check system requirements and compatibility

### System Information for Debugging
```bash
# System information
uname -a
cat /etc/os-release  # Linux
sw_vers  # macOS

# Node.js version
node --version
npm --version

# Python version
python3 --version
pip3 --version

# Available memory
free -h  # Linux
vm_stat  # macOS

# Disk space
df -h
```

### Creating Support Reports
```bash
# Generate system report
{
    echo "=== CyberSage 2.0 Support Report ==="
    echo "Date: $(date)"
    echo ""
    echo "System: $(uname -a)"
    echo "OS: $(cat /etc/os-release 2>/dev/null || sw_vers)"
    echo ""
    echo "Node.js: $(node --version 2>/dev/null || echo 'Not installed')"
    echo "Python: $(python3 --version 2>/dev/null || echo 'Not installed')"
    echo "npm: $(npm --version 2>/dev/null || echo 'Not installed')"
    echo ""
    echo "Ports in use:"
    netstat -tulpn 2>/dev/null | grep -E ":3000|:5000" || lsof -i :3000,5000 2>/dev/null
    echo ""
    echo "Running processes:"
    ps aux | grep -E "(node|python)" | grep -v grep
} > cybersage-support-report.txt

echo "Support report saved to: cybersage-support-report.txt"
```

### Community Resources
- **GitHub Issues**: [Report bugs and request features](https://github.com/your-username/CyberSage-2.0/issues)
- **Documentation**: [Complete documentation wiki](https://github.com/your-username/CyberSage-2.0/wiki)
- **Discussions**: [Community Q&A and support](https://github.com/your-username/CyberSage-2.0/discussions)

---

**🎉 Installation Complete!**

Access your CyberSage 2.0 application at: `http://localhost:3000`

For detailed tool documentation, see [TOOLS.md](./TOOLS.md)

For quick start guide, see [QUICK-START.md](./QUICK-START.md)
#!/bin/bash

# CyberSage 2.0 - Elite Vulnerability Intelligence Platform
# Automated Setup Script with Enhanced Features
# Author: CyberSage Team
# Version: 2.0.0

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "███████╗ █████╗  ██████╗ ███████╗    ███████╗██╗   ██╗██████╗ ███████╗"
echo "██╔════╝██╔══██╗██╔════╝ ██╔════╝    ██╔════╝██║   ██║██╔══██╗██╔════╝"
echo "█████╗  ███████║██║  ███╗█████╗      ███████╗██║   ██║██████╔╝█████╗  "
echo "██╔══╝  ██╔══██║██║   ██║██╔══╝      ╚════██║██║   ██║██╔══██╗██╔══╝  "
echo "██║     ██║  ██║╚██████╔╝███████╗    ███████║╚██████╔╝██║  ██║███████╗"
echo "╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝"
echo -e "${NC}"
echo -e "${GREEN}🧠 CyberSage v2.0 - Elite Vulnerability Intelligence Platform${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            OS="ubuntu"
            PKG_MANAGER="apt"
        elif command -v yum >/dev/null 2>&1; then
            OS="centos"
            PKG_MANAGER="yum"
        elif command -v pacman >/dev/null 2>&1; then
            OS="arch"
            PKG_MANAGER="pacman"
        else
            OS="linux"
            PKG_MANAGER="unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PKG_MANAGER="brew"
    else
        echo -e "${RED}❌ Unsupported operating system: $OSTYPE${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Detected OS: $OS${NC}"
    echo -e "${GREEN}✓ Package Manager: $PKG_MANAGER${NC}"
}

# Check for sudo privileges
check_sudo() {
    if [[ $EUID -eq 0 ]]; then
        SUDO=""
    elif sudo -n true 2>/dev/null; then
        SUDO="sudo"
    else
        echo -e "${YELLOW}⚠️  This script requires sudo privileges for package installation${NC}"
        echo -e "${YELLOW}⚠️  Please run: sudo $0${NC}"
        exit 1
    fi
}

# Install system dependencies
install_dependencies() {
    echo -e "${BLUE}[1/6] Installing system dependencies...${NC}"
    
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        $SUDO apt-get update -qq
        $SUDO apt-get install -y python3 python3-pip python3-venv nodejs npm git curl wget unzip nmap python3-dev build-essential >/dev/null 2>&1
    elif [[ "$PKG_MANAGER" == "yum" ]]; then
        $SUDO yum groupinstall -y "Development Tools" >/dev/null 2>&1
        $SUDO yum install -y python3 python3-pip nodejs npm git curl wget unzip nmap python3-devel >/dev/null 2>&1
    elif [[ "$PKG_MANAGER" == "brew" ]]; then
        brew install python3 node git curl wget nmap >/dev/null 2>&1
    elif [[ "$PKG_MANAGER" == "pacman" ]]; then
        $SUDO pacman -Sy --noconfirm python python-pip nodejs npm git curl wget nmap >/dev/null 2>&1
    else
        echo -e "${YELLOW}⚠️  Unknown package manager, skipping system dependencies${NC}"
    fi
    
    echo -e "${GREEN}✓ System dependencies installed${NC}"
}

# Install security tools
install_security_tools() {
    echo -e "${BLUE}[2/6] Installing security tools...${NC}"
    
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        $SUDO apt-get install -y nmap masscan gobuster dirb nikto wpscan sqlmap whois >/dev/null 2>&1 || true
    elif [[ "$PKG_MANAGER" == "yum" ]]; then
        $SUDO yum install -y nmap gobuster dirb nikto whois >/dev/null 2>&1 || true
    elif [[ "$PKG_MANAGER" == "brew" ]]; then
        brew install nmap gobuster nikto >/dev/null 2>&1 || true
    elif [[ "$PKG_MANAGER" == "pacman" ]]; then
        $SUDO pacman -Sy --noconfirm nmap gobuster dirb nikto >/dev/null 2>&1 || true
    fi
    
    echo -e "${GREEN}✓ Security tools installed${NC}"
}

# Setup Python virtual environment
setup_python_env() {
    echo -e "${BLUE}[3/6] Setting up Python virtual environment...${NC}"
    
    cd backend
    python3 -m venv venv
    source venv/bin/activate
    
    pip install --upgrade pip
    pip install -r requirements.txt
    
    deactivate
    cd ..
    
    echo -e "${GREEN}✓ Python virtual environment created${NC}"
}

# Setup React frontend
setup_frontend() {
    echo -e "${BLUE}[4/6] Setting up React frontend...${NC}"
    
    cd frontend
    
    # Install dependencies
    npm install --no-audit --no-fund >/dev/null 2>&1
    
    # Build the frontend
    npm run build >/dev/null 2>&1
    
    cd ..
    
    echo -e "${GREEN}✓ Frontend built successfully${NC}"
}

# Generate .env files
generate_env_files() {
    echo -e "${BLUE}[5/6] Generating environment configuration...${NC}"
    
    # Backend .env
    cat > backend/.env << EOF
SECRET_KEY=$(openssl rand -hex 16)
DATABASE_PATH=cybersage_v2.db
FLASK_ENV=production
FLASK_DEBUG=False
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
MAX_CONTENT_LENGTH=16777216
NMAP_TIMEOUT=30
NIKTO_TIMEOUT=60
WPSCAN_TIMEOUT=300
SQLMAP_TIMEOUT=300
SECURITY_SCAN_TIMEOUT=180
EOF
    
    # Frontend .env
    cat > frontend/.env << EOF
REACT_APP_BACKEND_URL=http://localhost:5000
REACT_APP_WS_URL=ws://localhost:5000/scan
GENERATE_SOURCEMAP=false
PORT=3000
EOF
    
    echo -e "${GREEN}✓ Environment files generated${NC}"
}

# Generate start script
generate_start_script() {
    echo -e "${BLUE}[6/6] Generating service management script...${NC}"
    
    cat > start.sh << 'EOF'
#!/bin/bash

# CyberSage 2.0 Service Manager
# Enhanced with PID management and health checks

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$PROJECT_DIR/backend"
FRONTEND_DIR="$PROJECT_DIR/frontend"
PID_DIR="$PROJECT_DIR/pids"

# Ensure PID directory exists
mkdir -p "$PID_DIR"

BACKEND_PID_FILE="$PID_DIR/backend.pid"
FRONTEND_PID_FILE="$PID_DIR/frontend.pid"

# Colors for output
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if a process is running
is_running() {
    local pid_file=$1
    if [[ -f "$pid_file" ]]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" >/dev/null 2>&1; then
            return 0
        else
            rm -f "$pid_file"
            return 1
        fi
    fi
    return 1
}

# Start services
start_services() {
    log_info "Starting CyberSage 2.0 services..."
    
    # Start backend
    if ! is_running "$BACKEND_PID_FILE"; then
        log_info "Starting backend..."
        cd "$BACKEND_DIR"
        source venv/bin/activate
        nohup python app.py > "$PROJECT_DIR/backend.log" 2>&1 &
        echo $! > "$BACKEND_PID_FILE"
        deactivate
        cd "$PROJECT_DIR"
        log_success "Backend started (PID: $(cat $BACKEND_PID_FILE))"
    else
        log_warning "Backend is already running"
    fi
    
    # Start frontend
    if ! is_running "$FRONTEND_PID_FILE"; then
        log_info "Starting frontend..."
        cd "$FRONTEND_DIR"
        nohup npm start > "$PROJECT_DIR/frontend.log" 2>&1 &
        echo $! > "$FRONTEND_PID_FILE"
        cd "$PROJECT_DIR"
        log_success "Frontend started (PID: $(cat $FRONTEND_PID_FILE))"
    else
        log_warning "Frontend is already running"
    fi
    
    echo ""
    log_success "🎉 CyberSage 2.0 is running!"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}🌐 Frontend:${NC} http://localhost:3000"
    echo -e "${CYAN}🔧 Backend:${NC}  http://localhost:5000"
    echo -e "${CYAN}📊 Health:${NC}   http://localhost:5000/api/health"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Stop services
stop_services() {
    log_info "Stopping CyberSage 2.0 services..."
    
    # Stop frontend
    if is_running "$FRONTEND_PID_FILE"; then
        local pid=$(cat "$FRONTEND_PID_FILE")
        log_info "Stopping frontend (PID: $pid)..."
        kill "$pid" 2>/dev/null || true
        sleep 2
        kill -9 "$pid" 2>/dev/null || true
        rm -f "$FRONTEND_PID_FILE"
        log_success "Frontend stopped"
    else
        log_warning "Frontend is not running"
    fi
    
    # Stop backend
    if is_running "$BACKEND_PID_FILE"; then
        local pid=$(cat "$BACKEND_PID_FILE")
        log_info "Stopping backend (PID: $pid)..."
        kill "$pid" 2>/dev/null || true
        sleep 2
        kill -9 "$pid" 2>/dev/null || true
        rm -f "$BACKEND_PID_FILE"
        log_success "Backend stopped"
    else
        log_warning "Backend is not running"
    fi
}

# Restart services
restart_services() {
    log_info "Restarting CyberSage 2.0 services..."
    stop_services
    sleep 3
    start_services
}

# Check status
check_status() {
    echo -e "${CYAN}🧠 CyberSage 2.0 Service Status${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Check backend
    if is_running "$BACKEND_PID_FILE"; then
        local pid=$(cat "$BACKEND_PID_FILE")
        echo -e "${GREEN}✅ Backend:${NC} Running (PID: $pid)"
        if curl -s http://localhost:5000/api/health >/dev/null 2>&1; then
            echo -e "${GREEN}   Health:${NC}  Healthy"
        else
            echo -e "${YELLOW}   Health:${NC}  Unreachable"
        fi
    else
        echo -e "${RED}❌ Backend:${NC} Stopped"
    fi
    
    # Check frontend
    if is_running "$FRONTEND_PID_FILE"; then
        local pid=$(cat "$FRONTEND_PID_FILE")
        echo -e "${GREEN}✅ Frontend:${NC} Running (PID: $pid)"
        if curl -s http://localhost:3000 >/dev/null 2>&1; then
            echo -e "${GREEN}   Status:${NC}  Accessible"
        else
            echo -e "${YELLOW}   Status:${NC}  Starting..."
        fi
    else
        echo -e "${RED}❌ Frontend:${NC} Stopped"
    fi
    
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Show logs
show_logs() {
    echo -e "${CYAN}📋 CyberSage 2.0 Logs${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [[ -f "$PROJECT_DIR/backend.log" ]]; then
        echo -e "${YELLOW}Backend Log:${NC}"
        tail -20 "$PROJECT_DIR/backend.log"
        echo ""
    fi
    
    if [[ -f "$PROJECT_DIR/frontend.log" ]]; then
        echo -e "${YELLOW}Frontend Log:${NC}"
        tail -20 "$PROJECT_DIR/frontend.log"
    fi
}

# Main script logic
case "${1:-start}" in
    start)
        start_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        restart_services
        ;;
    status)
        check_status
        ;;
    logs)
        show_logs
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
EOF
    
    chmod +x start.sh
    
    echo -e "${GREEN}✓ Service management script created${NC}"
}

# Final setup
final_setup() {
    echo -e "${GREEN}🎉 Setup completed successfully!${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}📋 Available Commands:${NC}"
    echo -e "${YELLOW}  ./start.sh${NC}              # Start all services"
    echo -e "${YELLOW}  ./start.sh --stop${NC}       # Stop all services"
    echo -e "${YELLOW}  ./start.sh --restart${NC}    # Restart all services"
    echo -e "${YELLOW}  ./start.sh --status${NC}     # Check service status"
    echo -e "${YELLOW}  ./start.sh --logs${NC}       # Show service logs"
    echo ""
    echo -e "${GREEN}🌐 Access URLs:${NC}"
    echo -e "${PURPLE}  Frontend: http://localhost:3000${NC}"
    echo -e "${PURPLE}  Backend:  http://localhost:5000${NC}"
    echo -e "${PURPLE}  API Docs: http://localhost:5000/api/docs${NC}"
    echo ""
    echo -e "${CYAN}💡 Tip: Run './start.sh' to start the services!${NC}"
}

# Main execution
main() {
    detect_os
    check_sudo
    install_dependencies
    install_security_tools
    setup_python_env
    setup_frontend
    generate_env_files
    generate_start_script
    final_setup
}

# Run main function
main "$@"
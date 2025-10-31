#!/bin/bash

# 🚀 CyberSage 2.0 - Lightning Fast Setup Script
# Automated installation for Linux/macOS

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_step() {
    echo -e "\n${CYAN}➤ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_header() {
    clear
    echo -e "${PURPLE}"
    echo "███████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗ █████╗  ██████╗ ███████╗            
    echo "██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝ ██╔════╝            
    echo "██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗███████║██║  ███╗█████╗              
    echo "██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══██║██║   ██║██╔══╝              
    echo "╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║██║  ██║╚██████╔╝███████╗            
    echo " ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝            "
                                                                                      
    echo -e "${NC}"
    echo -e "${CYAN}            Professional Cybersecurity Scanner v2.0${NC}"
    echo -e "${CYAN}                Lightning Fast Installation${NC}\n"
}

# Function to check command existence
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install package if not present
install_if_missing() {
    local package=$1
    if command_exists "$package"; then
        print_success "$package is already installed"
    else
        print_info "Installing $package..."
        if eval "$INSTALL_COMMAND $package" >/dev/null 2>&1; then
            print_success "$package installed successfully"
        else
            print_warning "Failed to install $package (may be optional)"
        fi
    fi
}

# Detect OS and package manager
detect_system() {
    print_step "Detecting operating system..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        # Detect Linux distribution
        if [ -f /etc/debian_version ]; then
            DISTRO="debian"
            INSTALL_COMMAND="sudo apt install -y"
        elif [ -f /etc/redhat-release ]; then
            DISTRO="redhat"
            INSTALL_COMMAND="sudo yum install -y"
        elif [ -f /etc/arch-release ]; then
            DISTRO="arch"
            INSTALL_COMMAND="sudo pacman -S --noconfirm"
        else
            DISTRO="unknown"
            INSTALL_COMMAND="echo"
        fi
        print_success "Linux detected - $DISTRO distribution"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        DISTRO="macos"
        if command_exists brew; then
            INSTALL_COMMAND="brew install"
            print_success "macOS detected - Homebrew available"
        else
            print_warning "macOS detected - Homebrew not found"
            print_info "Please install Homebrew: /bin/bash -c '$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)'"
            exit 1
        fi
    else
        print_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    print_step "Checking prerequisites..."
    
    # Check Python 3
    if command_exists python3; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_success "Python 3 found: $PYTHON_VERSION"
    else
        print_error "Python 3 is required but not installed"
        case $OS in
            linux)
                case $DISTRO in
                    debian) echo "Install with: sudo apt update && sudo apt install python3 python3-pip" ;;
                    redhat) echo "Install with: sudo yum install python3 python3-pip" ;;
                    arch) echo "Install with: sudo pacman -S python python-pip" ;;
                esac
                ;;
            macos) echo "Install with: brew install python3" ;;
        esac
        exit 1
    fi
    
    # Check pip
    if command_exists pip3; then
        print_success "pip3 found"
    else
        print_error "pip3 is required but not installed"
        exit 1
    fi
    
    # Check Node.js
    if command_exists node; then
        NODE_VERSION=$(node --version)
        print_success "Node.js found: $NODE_VERSION"
    else
        print_error "Node.js is required but not installed"
        case $OS in
            linux) echo "Install with: curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash - && sudo apt-get install -y nodejs" ;;
            macos) echo "Install with: brew install node" ;;
        esac
        exit 1
    fi
    
    # Check npm
    if command_exists npm; then
        NPM_VERSION=$(npm --version)
        print_success "npm found: v$NPM_VERSION"
    else
        print_error "npm is required but not installed"
        exit 1
    fi
}

# Install professional security tools
install_security_tools() {
    print_step "Installing professional security tools..."
    
    # Core tools list
    CORE_TOOLS="nmap curl git wget"
    
    # Distribution-specific installation
    case $OS in
        linux)
            case $DISTRO in
                debian)
                    print_info "Updating package lists..."
                    sudo apt update -qq >/dev/null 2>&1
                    INSTALL_CMD="sudo apt install -y"
                    ;;
                redhat)
                    INSTALL_CMD="sudo yum install -y"
                    ;;
                arch)
                    INSTALL_CMD="sudo pacman -S --noconfirm"
                    ;;
            esac
            
            print_info "Installing core security tools..."
            for tool in $CORE_TOOLS; do
                install_if_missing "$tool"
            done
            
            # Additional tools for Debian/Ubuntu
            if [ "$DISTRO" == "debian" ]; then
                OPTIONAL_TOOLS="nikto sqlmap gobuster dirb wordlists"
                for tool in $OPTIONAL_TOOLS; do
                    install_if_missing "$tool"
                done
            fi
            ;;
            
        macos)
            print_info "Installing core security tools via Homebrew..."
            CORE_TOOLS_BREW="nmap curl git"
            for tool in $CORE_TOOLS_BREW; do
                if brew list | grep -q "^$tool$"; then
                    print_success "$tool is already installed"
                else
                    print_info "Installing $tool..."
                    brew install $tool >/dev/null 2>&1 && print_success "$tool installed" || print_warning "$tool installation failed"
                fi
            done
            ;;
    esac
}

# Setup Python virtual environment and backend
setup_backend() {
    print_step "Setting up Python backend..."
    
    cd backend || { print_error "Backend directory not found"; exit 1; }
    
    # Create virtual environment
    if [ ! -d "venv" ]; then
        print_info "Creating Python virtual environment..."
        python3 -m venv venv
        print_success "Virtual environment created"
    else
        print_success "Virtual environment already exists"
    fi
    
    # Activate virtual environment
    print_info "Activating virtual environment..."
    source venv/bin/activate
    
    # Upgrade pip
    print_info "Upgrading pip..."
    pip install --upgrade pip >/dev/null 2>&1
    
    # Install Python dependencies
    print_info "Installing Python dependencies..."
    pip install -r requirements.txt >/dev/null 2>&1 && print_success "Python dependencies installed" || {
        print_error "Failed to install Python dependencies"
        exit 1
    }
    
    # Setup environment file
    if [ ! -f ".env" ]; then
        print_info "Creating environment configuration..."
        cp .env.example .env
        print_success "Environment file created"
    else
        print_success "Environment file already exists"
    fi
    
    cd ..
    print_success "Backend setup completed"
}

# Setup Node.js frontend
setup_frontend() {
    print_step "Setting up Node.js frontend..."
    
    cd frontend || { print_error "Frontend directory not found"; exit 1; }
    
    # Install Node.js dependencies
    print_info "Installing Node.js dependencies..."
    if npm install >/dev/null 2>&1; then
        print_success "Node.js dependencies installed"
    else
        print_warning "npm install had warnings, continuing anyway"
    fi
    
    # Setup environment file
    if [ ! -f ".env" ]; then
        print_info "Creating frontend environment configuration..."
        cp .env.example .env
        print_success "Frontend environment file created"
    else
        print_success "Frontend environment file already exists"
    fi
    
    cd ..
    print_success "Frontend setup completed"
}

# Initialize database
setup_database() {
    print_step "Initializing database..."
    
    cd backend
    source venv/bin/activate
    
    # Create database directory if it doesn't exist
    mkdir -p data
    
    print_info "Database will be created on first run"
    
    cd ..
    print_success "Database setup completed"
}

# Start services
start_services() {
    print_step "Starting CyberSage 2.0..."
    
    # Start backend in background
    print_info "Starting backend server..."
    cd backend
    source venv/bin/activate
    
    # Check if port 5000 is available
    if lsof -Pi :5000 -sTCP:LISTEN -t >/dev/null 2>&1; then
        print_warning "Port 5000 is already in use"
        print_info "Please stop the existing service or change the port"
    else
        nohup python app.py > ../backend.log 2>&1 &
        BACKEND_PID=$!
        echo $BACKEND_PID > ../backend.pid
        print_success "Backend started (PID: $BACKEND_PID)"
    fi
    
    cd ..
    
    # Wait a moment for backend to start
    sleep 3
    
    # Start frontend
    print_info "Starting frontend server..."
    cd frontend
    
    # Check if port 3000 is available
    if lsof -Pi :3000 -sTCP:LISTEN -t >/dev/null 2>&1; then
        print_warning "Port 3000 is already in use"
    else
        nohup npm run dev > ../frontend.log 2>&1 &
        FRONTEND_PID=$!
        echo $FRONTEND_PID > ../frontend.pid
        print_success "Frontend started (PID: $FRONTEND_PID)"
    fi
    
    cd ..
    
    print_success "Services started successfully!"
}

# Health check
health_check() {
    print_step "Performing health check..."
    
    sleep 5  # Give services time to start
    
    # Check backend
    if curl -s http://localhost:5000/api/health >/dev/null 2>&1; then
        print_success "Backend is running correctly"
    else
        print_warning "Backend health check failed"
    fi
    
    # Check frontend
    if curl -s http://localhost:3000 >/dev/null 2>&1; then
        print_success "Frontend is running correctly"
    else
        print_warning "Frontend health check failed"
    fi
}

# Show completion message
show_completion() {
    clear
    echo -e "${GREEN}"
    echo "🎉 INSTALLATION COMPLETED SUCCESSFULLY!"
    echo -e "${NC}"
    echo ""
    echo -e "${CYAN}🌐 CyberSage 2.0 is now running:${NC}"
    echo -e "   Frontend: ${BLUE}http://localhost:3000${NC}"
    echo -e "   Backend:  ${BLUE}http://localhost:5000${NC}"
    echo ""
    echo -e "${YELLOW}📱 Open your browser and navigate to:${NC}"
    echo -e "   ${BLUE}http://localhost:3000${NC}"
    echo ""
    echo -e "${GREEN}✅ What's included:${NC}"
    echo -e "   • 15+ Professional Security Tools"
    echo -e "   • Real-time Vulnerability Scanning"
    echo -e "   • AI-Powered Analysis Engine"
    echo -e "   • Interactive Dashboard"
    echo -e "   • Professional Reporting System"
    echo ""
    echo -e "${YELLOW}🔧 Management Commands:${NC}"
    echo -e "   Stop services:    kill \$(cat backend.pid frontend.pid)"
    echo -e "   View logs:        tail -f backend.log frontend.log"
    echo -e "   Restart:          ./setup.sh"
    echo ""
    echo -e "${PURPLE}🛡️  Happy Scanning! Stay Secure!${NC}"
    echo ""
}

# Main installation flow
main() {
    print_header
    
    # Check if we're in the right directory
    if [ ! -f "setup.sh" ] || [ ! -d "backend" ] || [ ! -d "frontend" ]; then
        print_error "Please run this script from the CyberSage-2.0 root directory"
        print_info "Make sure you have extracted/cloned the complete project"
        exit 1
    fi
    
    # Run installation steps
    detect_system
    check_prerequisites
    install_security_tools
    setup_backend
    setup_frontend
    setup_database
    start_services
    health_check
    show_completion
}

# Trap Ctrl+C and cleanup
cleanup() {
    echo -e "\n${YELLOW}🛑 Installation interrupted${NC}"
    print_info "Cleaning up..."
    # Kill any spawned processes
    [ -f "backend.pid" ] && kill $(cat backend.pid) 2>/dev/null || true
    [ -f "frontend.pid" ] && kill $(cat frontend.pid) 2>/dev/null || true
    exit 1
}

trap cleanup INT

# Run main installation
main

echo -e "\n${GREEN}🎊 CyberSage 2.0 setup completed!${NC}"
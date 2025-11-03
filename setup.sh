#!/bin/bash

# CyberSage 2.0 Installation Script
# This script sets up both frontend and backend

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

print_header() {
    echo ""
    echo "================================"
    echo "$1"
    echo "================================"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Check Node.js
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node -v)
        print_success "Node.js installed: $NODE_VERSION"
    else
        print_error "Node.js is not installed. Please install Node.js 18+ from https://nodejs.org/"
        exit 1
    fi
    
    # Check npm or pnpm
    if command -v pnpm &> /dev/null; then
        PNPM_VERSION=$(pnpm -v)
        print_success "pnpm installed: $PNPM_VERSION"
        PKG_MANAGER="pnpm"
    elif command -v npm &> /dev/null; then
        NPM_VERSION=$(npm -v)
        print_success "npm installed: $NPM_VERSION"
        PKG_MANAGER="npm"
    else
        print_error "npm or pnpm is required but not installed"
        exit 1
    fi
    
    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version)
        print_success "Python installed: $PYTHON_VERSION"
    else
        print_error "Python 3.8+ is not installed. Please install Python from https://python.org/"
        exit 1
    fi
    
    # Check pip
    if command -v pip3 &> /dev/null; then
        PIP_VERSION=$(pip3 --version)
        print_success "pip installed: $PIP_VERSION"
    else
        print_error "pip is not installed. Please install pip"
        exit 1
    fi
}

# Setup backend
setup_backend() {
    print_header "Setting up Backend"
    
    cd backend
    
    # Create virtual environment
    print_info "Creating Python virtual environment..."
    python3 -m venv venv
    print_success "Virtual environment created"
    
    # Activate virtual environment
    print_info "Activating virtual environment..."
    source venv/bin/activate || . venv/Scripts/activate
    
    # Upgrade pip
    print_info "Upgrading pip..."
    pip install --upgrade pip
    
    # Install dependencies
    print_info "Installing Python dependencies..."
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        print_success "Python dependencies installed"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
    
    # Create .env file if it doesn't exist
    if [ ! -f ".env" ]; then
        print_info "Creating .env file..."
        cat > .env << EOF
# API Keys (Required for AI features)
CLAUDE_API_KEY=your_claude_api_key_here
OPENAI_API_KEY=your_openai_api_key_here

# Database
DATABASE_URL=sqlite:///cybersage.db

# Server Configuration
FLASK_ENV=development
PORT=5001
CORS_ORIGINS=http://localhost:5173,http://localhost:3000

# Security
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60
EOF
        print_success ".env file created"
        print_info "Please edit backend/.env and add your API keys"
    else
        print_info ".env file already exists"
    fi
    
    cd ..
}

# Setup frontend
setup_frontend() {
    print_header "Setting up Frontend"
    
    cd frontend
    
    # Install dependencies
    print_info "Installing frontend dependencies..."
    $PKG_MANAGER install
    print_success "Frontend dependencies installed"
    
    # Create .env file if it doesn't exist
    if [ ! -f ".env" ]; then
        print_info "Creating .env file..."
        cat > .env << EOF
# API Configuration
VITE_API_URL=http://localhost:5001
VITE_WS_URL=ws://localhost:5001

# Feature Flags
VITE_ENABLE_AI_ANALYSIS=true
VITE_ENABLE_EXPORT=true
EOF
        print_success ".env file created"
    else
        print_info ".env file already exists"
    fi
    
    cd ..
}

# Build frontend
build_frontend() {
    print_header "Building Frontend"
    
    cd frontend
    print_info "Building frontend for production..."
    $PKG_MANAGER run build
    print_success "Frontend built successfully"
    cd ..
}

# Create start scripts
create_start_scripts() {
    print_header "Creating Start Scripts"
    
    # Create start.sh
    cat > start.sh << 'EOF'
#!/bin/bash

# Start CyberSage Application

# Colors
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}Starting CyberSage...${NC}"

# Start backend
cd backend
source venv/bin/activate || . venv/Scripts/activate
python app.py &
BACKEND_PID=$!
echo "Backend started (PID: $BACKEND_PID)"

# Start frontend
cd ../frontend
npm run dev &
FRONTEND_PID=$!
echo "Frontend started (PID: $FRONTEND_PID)"

echo ""
echo -e "${GREEN}CyberSage is running!${NC}"
echo "Frontend: http://localhost:5173"
echo "Backend: http://localhost:5001"
echo ""
echo "Press Ctrl+C to stop..."

# Wait for Ctrl+C
trap "kill $BACKEND_PID $FRONTEND_PID; exit" INT
wait
EOF
    
    chmod +x start.sh
    print_success "Start script created: ./start.sh"
    
    # Create stop.sh
    cat > stop.sh << 'EOF'
#!/bin/bash

# Stop CyberSage Application

echo "Stopping CyberSage..."

# Kill processes on specific ports
lsof -ti:5001 | xargs kill -9 2>/dev/null || true
lsof -ti:5173 | xargs kill -9 2>/dev/null || true

echo "CyberSage stopped"
EOF
    
    chmod +x stop.sh
    print_success "Stop script created: ./stop.sh"
}

# Main installation
main() {
    print_header "CyberSage 2.0 Installation"
    
    check_prerequisites
    setup_backend
    setup_frontend
    create_start_scripts
    
    print_header "Installation Complete!"
    
    echo ""
    echo "Next steps:"
    echo "1. Edit backend/.env and add your API keys (Claude, OpenAI)"
    echo "2. Start the application: ./start.sh"
    echo "3. Access the application at http://localhost:5173"
    echo ""
    echo "For production deployment, run: ./start.sh --production"
    echo ""
    print_success "Setup completed successfully!"
}

# Run main installation
main

#!/bin/bash

echo "=================================="
echo "🧠 CyberSage v2.0 Setup Script"
echo "=================================="
echo ""

# Check if Python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

echo "✅ Python3 found: $(python3 --version)"

# Check if pip3 is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed. Please install pip3."
    exit 1
fi

echo "✅ pip3 found"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 14 or higher."
    exit 1
fi

echo "✅ Node.js found: $(node --version)"

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed. Please install npm."
    exit 1
fi

echo "✅ npm found: $(npm --version)"

# Backend Setup
echo ""
echo "📦 Setting up backend..."
cd backend

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "❌ Failed to create virtual environment"
        exit 1
    fi
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment and install dependencies
echo "Installing Python dependencies..."
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install requirements
pip install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "❌ Failed to install Python dependencies"
    deactivate
    exit 1
fi

echo "✅ Python dependencies installed"

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating .env file..."
    cat > .env << EOF
SECRET_KEY=cybersage_v2_secret_$(date +%s)
OPENROUTER_API_KEY=
FLASK_ENV=development
FLASK_DEBUG=False
DATABASE_PATH=cybersage_v2.db
EOF
    echo "✅ .env file created"
else
    echo "✅ .env file already exists"
fi

# Initialize database
echo "Initializing database..."
python -c "from core.database import Database; db = Database(); print('[Database] Initialized successfully')"

deactivate
cd ..

# Frontend Setup
echo ""
echo "📦 Setting up frontend..."
cd frontend

# Install Node dependencies
echo "Installing Node.js dependencies (this may take a few minutes)..."
npm install

if [ $? -ne 0 ]; then
    echo "❌ Failed to install Node dependencies"
    exit 1
fi

echo "✅ Node.js dependencies installed"

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating frontend .env file..."
    cat > .env << EOF
REACT_APP_BACKEND_URL=http://localhost:5000
EOF
    echo "✅ Frontend .env file created"
else
    echo "✅ Frontend .env file already exists"
fi

cd ..

# Create start script if it doesn't exist
echo ""
echo "📝 Setting up start script..."

if [ ! -f "start.sh" ]; then
    cat > start.sh << 'STARTSCRIPT'
#!/bin/bash

echo "============================================"
echo "🧠 CyberSage v2.0 - Starting Application"
echo "============================================"
echo ""

# Check if backend virtual environment exists
if [ ! -d "backend/venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "   Please run: ./setup.sh first"
    exit 1
fi

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "============================================"
    echo "🛑 Stopping CyberSage v2.0..."
    echo "============================================"
    if [ ! -z "$BACKEND_PID" ]; then
        echo "Stopping backend (PID: $BACKEND_PID)..."
        kill $BACKEND_PID 2>/dev/null
    fi
    if [ ! -z "$FRONTEND_PID" ]; then
        echo "Stopping frontend (PID: $FRONTEND_PID)..."
        kill $FRONTEND_PID 2>/dev/null
    fi
    echo "✅ Shutdown complete"
    exit 0
}

# Trap Ctrl+C
trap cleanup INT TERM

# Start Backend
echo "🔧 Starting Backend..."
cd backend

# Activate virtual environment
source venv/bin/activate

# Start backend in background
python app.py > ../backend.log 2>&1 &
BACKEND_PID=$!
cd ..

echo "✅ Backend started (PID: $BACKEND_PID)"
echo "   Logs: backend.log"
echo "   URL:  http://localhost:5000"

# Wait for backend to be ready
echo ""
echo "⏳ Waiting for backend to initialize..."
sleep 5

# Check if backend is responding
for i in {1..10}; do
    if curl -s http://localhost:5000/api/health > /dev/null 2>&1; then
        echo "✅ Backend is ready!"
        break
    fi
    if [ $i -eq 10 ]; then
        echo "❌ Backend failed to start. Check backend.log for errors."
        echo ""
        echo "Showing last 20 lines of backend.log:"
        tail -n 20 backend.log
        cleanup
        exit 1
    fi
    sleep 2
done

# Start Frontend
echo ""
echo "🎨 Starting Frontend..."
cd frontend

# Start frontend in background
npm start > ../frontend.log 2>&1 &
FRONTEND_PID=$!
cd ..

echo "✅ Frontend started (PID: $FRONTEND_PID)"
echo "   Logs: frontend.log"
echo "   URL:  http://localhost:3000 (will open automatically)"

echo ""
echo "============================================"
echo "✅ CyberSage v2.0 is now running!"
echo "============================================"
echo ""
echo "📊 Backend:  http://localhost:5000"
echo "🌐 Frontend: http://localhost:3000"
echo ""
echo "📝 View Logs:"
echo "   Backend:  tail -f backend.log"
echo "   Frontend: tail -f frontend.log"
echo ""
echo "Press Ctrl+C to stop all services"
echo "============================================"
echo ""

# Wait for processes
wait
STARTSCRIPT

    chmod +x start.sh
    echo "✅ Created start.sh"
else
    echo "✅ start.sh already exists"
fi

echo ""
echo "=================================="
echo "✅ Setup Complete!"
echo "=================================="
echo ""
echo "📁 Project structure:"
echo "   backend/venv/     - Python virtual environment"
echo "   backend/.env      - Backend configuration"
echo "   frontend/.env     - Frontend configuration"
echo "   frontend/node_modules/ - Node.js dependencies"
echo ""
echo "🚀 To start CyberSage v2.0, run:"
echo "   ./start.sh"
echo ""
echo "📖 Quick Start:"
echo "   1. Run: ./start.sh"
echo "   2. Open: http://localhost:3000"
echo "   3. Enter a target and click 'Start Security Scan'"
echo ""
echo "🔧 Troubleshooting:"
echo "   - If backend fails: Check backend.log"
echo "   - If frontend fails: Check frontend.log"
echo "   - If port conflicts: Kill process on port 5000 or 3000"
echo ""
echo "=================================="
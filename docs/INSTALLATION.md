# Installation Guide

This guide will help you install and set up CyberSage 2.0 on your system.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Installation](#quick-installation)
- [Manual Installation](#manual-installation)
- [Docker Installation](#docker-installation)
- [Configuration](#configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **OS**: Linux, macOS, or Windows (with WSL2 recommended)
- **RAM**: Minimum 4GB, Recommended 8GB+
- **Disk Space**: Minimum 2GB free space

### Software Requirements

- **Node.js** 18.0.0 or higher
- **Python** 3.8 or higher
- **npm** or **pnpm** (latest version)
- **Git** (for cloning the repository)

### API Keys (Required for AI features)

- **Claude API Key** - Get from [Anthropic](https://www.anthropic.com/)
- **OpenAI API Key** (Optional) - Get from [OpenAI](https://openai.com/)

## Quick Installation

The fastest way to get started:

```bash
# Clone the repository
git clone https://github.com/yourusername/cybersage.git
cd cybersage

# Run the automated setup script
chmod +x setup.sh
./setup.sh

# Edit configuration
nano backend/.env  # Add your API keys

# Start the application
./start.sh
```

Access the application at `http://localhost:5173`

## Manual Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/cybersage.git
cd cybersage
```

### Step 2: Set Up Backend

```bash
cd backend

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Create environment file
cp .env.example .env
nano .env  # Edit and add your API keys
```

### Step 3: Set Up Frontend

```bash
cd ../frontend

# Install dependencies
npm install
# OR if you prefer pnpm:
pnpm install

# Create environment file
cp .env.example .env
nano .env  # Configure frontend settings
```

### Step 4: Initialize Database

```bash
cd ../backend
source venv/bin/activate
python -c "from app import init_db; init_db()"
```

### Step 5: Start the Application

**Terminal 1 - Backend:**
```bash
cd backend
source venv/bin/activate
python app.py
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

## Docker Installation

### Prerequisites for Docker

- **Docker** 20.10+ installed
- **Docker Compose** 1.29+ installed

### Using Docker Compose

```bash
# Clone the repository
git clone https://github.com/yourusername/cybersage.git
cd cybersage

# Create .env files
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env

# Edit backend/.env with your API keys
nano backend/.env

# Build and start containers
docker-compose up -d

# View logs
docker-compose logs -f

# Access the application
open http://localhost:8080
```

### Docker Commands

```bash
# Start containers
docker-compose up -d

# Stop containers
docker-compose down

# Restart containers
docker-compose restart

# View logs
docker-compose logs -f backend
docker-compose logs -f frontend

# Rebuild containers
docker-compose up -d --build

# Remove all containers and volumes
docker-compose down -v
```

## Configuration

### Backend Configuration (backend/.env)

```env
# Required API Keys
CLAUDE_API_KEY=sk-ant-your-key-here
OPENAI_API_KEY=sk-your-key-here  # Optional

# Database Configuration
DATABASE_URL=sqlite:///cybersage.db

# Server Configuration
FLASK_ENV=development  # or 'production'
PORT=5001
HOST=0.0.0.0

# CORS Settings
CORS_ORIGINS=http://localhost:5173,http://localhost:3000

# Security
SECRET_KEY=your-secret-key-here-change-in-production

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60

# Logging
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FILE=logs/cybersage.log

# Feature Flags
ENABLE_AI_ANALYSIS=true
ENABLE_EXPORT=true
ENABLE_WEBSOCKET=true
```

### Frontend Configuration (frontend/.env)

```env
# API Configuration
VITE_API_URL=http://localhost:5001
VITE_WS_URL=ws://localhost:5001

# Feature Flags
VITE_ENABLE_AI_ANALYSIS=true
VITE_ENABLE_EXPORT=true

# UI Configuration
VITE_THEME=dark  # or 'light'
VITE_DEFAULT_PAGE_SIZE=20

# Analytics (Optional)
VITE_ANALYTICS_ID=your-analytics-id
```

## Verification

### 1. Check Backend Health

```bash
curl http://localhost:5001/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "timestamp": "2025-11-01T12:00:00Z"
}
```

### 2. Check Frontend

Open browser and navigate to `http://localhost:5173`

You should see the CyberSage dashboard.

### 3. Test WebSocket Connection

In the browser console:
```javascript
const ws = new WebSocket('ws://localhost:5001');
ws.onopen = () => console.log('Connected!');
```

### 4. Test API Endpoints

```bash
# Test request repeater
curl -X POST http://localhost:5001/api/repeater/send \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://httpbin.org/get",
    "method": "GET"
  }'
```

## Troubleshooting

### Common Issues

#### Issue: Port Already in Use

**Error**: `Address already in use: 5001`

**Solution**:
```bash
# Find and kill the process
lsof -ti:5001 | xargs kill -9

# Or change the port in backend/.env
PORT=5002
```

#### Issue: Module Not Found (Python)

**Error**: `ModuleNotFoundError: No module named 'flask'`

**Solution**:
```bash
cd backend
source venv/bin/activate
pip install -r requirements.txt
```

#### Issue: Node Modules Missing

**Error**: `Cannot find module...`

**Solution**:
```bash
cd frontend
rm -rf node_modules pnpm-lock.yaml
npm install
```

#### Issue: API Key Not Working

**Error**: `Invalid API key` or `Unauthorized`

**Solution**:
1. Verify your API key is correct in `backend/.env`
2. Ensure there are no spaces or quotes around the key
3. Check if the key is active in your provider's dashboard

#### Issue: Database Locked

**Error**: `database is locked`

**Solution**:
```bash
cd backend
rm cybersage.db cybersage.db-journal
python -c "from app import init_db; init_db()"
```

#### Issue: CORS Error

**Error**: `Access to fetch... has been blocked by CORS policy`

**Solution**:
```bash
# Add your frontend URL to CORS_ORIGINS in backend/.env
CORS_ORIGINS=http://localhost:5173,http://localhost:3000
```

#### Issue: WebSocket Connection Failed

**Error**: `WebSocket connection failed`

**Solution**:
1. Check if backend is running
2. Verify WebSocket URL in `frontend/.env`
3. Check firewall settings

### Getting Help

If you encounter issues not listed here:

1. Check [GitHub Issues](https://github.com/yourusername/cybersage/issues)
2. Ask in [GitHub Discussions](https://github.com/yourusername/cybersage/discussions)
3. Email: support@cybersage.io

### Logs

Check logs for detailed error information:

**Backend logs**:
```bash
cd backend
tail -f logs/cybersage.log
```

**Frontend console**:
Open browser DevTools (F12) and check the Console tab

## Next Steps

- Read the [User Guide](USER_GUIDE.md)
- Review [API Documentation](API.md)
- Learn about [Security Best Practices](../SECURITY.md)
- Join our community on [Discord](#)

## Production Deployment

For production deployment, see [Production Deployment Guide](PRODUCTION.md).

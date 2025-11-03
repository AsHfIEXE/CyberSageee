# CyberSage 2.0 - AI-Powered Security Testing Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/yourusername/cybersage?style=social)](https://github.com/yourusername/cybersage)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

> Professional-grade security testing platform with AI-powered vulnerability analysis, HTTP request repeater, and automated exploit verification.

![CyberSage Banner](docs/images/banner.png)

## Features

### Core Security Testing Tools

- **HTTP Request Repeater** - Burp Suite-like interface for manual HTTP testing
  - Full HTTP method support (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
  - Header and parameter manipulation
  - Request history and session management
  - Syntax highlighting for requests and responses
  - Response analysis and comparison

- **Security Vulnerability Scanner** - Automated vulnerability detection
  - SQL injection testing
  - XSS (Cross-Site Scripting) detection
  - Command injection testing
  - Path traversal testing
  - File upload vulnerability scanning
  - Authentication bypass detection

- **AI-Powered Analysis** - Claude AI integration
  - Intelligent vulnerability prioritization
  - Attack path mapping
  - 60x faster than manual analysis
  - Real-time exploit verification
  - Automated remediation code generation

- **Business Impact Calculator** - Financial risk assessment
  - ROI analysis for security measures
  - Cost-benefit analysis
  - Risk quantification
  - Compliance scoring

### Professional Features

- **Real-time Testing** - WebSocket-based live updates
- **Payload Generation** - Pre-built security testing payloads
- **Session Management** - Track and replay testing sessions
- **Export Capabilities** - JSON, HTML, and PDF reports
- **Proxy Functionality** - HTTP traffic interception
- **Modern UI** - Professional blue-themed interface with micro-animations

## Demo

🔗 **Live Demo:** [https://cybersage-demo.space.minimax.io](https://cybersage-demo.space.minimax.io)

## Screenshots

<table>
  <tr>
    <td><img src="docs/images/dashboard.png" alt="Dashboard" width="400"/></td>
    <td><img src="docs/images/repeater.png" alt="HTTP Repeater" width="400"/></td>
  </tr>
  <tr>
    <td align="center">Dashboard</td>
    <td align="center">HTTP Request Repeater</td>
  </tr>
  <tr>
    <td><img src="docs/images/scanner.png" alt="Security Scanner" width="400"/></td>
    <td><img src="docs/images/ai-analysis.png" alt="AI Analysis" width="400"/></td>
  </tr>
  <tr>
    <td align="center">Security Scanner</td>
    <td align="center">AI-Powered Analysis</td>
  </tr>
</table>

## Quick Start

### Prerequisites

- **Node.js** 18+ and npm/pnpm
- **Python** 3.8+
- **Git**

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/cybersage.git
cd cybersage
```

2. **Run the setup script**
```bash
chmod +x setup.sh
./setup.sh
```

3. **Start the application**
```bash
# Start backend
cd backend
python app.py

# In another terminal, start frontend
cd frontend
npm run dev
```

4. **Access the application**
```
Frontend: http://localhost:5173
Backend API: http://localhost:5001
```

### Docker Installation (Alternative)

```bash
docker-compose up -d
```

Access at `http://localhost:8080`

## Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [User Guide](docs/USER_GUIDE.md)
- [API Documentation](docs/API.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

## Technology Stack

### Frontend
- **React 18** with TypeScript
- **Vite** for fast development
- **Tailwind CSS** for styling
- **shadcn/ui** for UI components
- **Lucide React** for icons
- **WebSocket** for real-time updates

### Backend
- **Python 3.8+**
- **Flask** web framework
- **Socket.IO** for WebSocket communication
- **SQLite** for data persistence
- **Claude AI** for intelligent analysis

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Frontend (React)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Dashboard  │  │  HTTP        │  │   Security   │  │
│  │              │  │  Repeater    │  │   Scanner    │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
                           ↓ HTTP/WebSocket
┌─────────────────────────────────────────────────────────┐
│                  Backend API (Flask)                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Request    │  │  Vulnerability│  │  AI Analysis │  │
│  │   Proxy      │  │  Scanner     │  │  Engine      │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│              External Services & Tools                   │
│     Claude AI  │  Security Tools  │  Database           │
└─────────────────────────────────────────────────────────┘
```

## Usage Examples

### HTTP Request Testing

```javascript
// Send a custom HTTP request
POST /api/repeater/send
{
  "url": "https://example.com/api/login",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json"
  },
  "body": {
    "username": "test",
    "password": "test123"
  }
}
```

### Security Scanning

```javascript
// Start a security scan
WebSocket: emit('start_scan', {
  target: "https://example.com",
  scan_types: ["sql_injection", "xss", "command_injection"]
})
```

### AI Vulnerability Analysis

```python
# Analyze vulnerabilities with AI
from ai_smart_prioritizer import AISmartPrioritizer

analyzer = AISmartPrioritizer()
results = analyzer.prioritize_vulnerabilities(vulnerabilities)
```

## Configuration

### Environment Variables

Create a `.env` file in the backend directory:

```env
# API Keys
CLAUDE_API_KEY=your_claude_api_key
OPENAI_API_KEY=your_openai_api_key

# Database
DATABASE_URL=sqlite:///cybersage.db

# Server
FLASK_ENV=development
PORT=5001
CORS_ORIGINS=http://localhost:5173

# Security
SECRET_KEY=your_secret_key_here
```

### Frontend Configuration

Edit `frontend/src/config.ts`:

```typescript
export const config = {
  apiUrl: 'http://localhost:5001',
  wsUrl: 'ws://localhost:5001',
  features: {
    aiAnalysis: true,
    exportReports: true
  }
}
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Quick Contribution Guide

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security

Found a security vulnerability? Please read our [Security Policy](SECURITY.md) and report it responsibly.

## Roadmap

- [ ] Integration with more security tools (Metasploit, Nessus)
- [ ] Advanced payload generation with AI
- [ ] Collaborative testing features
- [ ] Mobile application support
- [ ] Cloud deployment templates
- [ ] Plugin system for custom tools
- [ ] Advanced reporting with visualizations
- [ ] Integration with CI/CD pipelines

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [React](https://reactjs.org/) and [Flask](https://flask.palletsprojects.com/)
- UI components from [shadcn/ui](https://ui.shadcn.com/)
- Icons by [Lucide](https://lucide.dev/)
- AI powered by [Claude](https://www.anthropic.com/)
- Inspired by [Burp Suite](https://portswigger.net/burp) and [HETTY](https://github.com/dstotijn/hetty)

## Support

- **Documentation:** [docs/](docs/)
- **Issues:** [GitHub Issues](https://github.com/yourusername/cybersage/issues)
- **Discussions:** [GitHub Discussions](https://github.com/yourusername/cybersage/discussions)
- **Email:** support@cybersage.io

## Authors

- **Your Name** - *Initial work* - [@yourusername](https://github.com/yourusername)

See also the list of [contributors](https://github.com/yourusername/cybersage/contributors) who participated in this project.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/cybersage&type=Date)](https://star-history.com/#yourusername/cybersage&Date)

---

**Made with ❤️ by the CyberSage Team**

If you found this project helpful, please give it a ⭐️!

# CyberSage 2.0 - Advanced AI-Powered Security Testing Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/yourusername/cybersage?style=social)](https://github.com/yourusername/cybersage)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

> Enterprise-grade security testing platform with advanced HTTP repeater, HETTY HTTP/2 integration, AI-powered vulnerability analysis, and comprehensive security testing dashboard.

![CyberSage Banner](docs/images/banner.png)

## Features

### Advanced Security Testing Tools

- **Enhanced HTTP Request Repeater** - Professional Burp Suite-like interface with advanced capabilities
  - Full HTTP method support (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
  - Advanced parameter injection testing (SQL, XSS, Command Injection, LFI/RFI, LDAP)
  - Automated endpoint fuzzing with comprehensive wordlists
  - Security header analysis with OWASP recommendations
  - Request history and session management with vulnerability tracking
  - Real-time payload generation and testing templates
  - Response analysis with security score calculation

- **HETTY HTTP/2 Integration** - Advanced HTTP/2 testing and proxy capabilities
  - HTTP/2 protocol analysis and testing
  - Traffic interception and manipulation
  - HTTP/2 specific vulnerability testing
  - Stream manipulation and header compression testing
  - Connection depletion testing
  - Real-time security scanning with HTTP/2 awareness

- **Security Testing Dashboard** - Comprehensive security operations center
  - Real-time vulnerability tracking and prioritization
  - Security metrics and analytics
  - Test suite management and scheduling
  - Activity monitoring and audit trails
  - Trend analysis and reporting
  - Integration with all security testing tools

- **Advanced Vulnerability Scanner** - Enhanced automated vulnerability detection
  - SQL injection testing with multiple techniques
  - XSS (Cross-Site Scripting) detection and validation
  - Command injection testing
  - Path traversal and directory listing detection
  - File upload vulnerability scanning
  - Authentication bypass detection
  - OWASP Top 10 vulnerability coverage

- **AI-Powered Security Analysis** - Claude AI integration for intelligent security testing
  - Intelligent vulnerability prioritization with risk scoring
  - Attack path mapping and exploitation potential
  - 80x faster than manual analysis
  - Real-time exploit verification and validation
  - Automated remediation code generation
  - Business impact assessment with financial risk modeling
  - Smart payload recommendations based on target analysis

- **Business Impact Calculator** - Financial risk assessment and ROI analysis
  - Comprehensive ROI analysis for security measures
  - Cost-benefit analysis with industry benchmarks
  - Risk quantification and exposure calculation
  - Compliance scoring and gap analysis
  - Executive reporting with visual dashboards

### Professional & Enterprise Features

- **Real-time Testing Engine** - WebSocket-based live updates and monitoring
- **Advanced Payload Management** - Pre-built security testing payloads and custom generation
- **Session Management** - Comprehensive testing session tracking and replay
- **Export & Reporting** - JSON, HTML, PDF, and CSV report generation
- **Proxy Functionality** - HTTP/HTTPS traffic interception and analysis
- **Modern UI/UX** - Professional blue-themed interface with micro-animations
- **Multi-Protocol Support** - HTTP/1.1, HTTP/2, and WebSocket testing
- **Plugin Architecture** - Extensible framework for custom security tools
- **Compliance Reporting** - Built-in support for various security standards

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
- **HTTP/2** support for modern protocol testing

### Backend
- **Python 3.8+**
- **Flask** web framework with blueprints
- **Socket.IO** for WebSocket communication
- **SQLite** for data persistence
- **Claude AI** for intelligent analysis
- **HTTP/2** protocol support
- **Advanced Security Testing Engine** with payload management

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Frontend (React)                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   Security   │  │   Enhanced   │  │   HETTY      │  │  Advanced    │   │
│  │   Testing    │  │   HTTP       │  │   HTTP/2     │  │  Dashboard   │   │
│  │   Dashboard  │  │   Repeater   │  │   Integration│  │              │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                 ↓ HTTP/WebSocket/REST API
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Backend API (Flask)                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   Enhanced   │  │  Advanced    │  │  HTTP/2      │  │  AI Security │   │
│  │   Repeater   │  │  Vulnerability│  │  Testing     │  │  Analysis    │   │
│  │   API        │  │  Scanner     │  │  Engine      │  │  Engine      │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                 ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│                     External Services & Security Tools                       │
│     Claude AI    │  HTTP/2 Tools  │  Security Databases  │  WebSocket      │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Usage Examples

### Advanced HTTP Request Testing with Parameter Injection

```javascript
// Enhanced HTTP request with parameter injection testing
POST /api/repeater/inject
{
  "url": "https://example.com/api/login",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json"
  },
  "body": {
    "username": "test",
    "password": "test123"
  },
  "injection_tests": {
    "sql_injection": true,
    "xss": true,
    "command_injection": true,
    "lfi_rfi": true,
    "ldap_injection": true
  }
}
```

### Endpoint Fuzzing for Discovery

```javascript
// Automated endpoint discovery through fuzzing
POST /api/repeater/fuzz
{
  "base_url": "https://example.com",
  "wordlist": "common_paths",
  "recursive": true,
  "max_depth": 3,
  "respect_robots": true
}
```

### Security Header Analysis

```javascript
// Comprehensive security header analysis
GET /api/repeater/headers/analyze
{
  "url": "https://example.com",
  "check_headers": [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security"
  ]
}
```

### HETTY HTTP/2 Integration Testing

```javascript
// Start HTTP/2 proxy and testing
WebSocket: emit('start_http2_proxy', {
  target: "https://example.com",
  proxy_port: 8080,
  intercept_requests: true,
  intercept_responses: true,
  http2_specific_tests: true
})
```

### Advanced Security Scanning

```javascript
// Start comprehensive security scan with real-time updates
WebSocket: emit('start_advanced_scan', {
  target: "https://example.com",
  scan_types: ["sql_injection", "xss", "command_injection", "path_traversal"],
  use_payload_templates: true,
  ai_enhanced: true,
  business_impact_analysis: true
})
```

### AI Vulnerability Analysis and Prioritization

```python
# Advanced AI-powered vulnerability analysis
from ai_smart_prioritizer import AISmartPrioritizer
from business_impact_calculator import BusinessImpactCalculator

# Analyze and prioritize vulnerabilities
analyzer = AISmartPrioritizer()
impact_calc = BusinessImpactCalculator()

vulnerabilities = load_vulnerabilities()
prioritized = analyzer.prioritize_vulnerabilities(vulnerabilities)
business_impact = impact_calc.calculate_impact(prioritized)

# Generate remediation recommendations
recommendations = analyzer.generate_remediation_code(prioritized)
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

- [x] ✅ **Completed:** Enhanced HTTP Repeater with parameter injection testing
- [x] ✅ **Completed:** HETTY HTTP/2 integration and testing capabilities
- [x] ✅ **Completed:** Security Testing Dashboard with comprehensive analytics
- [x] ✅ **Completed:** AI-powered vulnerability prioritization and verification
- [x] ✅ **Completed:** Advanced fuzzing and endpoint discovery
- [x] ✅ **Completed:** Security header analysis with OWASP recommendations
- [ ] Integration with additional security tools (Metasploit, Nessus, Burp Suite Pro)
- [ ] Advanced collaborative testing features with team management
- [ ] Mobile application support for on-the-go security testing
- [ ] Cloud deployment templates for AWS, Azure, GCP
- [ ] Extended plugin system for third-party security tools
- [ ] Advanced reporting with interactive visualizations and dashboards
- [ ] Integration with CI/CD pipelines for automated security testing
- [ ] Custom payload generation with machine learning
- [ ] Real-time threat intelligence integration

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [React](https://reactjs.org/) and [Flask](https://flask.palletsprojects.com/)
- UI components from [shadcn/ui](https://ui.shadcn.com/)
- Icons by [Lucide](https://lucide.dev/)
- AI powered by [Claude](https://www.anthropic.com/)
- Inspired by [Burp Suite](https://portswigger.net/burp) and [HETTY](https://github.com/dstotijn/hetty)
- Security testing methodologies from [OWASP](https://owasp.org/)

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

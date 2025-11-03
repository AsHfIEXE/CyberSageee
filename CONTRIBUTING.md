# Contributing to CyberSage

First off, thank you for considering contributing to CyberSage! It's people like you that make CyberSage such a great tool.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to security@cybersage.io.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples**
- **Describe the behavior you observed and what you expected**
- **Include screenshots if possible**
- **Include your environment details** (OS, Node version, Python version, browser)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a detailed description of the suggested enhancement**
- **Explain why this enhancement would be useful**
- **List some examples of how it would be used**

### Pull Requests

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Make your changes
4. Write or update tests as needed
5. Ensure all tests pass
6. Update documentation as needed
7. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
8. Push to the branch (`git push origin feature/AmazingFeature`)
9. Open a Pull Request

## Development Setup

### Prerequisites

- Node.js 18+
- Python 3.8+
- Git

### Setup Instructions

1. **Clone your fork**
```bash
git clone https://github.com/your-username/cybersage.git
cd cybersage
```

2. **Install dependencies**
```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Frontend
cd ../frontend
npm install
```

3. **Set up environment variables**
```bash
# Backend
cp backend/.env.example backend/.env
# Edit .env with your API keys

# Frontend
cp frontend/.env.example frontend/.env
```

4. **Run the development servers**
```bash
# Backend (in one terminal)
cd backend
python app.py

# Frontend (in another terminal)
cd frontend
npm run dev
```

## Coding Standards

### Python (Backend)

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use type hints where possible
- Write docstrings for all functions and classes
- Use meaningful variable names

Example:
```python
def analyze_vulnerability(vuln_data: dict) -> dict:
    """
    Analyze a vulnerability using AI.
    
    Args:
        vuln_data: Dictionary containing vulnerability details
        
    Returns:
        Dictionary with analysis results and recommendations
    """
    # Implementation
    pass
```

### TypeScript/JavaScript (Frontend)

- Use TypeScript for new code
- Follow [Airbnb JavaScript Style Guide](https://github.com/airbnb/javascript)
- Use functional components with hooks
- Use meaningful component and variable names

Example:
```typescript
interface VulnerabilityProps {
  data: VulnerabilityData;
  onAnalyze: (id: string) => void;
}

export const VulnerabilityCard: React.FC<VulnerabilityProps> = ({ 
  data, 
  onAnalyze 
}) => {
  // Implementation
};
```

### Git Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests after the first line

Example:
```
Add HTTP request history feature

- Implement request storage in local database
- Add UI for viewing request history
- Add search and filter functionality

Closes #123
```

## Testing

### Backend Tests

```bash
cd backend
pytest tests/
```

### Frontend Tests

```bash
cd frontend
npm test
```

### E2E Tests

```bash
npm run test:e2e
```

## Documentation

- Update README.md if you change functionality
- Add JSDoc/docstrings to new functions
- Update API documentation if you add/modify endpoints
- Add examples for new features

## Project Structure

```
cybersage/
├── backend/
│   ├── app.py                 # Main Flask application
│   ├── ai_smart_prioritizer.py
│   ├── exploit_verifier.py
│   ├── business_impact_calculator.py
│   └── tests/
├── frontend/
│   ├── src/
│   │   ├── components/        # React components
│   │   ├── services/          # API services
│   │   ├── hooks/             # Custom React hooks
│   │   └── utils/             # Utility functions
│   └── tests/
├── docs/                      # Documentation
└── scripts/                   # Build and deployment scripts
```

## Adding New Features

### Adding a New Security Test

1. **Backend**: Create a new test module in `backend/security_tests/`
2. **Add to scanner**: Update `security_testing_engine.py`
3. **Frontend**: Add UI in `frontend/src/components/SecurityTester.tsx`
4. **Tests**: Add tests for the new feature
5. **Documentation**: Update docs/USER_GUIDE.md

### Adding a New AI Analysis Feature

1. **Backend**: Add method to `AISmartPrioritizer` class
2. **API endpoint**: Add route in `app.py`
3. **Frontend**: Update `api.ts` service
4. **UI**: Add component or update existing one
5. **Documentation**: Update API docs

## Code Review Process

1. All code changes require review from at least one maintainer
2. Automated tests must pass
3. Code must follow style guidelines
4. Documentation must be updated
5. Security considerations must be addressed

## Security

- Never commit API keys or secrets
- Use environment variables for sensitive data
- Follow OWASP security guidelines
- Report security vulnerabilities privately to security@cybersage.io

## Questions?

Feel free to ask questions in:
- GitHub Discussions
- GitHub Issues (with question label)
- Discord community

## Recognition

Contributors will be added to:
- README.md acknowledgments
- CONTRIBUTORS.md file
- GitHub contributors page

Thank you for contributing to CyberSage! 🎉

# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Currently supported versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.x.x   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **security@cybersage.io**

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information in your report:

- Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

This information will help us triage your report more quickly.

## Preferred Languages

We prefer all communications to be in English.

## Disclosure Policy

When we receive a security bug report, we will:

1. Confirm the problem and determine affected versions
2. Audit code to find any similar problems
3. Prepare fixes for all supported releases
4. Release fixes as soon as possible

## Security Update Process

1. **Report received** - We acknowledge receipt within 48 hours
2. **Triage** - We assess the severity and impact (1-7 days)
3. **Fix development** - We develop and test a fix (varies by complexity)
4. **Release** - We release a security update
5. **Disclosure** - We publish a security advisory after fix is deployed

## Security Best Practices

### For Users

- Keep your installation up to date
- Use strong, unique API keys
- Never commit API keys or credentials to version control
- Use environment variables for sensitive configuration
- Enable HTTPS in production
- Regularly review access logs
- Use strong passwords for any authentication
- Keep your dependencies up to date

### For Developers

- Never commit sensitive data (keys, passwords, tokens)
- Use environment variables for configuration
- Validate and sanitize all user inputs
- Use parameterized queries to prevent SQL injection
- Implement proper authentication and authorization
- Use HTTPS for all API communications
- Follow the principle of least privilege
- Regularly update dependencies
- Run security audits on your code
- Use secure coding practices

## Security Features

CyberSage includes several security features:

- **Input Validation** - All user inputs are validated and sanitized
- **Rate Limiting** - API endpoints are rate-limited to prevent abuse
- **CORS Protection** - Cross-Origin Resource Sharing is properly configured
- **SQL Injection Protection** - Parameterized queries are used throughout
- **XSS Protection** - Output is properly escaped
- **CSRF Protection** - Cross-Site Request Forgery tokens are implemented
- **Secure Headers** - Security headers are set appropriately
- **Environment Variables** - Sensitive data is stored in environment variables

## Known Issues

We maintain a list of known security issues at:
https://github.com/yourusername/cybersage/security/advisories

## Bug Bounty Program

We currently do not have a bug bounty program, but we recognize and appreciate security researchers who help improve the security of CyberSage.

## Security Updates

Subscribe to security advisories at:
https://github.com/yourusername/cybersage/security/advisories

## Contact

For security concerns, contact: security@cybersage.io

For general support: support@cybersage.io

## Attribution

We would like to thank the following security researchers for their contributions:

- (List will be updated as vulnerabilities are reported and fixed)

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Security Best Practices](https://github.com/yourusername/cybersage/blob/main/docs/SECURITY_BEST_PRACTICES.md)

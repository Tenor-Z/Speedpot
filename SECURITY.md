# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Speedpot, please **do not** open a public GitHub issue. Instead, please email the maintainers directly.

**Email**: [security@speedpot.dev] *(Replace with actual email)*

Please include:
* Type of vulnerability
* Location of the vulnerability (file, line number if possible)
* Steps to reproduce
* Potential impact
* Your name and contact information (optional)

We will:
* Confirm receipt within 48 hours
* Provide an estimated timeline for a fix
* Keep you updated on progress
* Credit you in the security advisory if desired

## Security Considerations for Users

### Safe Deployment

1. **Isolated Networks**: Deploy Speedpot on isolated test networks only
2. **VM/Containers**: Consider running in virtual machines or containers
3. **Firewall Rules**: Implement strict firewall policies around the honeypot
4. **Monitoring**: Monitor bandwidth and CPU usage for suspicious behavior
5. **Log Rotation**: Regularly rotate and archive logs

### Data Privacy

1. **No Sensitive Data**: Never store real passwords, API keys, or PII in the honeypot
2. **Log Cleanup**: Regularly clean old logs containing captured payloads
3. **Database Backup**: Backup the database in a secure location
4. **Access Control**: Restrict access to the honeypot GUI and database

### Network Security

1. **Segmentation**: Place honeypot on a separate network segment
2. **IDS/IPS**: Deploy network intrusion detection systems
3. **Logging**: Centralize logs to external SIEM if possible
4. **DNS**: Use DNS sinkholing to prevent C&C communications

## Supported Versions

| Version | Supported          |
|---------|-------------------|
| 1.0.x   | ✅ Active Support |
| < 1.0   | ❌ No Support     |

## Security Best Practices

### For Developers
- Keep dependencies updated
- Use security linters and static analysis tools
- Follow secure coding practices
- Report vulnerabilities responsibly
- Document security considerations

### For Users
- Keep Speedpot and Python updated
- Review logs regularly
- Use strong credentials for access
- Enable Windows Defender/antivirus
- Keep backups of configurations

## Known Limitations

1. **Windows Primary**: Speedpot is primarily tested on Windows
2. **No Encryption**: Emulated services don't use encryption by default
3. **Single Threaded**: Some components may bottleneck under heavy load
4. **Resource Intensive**: Logging can consume significant disk space

## Future Security Improvements

- [ ] TLS/SSL support for emulated services
- [ ] Rate limiting and throttling
- [ ] Encrypted logging options
- [ ] Multi-threaded architecture improvements
- [ ] FIPS 140-2 compliance options

## Questions?

If you have questions about security, please contact the maintainers or create a private security advisory.
\`\`\`

```text file=".gitignore"
# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# C extensions
*.so

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
pip-wheel-metadata/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# PyInstaller
*.manifest
*.spec

# Unit test / coverage reports
htmlcov/
.tox/
.nox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
*.py,cover
.hypothesis/
.pytest_cache/

# Environments
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# IDEs
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store

# Speedpot specific
honeypot.db
honeypot.log
honeypot_*.log
blocked_ips.json
keys/api_keys.json

# Node modules (if using web dashboard)
node_modules/
npm-debug.log

# Temporary files
*.tmp
*.temp
*.bak

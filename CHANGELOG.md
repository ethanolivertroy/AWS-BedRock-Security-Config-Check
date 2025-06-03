# Changelog

## [1.0.2] - 2024-01-06
### Fixed
- Fixed "command not found" issue after pip install
- Module not being included in PyPI package

### Added
- Automated release system with GitHub Actions
- Makefile for common development tasks
- Release documentation

## [1.0.1] - 2024-01-06
### Fixed
- Initial attempt to fix pip installation (incomplete)

## [1.0.0] - 2024-01-06
### Added
- Initial public release
- GenAI-specific security checks
- Three modes: beginner, expert, learning
- JSON output for CI/CD integration
- Comprehensive AWS Bedrock security auditing
- Risk scoring system (1-10 scale)
- Interactive CloudShell setup script

### Security Checks
- Prompt injection detection
- PII exposure scanning  
- Model access policy validation
- Encryption verification
- VPC endpoint checking
- IAM permission auditing
- Cost anomaly detection
- Audit logging configuration
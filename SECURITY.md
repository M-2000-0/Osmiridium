# Security Policy

## Supported Versions

| Version | Supported | Security Updates |
|---------|-----------|------------------|
| 0.1.0-alpha | :white_check_mark: | See below |

## Reporting Vulnerabilities

Please report security vulnerabilities privately, via email, to security@osmiridium.tech.

You can expect a response within 5 business days. All security vulnerabilities will be acknowledged and assessed within 48 hours.

## Security Updates

Security fixes will be released as soon as possible, typically within 2 weeks of report validation. Critical vulnerabilities affecting the MPC protocol or transport security will be prioritized.

## Preferred Reporting Method

1. Send an email to security@osmiridium.tech with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Affected versions

2. If possible, include:
   - Minimal reproduction steps
   - Version information
   - Environment details

## Security Advisory Process

1. Initial triage and validation (24-48 hours)
2. CVE assignment if applicable
3. Development of fix
4. Testing and verification
5. Release with security advisory
6. Documentation of mitigation steps

## Temporary Mitigations

Until a fix is released, the following mitigations are recommended:
- Disable TLS if mTLS is not properly configured
- Restrict network access to party endpoints
- Monitor for unusual API activity
- Limit participant registration to trusted parties
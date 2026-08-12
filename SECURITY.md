# Security Policy

## Reporting a Vulnerability

If you discover a potential security vulnerability within **Rizin MCP Server**, please report it responsibly.

### Disclosure Process

1. Do NOT open a public GitHub issue for security vulnerabilities.
2. Email your findings to the repository maintainer or open a private advisory.
3. Include detailed steps to reproduce the vulnerability.
4. Allow reasonable time for the maintainer to review and issue a fix before public disclosure.

## Security Practices in this Repo

- **Path Traversal Protection**: Implemented via `get_safe_path()` to restrict file access to valid workspace bounds.
- **Command Injection Prevention**: Implemented via `sanitize_symbol_or_address()` to validate input addresses and symbols before sending to `rzpipe`.

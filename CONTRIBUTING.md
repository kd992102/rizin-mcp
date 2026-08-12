# Contributing to Rizin MCP Server

Thank you for considering contributing to Rizin MCP Server!

## How to Contribute

1. **Fork the Repository**: Create your own feature branch.
2. **Setup Development Environment**:
   ```bash
   uv sync
   ```
3. **Make Code Changes**: Ensure your changes conform to Python PEP 8 styling and pass typing/lint checks.
4. **Add Unit Tests**: Place new unit tests in the `tests/` directory.
5. **Submit a Pull Request**: Provide a detailed title and description of your changes.

## Security Considerations

- Do not commit sensitive environment files (`.env`), API keys, or proprietary sample binaries.
- Ensure all inputs passed to shell or Rizin commands are sanitized using `sanitize_symbol_or_address` or `get_safe_path`.

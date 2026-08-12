# Rizin MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)

**Rizin MCP Server** is a server that integrates the **Rizin reverse engineering tool**, **RzGhidra decompiler (pdg)**, and **Mandiant capa behavioral capability identification** with **MCP (Model Context Protocol)**.

It empowers Large Language Models (such as Claude, GPT-4, Llama 3) to automatically open binary files, identify behavioral labels (MITRE ATT&CK / MBC), automatically extract program feature addresses, and directly perform C pseudocode decompilation and analysis.

---

## Repository Structure

```text
rizin-mcp/
├── src/
│   └── rizin_mcp/
│       ├── __init__.py
│       ├── server.py          # Core logic for the MCP Server
│       ├── rz_extractor.py    # Efficient Rizin feature extractor (RizinFeatureExtractor)
│       └── client_proxy.py    # Client proxy for multi-turn tool-calling tests
├── docker/                    # Docker deployment configuration (Dockerfile, compose)
├── tests/                     # Unit tests and validation scripts
├── .gitignore                 # Git ignore configuration
├── LICENSE                    # MIT License
├── README.md                  # Project documentation
└── pyproject.toml             # Project configuration and dependency management (uv / pip)
```

---

## Quick Start

### 1. Installation and Preparation
Use [uv](https://github.com/astral-sh/uv) for fast environment setup and dependency installation:
```bash
git clone https://github.com/kd992102/rizin-mcp.git
cd rizin-mcp
uv sync
```

### 2. Start MCP Server
You can start the MCP Server directly via the package CLI or as a module:
```bash
uv run python -m rizin_mcp.server
```

---

## Testing and Integration

### A. Testing with Anthropic's Official Web UI (MCP Inspector)
```bash
npx @modelcontextprotocol/inspector uv run python -m rizin_mcp.server
```
After executing, open `http://localhost:6274` in your browser to test, view analysis logs, and inspect C decompiled code on the web interface.

### B. Integrating with Claude Desktop
Add the following to `%APPDATA%\Claude\claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "rizin-analyzer": {
      "command": "uv",
      "args": [
        "--directory",
        "C:\\path\\to\\rizin-mcp",
        "run",
        "python",
        "-m",
        "rizin_mcp.server"
      ]
    }
  }
}
```

### C. Deployment using Docker (Headless Mode)
This project supports encapsulating the server in a Docker container for execution:
```bash
docker compose -f docker/docker-compose.yml up -d
```

---

## Provided MCP Tools

| Tool Name | Description |
| :--- | :--- |
| `open_and_analyze` | Open a binary file and perform automatic analysis (`aaa`). |
| `run_capa_analysis` | Use Mandiant capa against capa-rules to identify binary capabilities and feature addresses (supports independent caching). |
| `list_functions` | List all function names, addresses, and sizes (supports keyword filtering). |
| `decompile_function` | Call RzGhidra (pdg) to decompile a specific address/function into C code. |
| `disassemble_function` | Get the assembly disassembly for a specific function. |
| `get_binary_info` | Get architectural information such as Headers, Sections, Imports, and Exports. |
| `search_strings` | Search for readable strings present in the binary file. |
| `execute_rizin_command` | Execute custom Rizin commands (e.g., `px 64 @ 0x...`). |
| `close_file` | Safely close the currently opened file and session. |

---

## Acknowledgments
This project relies heavily on the excellent work of the open-source community. We would like to express our gratitude to the following projects:

* **[Mandiant capa](https://github.com/mandiant/capa)**: For their powerful automated malware capability detection engine and comprehensive [capa-rules](https://github.com/mandiant/capa-rules).
* **[Rizin](https://github.com/rizinorg/rizin)**: For providing an extremely fast and robust binary analysis framework.
* **[rz-ghidra](https://github.com/rizinorg/rz-ghidra)**: For bringing the formidable Ghidra decompiler to the Rizin ecosystem.

---

## License
This project is licensed under the [MIT License](LICENSE).

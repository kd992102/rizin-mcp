# Rizin MCP Server - Docker Deployment Guide

This directory contains all the configuration files for packaging `rizin-mcp` into a Headless Docker container.

## File Structure

* `Dockerfile`: Built on top of `python:3.12-slim`, it automatically downloads and configures the Linux version of the Rizin binary engine.
* `docker-compose.yml`: Pre-configured persistent Volume mounts (`docker_analysis_cache`, `samples`, `capa-rules`) and container resource limits.
* `.dockerignore`: Excludes Windows-specific binaries, virtual environments, and other non-essential resources.
* `README.md`: This documentation file.

## Quick Start

### 1. Build Image

```bash
docker compose -f docker/docker-compose.yml build
```

### 2. Connect and Use Stdio MCP Server

Add the following to your Claude Desktop or MCP Client configuration:

```json
{
  "mcpServers": {
    "rizin-analyzer": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v", "docker_analysis_cache:/app/.analysis_cache",
        "-v", "${PWD}/samples:/samples",
        "docker-rizin-mcp"
      ]
    }
  }
}
```

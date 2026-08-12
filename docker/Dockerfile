# ==============================================================================
# Rizin MCP Server - Headless Dockerfile
# ==============================================================================

FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    xz-utils \
    ca-certificates \
    zlib1g \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Download and extract the pre-compiled Rizin v0.9.0 + rz-ghidra decompiler plugin
# TODO: Replace the URL below with the URL of the file uploaded to your GitHub Releases
RUN curl -L -o /tmp/rizin-ghidra-v0.9.0-linux-x86_64.tar.gz "https://github.com/USERNAME/rizin-mcp/releases/download/v0.1.0/rizin-ghidra-v0.9.0-linux-x86_64.tar.gz" \
    && tar -xzf /tmp/rizin-ghidra-v0.9.0-linux-x86_64.tar.gz -C / \
    && rm /tmp/rizin-ghidra-v0.9.0-linux-x86_64.tar.gz \
    && ldconfig

# Install Python dependency management tool uv
RUN pip install --no-cache-dir uv

# 2. Create application working directory
WORKDIR /app

# Copy project configuration and install Python dependencies (including flare-capa, rzpipe, mcp)
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY capa-rules/ ./capa-rules/

# Install project packages and flare-capa dependencies via uv
RUN uv pip install --system -e .

# If the local machine does not have the capa-rules repository, automatically clone the official Mandiant capa-rules
RUN if [ ! -d "/app/capa-rules" ] || [ -z "$(ls -A /app/capa-rules)" ]; then \
    git clone --depth 1 https://github.com/mandiant/capa-rules /app/capa-rules; \
    fi

# 3. Create cache directory and setup non-root user (for better container security)
RUN mkdir -p /app/.analysis_cache /samples && \
    useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app /samples

USER appuser

# Set default environment variables
ENV PYTHONUNBUFFERED=1

# 4. Run MCP Server by default (Stdio mode)
ENTRYPOINT ["python", "-m", "rizin_mcp.server"]

# ==============================================================================
# Rizin MCP Server - Headless Dockerfile
# ==============================================================================

FROM python:3.12-slim

# 1. 安裝系統基本軟體包與 Linux 版 Rizin (0.7.3)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    xz-utils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 下載並安裝 Rizin Linux 官方二進位版本
RUN curl -sSL https://github.com/rizinorg/rizin/releases/download/v0.7.3/rizin-v0.7.3-x86_64.tar.gz | tar -xz -C /usr/local --strip-components=1

# 安裝 Python 依賴管理工具 uv
RUN pip install --no-cache-dir uv

# 2. 建立應用程式工作目錄
WORKDIR /app

# 複製專案設定檔並安裝 Python 相依套件
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY capa-rules/ ./capa-rules/

# 透過 uv 安裝專案套件
RUN uv pip install --system -e .

# 3. 建立快取目錄與設定非 root 使用者 (提升容器執行安全性)
RUN mkdir -p /app/.analysis_cache /samples && \
    useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app /samples

USER appuser

# 設定預設環境變數
ENV PYTHONUNBUFFERED=1

# 4. 預設執行 MCP Server (Stdio 模式)
ENTRYPOINT ["python", "-m", "rizin_mcp.server"]

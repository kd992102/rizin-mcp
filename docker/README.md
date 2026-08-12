# Rizin MCP Server - Docker 部署指南

本資料夾包含了將 `rizin-mcp` 封裝為 Headless Docker 容器的所有設定檔。

## 📁 檔案結構

* `Dockerfile`: 基於 `python:3.12-slim` 建置，自動下載並配置 Linux 版 Rizin 二進位引擎。
* `docker-compose.yml`: 預先配置持久化 Volume 掛載（`.analysis_cache`、`samples`、`capa-rules`）與容器安全限制。
* `.dockerignore`: 排除 Windows 專用二進位檔與虛擬環境等非必要資源。
* `README.md`: 本說明文件。

## 🚀 快速開始

### 1. 建置 Image

```bash
docker compose -f docker/docker-compose.yml build
```

### 2. 連接與使用 Stdio MCP Server

在 Claude Desktop 或 MCP Client 配置中加入：

```json
{
  "mcpServers": {
    "rizin-analyzer": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v", "${PWD}/.analysis_cache:/app/.analysis_cache",
        "-v", "${PWD}/samples:/samples",
        "docker-rizin-mcp"
      ]
    }
  }
}
```

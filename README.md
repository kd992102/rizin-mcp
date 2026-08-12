# Rizin MCP Server 🚀

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)

**Rizin MCP Server** 是將 **Rizin 逆向工程工具**、**RzGhidra 反編譯器 (pdg)** 以及 **Mandiant capa 行為特徵識別** 與 **MCP (Model Context Protocol)** 整合的伺服器。

讓大語言模型 (如 Claude, GPT-4, Llama 3) 具備自動開啟二進位檔案、行為標籤識別 (MITRE ATT&CK / MBC)、自動提取程式特徵位址並直接進行 C 語言虛擬碼反編譯與分析的能力。

---

## 📁 專案架構 (Repository Structure)

```text
rizin-mcp/
├── src/
│   └── rizin_mcp/
│       ├── __init__.py
│       ├── server.py          # MCP Server 核心邏輯
│       ├── rz_extractor.py    # 高效 Rizin 特徵提取器 (RizinFeatureExtractor)
│       └── client_proxy.py    # Client 代理與多輪 Tool-calling 測試
├── docker/                    # Docker 部署相關設定檔 (Dockerfile, compose)
├── tests/                     # 單元測試與驗證腳本
├── .gitignore                 # Git 忽略組態檔
├── LICENSE                    # MIT 授權條款
├── README.md                  # 專案說明文件
└── pyproject.toml             # 專案組態與依賴管理 (uv / pip)
```

---

## ⚡️ 快速開始 (Quick Start)

### 1. 安裝與準備
使用 [uv](https://github.com/astral-sh/uv) 進行快速環境與依賴安裝：
```bash
git clone https://github.com/your-username/rizin-mcp.git
cd rizin-mcp
uv sync
```

### 2. 啟動 MCP Server
你可以直接透過套件 CLI 或模組方式啟動 MCP Server：
```bash
uv run python -m rizin_mcp.server
```

---

## 🌐 測試與整合

### A. 使用 Anthropic 官方 Web UI (MCP Inspector) 測試
```bash
npx @modelcontextprotocol/inspector uv run python -m rizin_mcp.server
```
執行後在瀏覽器開啟 `http://localhost:6274` 即可在網頁介面上進行測試、檢視分析紀錄與 C 語言反編譯程式碼。

### B. 整合 Claude Desktop
在 `%APPDATA%\Claude\claude_desktop_config.json` 中新增：
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

### C. 使用 Docker 部署 (Headless 模式)
本專案支援將伺服器封裝於 Docker 容器中執行：
```bash
docker compose -f docker/docker-compose.yml up -d
```

---

## 🛠️ 提供之 MCP Tools

| 工具名稱 | 功能描述 |
| :--- | :--- |
| `open_and_analyze` | 開啟二進位檔案並執行自動分析 (`aaa`) |
| `run_capa_analysis` | 使用 Mandiant capa 比對 capa-rules 識別二進位行為能力與特徵位址 (支援獨立快取) |
| `list_functions` | 列出所有函式名稱、位址與大小 (支援關鍵字過濾) |
| `decompile_function` | 調用 RzGhidra (pdg) 將指定位址/函式反編譯為 C 語言程式碼 |
| `disassemble_function` | 取得指定函式的組合語言 (Assembly) 反組譯 |
| `get_binary_info` | 取得檔頭、Sections、Imports、Exports 等架構資訊 |
| `search_strings` | 搜尋二進位檔案中出現的可讀字串 |
| `execute_rizin_command` | 執行自訂 Rizin 指令 (如 `px 64 @ 0x...`) |
| `close_file` | 安全關閉當前開啟的檔案與 Session |

---

## 📄 License
本專案採用 [MIT License](LICENSE) 授權。

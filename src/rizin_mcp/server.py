import os
import sys
import re
import json
import contextlib
import subprocess
import traceback
import concurrent.futures
from pathlib import Path
from typing import Dict, Any, Optional
import rzpipe
from mcp.server import MCPServer

import capa.rules
import capa.main
from rizin_mcp.rz_extractor import RizinFeatureExtractor

# 自動定位與設定 Rizin, Ghidra Sleigh 與 Capa 規則路徑
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(PACKAGE_DIR, "..", ".."))

LOCAL_RIZIN_BIN = os.path.join(PROJECT_ROOT, "rizin-win-installer-clang_cl-64", "bin")
if os.path.exists(LOCAL_RIZIN_BIN):
    os.environ["PATH"] = LOCAL_RIZIN_BIN + os.path.pathsep + os.environ.get("PATH", "")

SLEIGH_PATH = os.path.join(PROJECT_ROOT, "rizin-win-installer-clang_cl-64", "lib", "rizin", "plugins", "rz_ghidra_sleigh")
CAPA_RULES_PATH = os.path.join(PROJECT_ROOT, "capa-rules")

ALLOWED_BASE_DIR = os.path.abspath(os.getcwd())

def get_safe_path(user_path: str) -> str:
    """驗證與轉換安全的檔案路徑，防止 Path Traversal 攻擊"""
    target_path = os.path.abspath(os.path.join(ALLOWED_BASE_DIR, user_path))
    if not os.path.exists(target_path):
        abs_user_path = os.path.abspath(user_path)
        if os.path.exists(abs_user_path):
            return abs_user_path
        raise FileNotFoundError(f"找不到指定的檔案: {user_path}")
    return target_path

def sanitize_symbol_or_address(identifier: str) -> str:
    """清理位址或符號名稱，防止在 Rizin 命令列中注入多重指令 (Command Injection)"""
    cleaned = identifier.strip()
    if not re.match(r"^[a-zA-Z0-9_\.\+\-]+$", cleaned):
        raise ValueError(f"安全警報：不合法或包含潛在危險字元的位址/符號名稱: '{identifier}'")
    return cleaned

@contextlib.contextmanager
def suppress_stderr():
    """抑制 C 層與 stderr 輸出，確保 Stdio MCP 通訊管道純淨"""
    try:
        stderr_fd = sys.stderr.fileno()
        saved_stderr_fd = os.dup(stderr_fd)
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, stderr_fd)
        yield
    except Exception:
        yield
    finally:
        try:
            os.dup2(saved_stderr_fd, stderr_fd)
            os.close(saved_stderr_fd)
            os.close(devnull)
        except Exception:
            pass

# 全域 Session 物件與快取的 RuleSet
CURRENT_RZ: Optional[rzpipe.open] = None
CURRENT_FILE_PATH: Optional[str] = None
CACHED_RULESET: Optional[capa.rules.RuleSet] = None

def get_capa_ruleset() -> capa.rules.RuleSet:
    """快取並載入 capa-rules 規則庫 (相容 capa 9.x pathlib.Path 需求)"""
    global CACHED_RULESET
    if CACHED_RULESET is None:
        if not os.path.exists(CAPA_RULES_PATH):
            raise FileNotFoundError(f"找不到 capa-rules 規則庫目錄: {CAPA_RULES_PATH}")
        
        rule_paths = []
        for root, _, files in os.walk(CAPA_RULES_PATH):
            for f in files:
                if f.endswith((".yml", ".yaml")):
                    rule_paths.append(Path(os.path.join(root, f)))
        
        if hasattr(capa.rules, "get_rules"):
            CACHED_RULESET = capa.rules.get_rules(rule_paths)
        else:
            rules_list = [capa.rules.Rule.from_yaml_file(str(p)) for p in rule_paths]
            CACHED_RULESET = capa.rules.RuleSet(rules_list)
            
    return CACHED_RULESET

# 初始化 MCPServer
server = MCPServer("rizin-analyzer")

@server.tool(
    name="open_and_analyze",
    description="開啟並自動分析二進位檔案。在對檔案進行任何反編譯、反組譯或查詢前必須先呼叫此工具。"
)
def open_and_analyze(file_path: str, analyze_level: str = "aaa") -> str:
    global CURRENT_RZ, CURRENT_FILE_PATH
    try:
        safe_path = get_safe_path(file_path)
        
        if CURRENT_RZ is not None:
            try:
                CURRENT_RZ.quit()
            except Exception:
                pass
            CURRENT_RZ = None
            CURRENT_FILE_PATH = None
        
        with suppress_stderr():
            rz = rzpipe.open(safe_path, flags=["-e", "bin.cache=true"])
            if os.path.exists(SLEIGH_PATH):
                rz.cmd(f"e ghidra.sleighhome={SLEIGH_PATH}")
            rz.cmd("e log.level=0")
            
            level = analyze_level if analyze_level in ["a", "aa", "aaa", "aaaa"] else "aaa"
            rz.cmd(level)
            
            info_raw = rz.cmd("iIj")
            info = json.loads(info_raw) if info_raw else {}
            
            funcs_raw = rz.cmd("aflj")
            funcs = json.loads(funcs_raw) if funcs_raw else []
        
        CURRENT_RZ = rz
        CURRENT_FILE_PATH = safe_path
        
        return json.dumps({
            "status": "success",
            "message": f"成功載入並分析檔案: {os.path.basename(safe_path)}",
            "file_path": safe_path,
            "architecture": info.get("arch"),
            "format": info.get("bintype"),
            "bits": info.get("bits"),
            "endian": info.get("endian"),
            "total_functions": len(funcs)
        }, ensure_ascii=False, indent=2)

    except Exception as e:
        return json.dumps({"status": "error", "message": f"分析失敗: {str(e)}"}, ensure_ascii=False)

@server.tool(
    name="run_capa_analysis",
    description="【極速 Rizin Extractor 模式】自動比對 capa-rules 識別惡意能力。支援指定 max_functions (預設500) 與 timeout_seconds 超時門檻 (預設30秒)。"
)
def run_capa_analysis(file_path: str = "", timeout_seconds: int = 30, max_functions: int = 500) -> str:
    global CURRENT_RZ, CURRENT_FILE_PATH
    
    if file_path and file_path.strip():
        safe_input = get_safe_path(file_path)
        if CURRENT_FILE_PATH != safe_input:
            open_res = open_and_analyze(safe_input)
            if "error" in open_res:
                return open_res

    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "未指定檔案且目前無開啟的檔案，請先呼叫 open_and_analyze。"})
    
    try:
        rules = get_capa_ruleset()
        
        def _execute_capa():
            extractor = RizinFeatureExtractor(CURRENT_RZ, max_functions=max_functions)
            return capa.main.find_capabilities(rules, extractor)

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_execute_capa)
            try:
                capa_res = future.result(timeout=timeout_seconds)
            except concurrent.futures.TimeoutError:
                return json.dumps({
                    "status": "warning",
                    "message": f"capa 分析達到 {timeout_seconds} 秒超時限制保護門檻，已自動安全中斷以防止 MCP 連線通訊逾時。",
                    "hint": "你可以嘗試設置較小的 max_functions (如 max_functions=200) 以提高檢索速度。"
                }, ensure_ascii=False, indent=2)
            
        result_capabilities = []
        
        rules_matches = {}
        if hasattr(capa_res, "matches"):
            rules_matches = capa_res.matches
        elif hasattr(capa_res, "rules"):
            rules_matches = capa_res.rules
        elif isinstance(capa_res, tuple) and len(capa_res) > 0:
            rules_matches = capa_res[0]
        elif isinstance(capa_res, dict):
            rules_matches = capa_res

        for rule_name, rule_matches in rules_matches.items():
            rule = rules[rule_name]
            meta = rule.meta
            
            addresses = []
            locs = []
            if hasattr(rule_matches, "locations"):
                locs = rule_matches.locations
            elif isinstance(rule_matches, (tuple, list)):
                locs = rule_matches
            elif isinstance(rule_matches, dict):
                locs = rule_matches.get("locations", [])

            for match_item in locs:
                addr_val = None
                if isinstance(match_item, tuple) and len(match_item) > 0:
                    addr_val = match_item[0]
                else:
                    addr_val = match_item
                    
                if hasattr(addr_val, "value"):
                    v = addr_val.value
                    if isinstance(v, int):
                        addresses.append(hex(v))
                    elif v is not None and "Result object" not in str(v):
                        addresses.append(str(v))
                elif isinstance(addr_val, int):
                    addresses.append(hex(addr_val))
                elif isinstance(addr_val, str) and "Result object" not in addr_val:
                    addresses.append(addr_val)
                    
            result_capabilities.append({
                "rule": rule_name,
                "namespace": meta.get("namespace", ""),
                "scopes": meta.get("scopes", []),
                "attack": meta.get("attack", []),
                "mbc": meta.get("mbc", []),
                "matched_addresses": addresses[:5]
            })
            
        return json.dumps({
            "status": "success",
            "mode": "Rizin Feature Extractor (Ultra Fast)",
            "file_path": CURRENT_FILE_PATH,
            "total_capabilities": len(result_capabilities),
            "capabilities": result_capabilities
        }, ensure_ascii=False, indent=2)

    except Exception as e:
        tb = traceback.format_exc()
        return json.dumps({"status": "error", "message": f"capa 分析失敗: {str(e)}", "traceback": tb}, ensure_ascii=False, indent=2)

@server.tool(
    name="list_functions",
    description="列出目前檔案中所有已被分析出來的函式。支援用關鍵字過濾函式名稱或位址。"
)
def list_functions(filter_keyword: str = "") -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "尚未開啟並分析任何檔案，請先呼叫 open_and_analyze。"})
    
    try:
        with suppress_stderr():
            funcs_raw = CURRENT_RZ.cmd("aflj")
            funcs = json.loads(funcs_raw) if funcs_raw else []
        
        result = []
        filter_lower = filter_keyword.lower().strip()
        for f in funcs:
            name = f.get("name", "")
            addr = hex(f.get("offset", 0))
            size = f.get("size", 0)
            if not filter_lower or filter_lower in name.lower() or filter_lower in addr.lower():
                result.append({
                    "name": name,
                    "address": addr,
                    "size": size,
                    "nargs": f.get("nargs", 0),
                    "nlocals": f.get("nlocals", 0)
                })
        
        return json.dumps({
            "status": "success",
            "count": len(result),
            "functions": result
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"取得函式列表失敗: {str(e)}"})

@server.tool(
    name="decompile_function",
    description="使用 Ghidra 反編譯器將指定的記憶體位址 (如 0x140001000) 或函式名稱 (如 fcn.140001000, main) 反編譯為 C 語言虛擬碼。"
)
def decompile_function(address_or_name: str) -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "尚未開啟並分析任何檔案，請先呼叫 open_and_analyze。"})
    
    try:
        safe_target = sanitize_symbol_or_address(address_or_name)
        with suppress_stderr():
            CURRENT_RZ.cmd(f"s {safe_target}")
            CURRENT_RZ.cmd("af")
            c_code = CURRENT_RZ.cmd("pdg")
        
        if not c_code or not c_code.strip():
            return json.dumps({
                "status": "warning",
                "message": f"位址/名稱 '{address_or_name}' 無法反編譯或無回傳程式碼。",
                "code": ""
            })
            
        return json.dumps({
            "status": "success",
            "target": address_or_name,
            "code": c_code
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"反編譯失敗: {str(e)}"})

@server.tool(
    name="disassemble_function",
    description="取得指定函式/位址的組合語言 (Assembly) 反組譯輸出。"
)
def disassemble_function(address_or_name: str) -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "尚未開啟並分析任何檔案，請先呼叫 open_and_analyze。"})
    
    try:
        safe_target = sanitize_symbol_or_address(address_or_name)
        with suppress_stderr():
            CURRENT_RZ.cmd(f"s {safe_target}")
            asm_code = CURRENT_RZ.cmd("pdf")
            
        return json.dumps({
            "status": "success",
            "target": address_or_name,
            "disassembly": asm_code
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"反組譯失敗: {str(e)}"})

@server.tool(
    name="get_binary_info",
    description="取得目前二進位檔案的詳細標頭、Sections (節區)、Imports (匯入表)、Exports (匯出表) 等資訊。"
)
def get_binary_info() -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "尚未開啟並分析任何檔案，請先呼叫 open_and_analyze。"})
    
    try:
        with suppress_stderr():
            info = json.loads(CURRENT_RZ.cmd("iIj") or "{}")
            imports = json.loads(CURRENT_RZ.cmd("iij") or "[]")
            sections = json.loads(CURRENT_RZ.cmd("iSj") or "[]")
            exports = json.loads(CURRENT_RZ.cmd("iEj") or "[]")
            
        return json.dumps({
            "status": "success",
            "info": info,
            "sections_count": len(sections),
            "imports_count": len(imports),
            "exports_count": len(exports),
            "imports_sample": imports[:20],
            "sections": sections
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"取得二進位資訊失敗: {str(e)}"})

@server.tool(
    name="search_strings",
    description="搜尋二進位檔案中出現的可讀字串。支援傳入 query 關鍵字過濾。"
)
def search_strings(query: str = "") -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "尚未開啟並分析任何檔案，請先呼叫 open_and_analyze。"})
    
    try:
        with suppress_stderr():
            strings_raw = CURRENT_RZ.cmd("izj")
            strings = json.loads(strings_raw) if strings_raw else []
        
        query_lower = query.lower().strip()
        matched = []
        for s in strings:
            string_val = s.get("string", "")
            if not query_lower or query_lower in string_val.lower():
                matched.append({
                    "address": hex(s.get("vaddr", 0)),
                    "type": s.get("type"),
                    "string": string_val
                })
        
        return json.dumps({
            "status": "success",
            "total_matched": len(matched),
            "strings": matched[:100]
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"字串搜尋失敗: {str(e)}"})

@server.tool(
    name="execute_rizin_command",
    description="[高權限工具] 直接對 Rizin 執行自訂指令 (例如 `px 64 @ 0x140001000`, `afl` 等)。"
)
def execute_rizin_command(command: str) -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "尚未開啟並分析任何檔案，請先呼叫 open_and_analyze。"})
    
    try:
        with suppress_stderr():
            output = CURRENT_RZ.cmd(command)
            
        return json.dumps({
            "status": "success",
            "command": command,
            "output": output
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"執行指令失敗: {str(e)}"})

@server.tool(
    name="close_file",
    description="關閉當前開啟的二進位檔案與 Rizin Session。"
)
def close_file() -> str:
    global CURRENT_RZ, CURRENT_FILE_PATH
    if CURRENT_RZ is None:
        return json.dumps({"status": "info", "message": "目前無開啟的檔案。"})
    
    try:
        with suppress_stderr():
            CURRENT_RZ.quit()
        CURRENT_RZ = None
        CURRENT_FILE_PATH = None
        return json.dumps({"status": "success", "message": "已成功關閉檔案與 Rizin Session。"})
    except Exception as e:
        return json.dumps({"status": "error", "message": f"關閉檔案失敗: {str(e)}"})

def main():
    """Main entry point for running the server via CLI."""
    server.run()

if __name__ == "__main__":
    main()

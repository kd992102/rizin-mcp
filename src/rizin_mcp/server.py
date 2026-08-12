import os
import sys
import re
import json
import hashlib
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

# 分析結果持久化快取目錄
ANALYSIS_CACHE_DIR = os.path.join(PROJECT_ROOT, ".analysis_cache")
os.makedirs(ANALYSIS_CACHE_DIR, exist_ok=True)

ALLOWED_BASE_DIR = os.path.abspath(os.getcwd())


def get_file_sha256(file_path: str) -> str:
    """計算檔案的 SHA-256 雜湊值作為快取 Key"""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_cache_file_path(file_path: str) -> str:
    """根據檔案 SHA-256 雜湊生成快取檔案路徑"""
    file_sha256 = get_file_sha256(file_path)
    cache_filename = f"{file_sha256}_full.json"
    return os.path.join(ANALYSIS_CACHE_DIR, cache_filename)

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

SAVED_CONSOLE_FD: Optional[int] = None


def log_info(msg: str):
    """將乾淨透明的 Log 寫入真實主控台，讓使用者在 Terminal 或 Inspector 中及時觀察進度"""
    formatted = f"[rizin-mcp] {msg}\n"
    if SAVED_CONSOLE_FD is not None:
        try:
            os.write(SAVED_CONSOLE_FD, formatted.encode("utf-8", errors="ignore"))
            return
        except Exception:
            pass
    try:
        sys.stderr.write(formatted)
        sys.stderr.flush()
    except Exception:
        pass


@contextlib.contextmanager
def suppress_stderr():
    """抑制 C 層與 stderr 雜訊輸出，同時保留 SAVED_CONSOLE_FD 給 log_info 使用"""
    global SAVED_CONSOLE_FD
    saved_stderr_fd = None
    devnull = None
    try:
        stderr_fd = sys.stderr.fileno()
        saved_stderr_fd = os.dup(stderr_fd)
        SAVED_CONSOLE_FD = saved_stderr_fd
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, stderr_fd)
    except Exception:
        pass

    try:
        yield
    finally:
        try:
            if saved_stderr_fd is not None:
                os.dup2(saved_stderr_fd, sys.stderr.fileno())
                os.close(saved_stderr_fd)
            if devnull is not None:
                os.close(devnull)
            SAVED_CONSOLE_FD = None
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
        filename = os.path.basename(safe_path)
        log_info(f"[INFO] 正在載入二進位檔案: {filename}")
        
        if CURRENT_RZ is not None:
            log_info("[INFO] 關閉前一次 Rizin Session...")
            try:
                CURRENT_RZ.quit()
            except Exception:
                pass
            CURRENT_RZ = None
            CURRENT_FILE_PATH = None
        
        import time
        t0 = time.time()
        level = analyze_level if analyze_level in ["a", "aa", "aaa", "aaaa"] else "aaa"
        log_info(f"[INFO] 啟動 Rizin 分析引擎 (分析層級: '{level}')...")
        
        with suppress_stderr():
            rz = rzpipe.open(safe_path, flags=["-e", "bin.cache=true"])
            if os.path.exists(SLEIGH_PATH):
                rz.cmd(f"e ghidra.sleighhome={SLEIGH_PATH}")
            rz.cmd("e log.level=0")
            rz.cmd(level)
            
            info_raw = rz.cmd("iIj")
            info = json.loads(info_raw) if info_raw else {}
            
            funcs_raw = rz.cmd("aflj")
            funcs = json.loads(funcs_raw) if funcs_raw else []
        
        t1 = time.time()
        CURRENT_RZ = rz
        CURRENT_FILE_PATH = safe_path
        
        log_info(f"[SUCCESS] Rizin 分析完成！共識別出 {len(funcs)} 個函式，歷時 {t1 - t0:.2f} 秒。")
        
        return json.dumps({
            "status": "success",
            "message": f"成功載入並分析檔案: {filename}",
            "file_path": safe_path,
            "architecture": info.get("arch"),
            "format": info.get("bintype"),
            "bits": info.get("bits"),
            "endian": info.get("endian"),
            "total_functions": len(funcs)
        }, ensure_ascii=False, indent=2)

    except Exception as e:
        log_info(f"[ERROR] 分析失敗: {str(e)}")
        return json.dumps({"status": "error", "message": f"分析失敗: {str(e)}"}, ensure_ascii=False)

@server.tool(
    name="run_capa_analysis",
    description="【極速 Rizin Extractor 模式】利用已由 open_and_analyze 分析好的 Rizin Session 比對 capa-rules 識別惡意能力。必須先呼叫 open_and_analyze。會完整分析所有函式直至完成，自動支援磁碟快取，若已分析過直接讀檔回傳。"
)
def run_capa_analysis(force_reanalysis: bool = False) -> str:
    global CURRENT_RZ, CURRENT_FILE_PATH
    
    if CURRENT_RZ is None or not CURRENT_FILE_PATH:
        log_info("[ERROR] 尚未開啟並分析任何檔案！請先呼叫 open_and_analyze。")
        return json.dumps({"status": "error", "message": "尚未開啟並分析任何檔案，請先呼叫 open_and_analyze 開啟檔案。"}, ensure_ascii=False)

    target_path = CURRENT_FILE_PATH
    filename = os.path.basename(target_path)
    log_info(f"[INFO] 開始準備對 {filename} 進行 capa 惡意能力特徵比對...")

    # 1. 檢查快取：若未指定強制重新分析，先檢查快取檔
    cache_file = get_cache_file_path(target_path)
    cache_name = os.path.basename(cache_file)
    log_info(f"[CACHE] 檢查磁碟快取檔 ({cache_name})...")
    if not force_reanalysis and os.path.exists(cache_file):
        try:
            log_info(f"[CACHE] 成功命中磁碟快取 ({cache_name})！直接讀取分析結果...")
            with open(cache_file, "r", encoding="utf-8") as f:
                cached_data = json.load(f)
            cached_data["cached"] = True
            cached_data["message"] = "讀取快取分析結果成功 (Cached)"
            return json.dumps(cached_data, ensure_ascii=False, indent=2)
        except Exception:
            log_info("[WARN] 快取檔讀取異常，將重新進行比對...")

    # 2. 使用由 open_and_analyze 建立的 CURRENT_RZ 進行完整 capa 特徵比對 (無限制分析所有函式直至完成)
    try:
        import time
        t0 = time.time()
        log_info("[INFO] 載入 capa 規則庫與初始化 RizinFeatureExtractor (無數量限制模式)...")
        rules = get_capa_ruleset()
        
        with suppress_stderr():
            extractor = RizinFeatureExtractor(CURRENT_RZ, path=Path(target_path), max_functions=0, log_callback=log_info)
            capa_res = capa.main.find_capabilities(rules, extractor)
            
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
            
        t1 = time.time()
        log_info(f"[SUCCESS] capa 惡意能力特徵比對完成！共比對出 {len(result_capabilities)} 項惡意能力，歷時 {t1 - t0:.2f} 秒。")

        response_payload = {
            "status": "success",
            "cached": False,
            "mode": "Rizin Feature Extractor (Full Complete Mode)",
            "file_path": target_path,
            "total_capabilities": len(result_capabilities),
            "capabilities": result_capabilities
        }

        # 3. 將分析結果寫入磁碟快取
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(response_payload, f, ensure_ascii=False, indent=2)
            log_info(f"[CACHE] 已將分析結果寫入磁碟快取檔: {cache_name}")
        except Exception as e:
            log_info(f"[WARN] 寫入分析快取失敗: {e}")

        return json.dumps(response_payload, ensure_ascii=False, indent=2)

    except Exception as e:
        tb = traceback.format_exc()
        log_info(f"[ERROR] capa 分析失敗: {str(e)}")
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

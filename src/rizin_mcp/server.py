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

# Automatically locate and setup Rizin, Ghidra Sleigh, and Capa rules paths
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(PACKAGE_DIR, "..", ".."))

LOCAL_RIZIN_BIN = os.path.join(PROJECT_ROOT, "rizin-win-installer-clang_cl-64", "bin")
if os.path.exists(LOCAL_RIZIN_BIN):
    os.environ["PATH"] = LOCAL_RIZIN_BIN + os.path.pathsep + os.environ.get("PATH", "")

SLEIGH_PATH = os.path.join(PROJECT_ROOT, "rizin-win-installer-clang_cl-64", "lib", "rizin", "plugins", "rz_ghidra_sleigh")
CAPA_RULES_PATH = os.path.join(PROJECT_ROOT, "capa-rules")

# Persistent cache directory for analysis results
ANALYSIS_CACHE_DIR = os.path.join(PROJECT_ROOT, ".analysis_cache")
os.makedirs(ANALYSIS_CACHE_DIR, exist_ok=True)

ALLOWED_BASE_DIR = os.path.abspath(os.getcwd())


def get_file_sha256(file_path: str) -> str:
    """Calculate SHA-256 hash of the file as cache key"""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_cache_file_path(file_path: str) -> str:
    """Generate cache file path based on the file's SHA-256 hash"""
    file_sha256 = get_file_sha256(file_path)
    cache_filename = f"{file_sha256}_full.json"
    return os.path.join(ANALYSIS_CACHE_DIR, cache_filename)

def get_safe_path(user_path: str) -> str:
    """Validate and resolve safe file paths to prevent Path Traversal attacks"""
    target_path = os.path.abspath(os.path.join(ALLOWED_BASE_DIR, user_path))
    if not os.path.exists(target_path):
        abs_user_path = os.path.abspath(user_path)
        if os.path.exists(abs_user_path):
            return abs_user_path
        raise FileNotFoundError(f"Cannot find the specified file: {user_path}")
    return target_path

def sanitize_symbol_or_address(identifier: str) -> str:
    """Sanitize address or symbol name to prevent Command Injection in Rizin command line"""
    cleaned = identifier.strip()
    if not re.match(r"^[a-zA-Z0-9_\.\+\-]+$", cleaned):
        raise ValueError(f"Security Alert: Invalid or potentially dangerous characters in address/symbol name: '{identifier}'")
    return cleaned

SAVED_CONSOLE_FD: Optional[int] = None


def log_info(msg: str):
    """Write clean logs to the real console, allowing users to observe progress in Terminal or Inspector"""
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
    """Suppress C-level and stderr noise output, while preserving SAVED_CONSOLE_FD for log_info to use"""
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

# Global Session object and cached RuleSet
CURRENT_RZ: Optional[rzpipe.open] = None
CURRENT_FILE_PATH: Optional[str] = None
CACHED_RULESET: Optional[capa.rules.RuleSet] = None

def get_capa_ruleset() -> capa.rules.RuleSet:
    """Cache and load capa-rules repository (compatible with capa 9.x pathlib.Path requirement)"""
    global CACHED_RULESET
    if CACHED_RULESET is None:
        if not os.path.exists(CAPA_RULES_PATH):
            raise FileNotFoundError(f"Cannot find capa-rules directory: {CAPA_RULES_PATH}")
        
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

# Initialize MCPServer
server = MCPServer("rizin-analyzer")

@server.tool(
    name="open_and_analyze",
    description="Open and automatically analyze a binary file. This tool must be called before performing any decompilation, disassembly, or queries on the file."
)
def open_and_analyze(file_path: str, analyze_level: str = "aaa") -> str:
    global CURRENT_RZ, CURRENT_FILE_PATH
    try:
        safe_path = get_safe_path(file_path)
        filename = os.path.basename(safe_path)
        log_info(f"[INFO] Loading binary file: {filename}")
        
        if CURRENT_RZ is not None:
            log_info("[INFO] Closing previous Rizin Session...")
            try:
                CURRENT_RZ.quit()
            except Exception:
                pass
            CURRENT_RZ = None
            CURRENT_FILE_PATH = None
        
        import time
        t0 = time.time()
        level = analyze_level if analyze_level in ["a", "aa", "aaa", "aaaa"] else "aaa"
        log_info(f"[INFO] Starting Rizin analysis engine (Analysis level: '{level}')...")
        
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
        
        log_info(f"[SUCCESS] Rizin analysis completed! Identified {len(funcs)} functions, took {t1 - t0:.2f} seconds.")
        
        return json.dumps({
            "status": "success",
            "message": f"Successfully loaded and analyzed file: {filename}",
            "file_path": safe_path,
            "architecture": info.get("arch"),
            "format": info.get("bintype"),
            "bits": info.get("bits"),
            "endian": info.get("endian"),
            "total_functions": len(funcs)
        }, ensure_ascii=False, indent=2)

    except Exception as e:
        log_info(f"[ERROR] Analysis failed: {str(e)}")
        return json.dumps({"status": "error", "message": f"Analysis failed: {str(e)}"}, ensure_ascii=False)

@server.tool(
    name="run_capa_analysis",
    description="[Ultra-fast Rizin Extractor Mode] Use the pre-analyzed Rizin Session from open_and_analyze to match capa-rules and identify malicious capabilities. open_and_analyze must be called first. It fully analyzes all functions until completion, automatically supports disk caching, and directly returns cached results if already analyzed."
)
def run_capa_analysis(force_reanalysis: bool = False) -> str:
    global CURRENT_RZ, CURRENT_FILE_PATH
    
    if CURRENT_RZ is None or not CURRENT_FILE_PATH:
        log_info("[ERROR] No file has been opened and analyzed yet! Please call open_and_analyze first.")
        return json.dumps({"status": "error", "message": "No file has been opened and analyzed. Please call open_and_analyze first."}, ensure_ascii=False)

    target_path = CURRENT_FILE_PATH
    filename = os.path.basename(target_path)
    log_info(f"[INFO] Preparing capa malicious capability matching for {filename}...")

    # 1. Check cache: If forced re-analysis is not specified, check the cache file first
    cache_file = get_cache_file_path(target_path)
    cache_name = os.path.basename(cache_file)
    log_info(f"[CACHE] Checking disk cache file ({cache_name})...")
    if not force_reanalysis and os.path.exists(cache_file):
        try:
            log_info(f"[CACHE] Disk cache hit ({cache_name})! Directly reading analysis results...")
            with open(cache_file, "r", encoding="utf-8") as f:
                cached_data = json.load(f)
            cached_data["cached"] = True
            cached_data["message"] = "Successfully read cached analysis results"
            return json.dumps(cached_data, ensure_ascii=False, indent=2)
        except Exception:
            log_info("[WARN] Cache file read exception, will re-analyze...")

    # 2. Use CURRENT_RZ established by open_and_analyze for full capa feature matching (no function limit until completion)
    try:
        import time
        t0 = time.time()
        log_info("[INFO] Loading capa ruleset and initializing RizinFeatureExtractor (unlimited mode)...")
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
        log_info(f"[SUCCESS] capa malicious capability matching completed! Matched {len(result_capabilities)} capabilities, took {t1 - t0:.2f} seconds.")

        response_payload = {
            "status": "success",
            "cached": False,
            "mode": "Rizin Feature Extractor (Full Complete Mode)",
            "file_path": target_path,
            "total_capabilities": len(result_capabilities),
            "capabilities": result_capabilities
        }

        # 3. Write analysis results to disk cache
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(response_payload, f, ensure_ascii=False, indent=2)
            log_info(f"[CACHE] Analysis results written to disk cache file: {cache_name}")
        except Exception as e:
            log_info(f"[WARN] Failed to write analysis cache: {e}")

        return json.dumps(response_payload, ensure_ascii=False, indent=2)

    except Exception as e:
        tb = traceback.format_exc()
        log_info(f"[ERROR] capa analysis failed: {str(e)}")
        return json.dumps({"status": "error", "message": f"capa analysis failed: {str(e)}", "traceback": tb}, ensure_ascii=False, indent=2)





@server.tool(
    name="list_functions",
    description="List all functions identified in the current file. Supports filtering by function name or address using a keyword."
)
def list_functions(filter_keyword: str = "") -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "No file has been opened and analyzed. Please call open_and_analyze first."})
    
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
        return json.dumps({"status": "error", "message": f"Failed to retrieve function list: {str(e)}"})

@server.tool(
    name="decompile_function",
    description="Use the Ghidra decompiler to decompile a specified memory address (e.g., 0x140001000) or function name (e.g., fcn.140001000, main) into C pseudocode."
)
def decompile_function(address_or_name: str) -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "No file has been opened and analyzed. Please call open_and_analyze first."})
    
    try:
        safe_target = sanitize_symbol_or_address(address_or_name)
        with suppress_stderr():
            CURRENT_RZ.cmd(f"s {safe_target}")
            CURRENT_RZ.cmd("af")
            c_code = CURRENT_RZ.cmd("pdg")
        
        if not c_code or not c_code.strip():
            return json.dumps({
                "status": "warning",
                "message": f"Address/Name '{address_or_name}' cannot be decompiled or returned no code.",
                "code": ""
            })
            
        return json.dumps({
            "status": "success",
            "target": address_or_name,
            "code": c_code
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Decompilation failed: {str(e)}"})

@server.tool(
    name="disassemble_function",
    description="Get the assembly disassembly output for a specified function/address."
)
def disassemble_function(address_or_name: str) -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "No file has been opened and analyzed. Please call open_and_analyze first."})
    
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
        return json.dumps({"status": "error", "message": f"Disassembly failed: {str(e)}"})

@server.tool(
    name="get_binary_info",
    description="Get detailed architectural information of the current binary file, including Headers, Sections, Imports, Exports, etc."
)
def get_binary_info() -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "No file has been opened and analyzed. Please call open_and_analyze first."})
    
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
        return json.dumps({"status": "error", "message": f"Failed to retrieve binary info: {str(e)}"})

@server.tool(
    name="search_strings",
    description="Search for readable strings present in the binary file. Supports filtering with a query keyword."
)
def search_strings(query: str = "") -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "No file has been opened and analyzed. Please call open_and_analyze first."})
    
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
        return json.dumps({"status": "error", "message": f"String search failed: {str(e)}"})

@server.tool(
    name="get_xrefs",
    description="Find and analyze cross-references (Xrefs) and call dependencies for a specified function or address. Supports passing an address/name or global query, returning format includes [{'type': 'CALL', 'from': '0x401000', 'to': '0x402000'}]."
)
def get_xrefs(address_or_name: str = "", xref_type: str = "ALL", limit: int = 100) -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "No file has been opened and analyzed. Please call open_and_analyze first."})
    
    try:
        with suppress_stderr():
            if address_or_name:
                safe_target = sanitize_symbol_or_address(address_or_name)
                CURRENT_RZ.cmd(f"s {safe_target}")
                raw = CURRENT_RZ.cmd("afxj")
                if not raw or raw.strip() in ["", "[]"] or "ERROR" in raw:
                    t_raw = CURRENT_RZ.cmd("axtj")
                    f_raw = CURRENT_RZ.cmd("axfj")
                    t_list = json.loads(t_raw) if t_raw and "ERROR" not in t_raw else []
                    f_list = json.loads(f_raw) if f_raw and "ERROR" not in f_raw else []
                    items = t_list + f_list
                else:
                    items = json.loads(raw)
            else:
                raw = CURRENT_RZ.cmd("axlj")
                items = json.loads(raw) if raw and "ERROR" not in raw else []
        
        type_filter = xref_type.strip().upper()
        xrefs = []
        for item in items:
            f_val = item.get("from")
            t_val = item.get("to")
            x_type = str(item.get("type", "UNKNOWN")).upper()
            
            if type_filter != "ALL" and x_type != type_filter:
                continue
                
            from_addr = hex(f_val) if isinstance(f_val, int) else str(f_val)
            to_addr = hex(t_val) if isinstance(t_val, int) else str(t_val)
            
            xrefs.append({
                "type": x_type,
                "from": from_addr,
                "to": to_addr
            })
            
            if len(xrefs) >= limit:
                break
                
        return json.dumps({
            "status": "success",
            "target": address_or_name if address_or_name else "ALL",
            "count": len(xrefs),
            "xrefs": xrefs
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Cross-reference query failed: {str(e)}"})

@server.tool(
    name="execute_rizin_command",
    description="[High Privilege Tool] Execute custom commands directly in Rizin (e.g., `px 64 @ 0x140001000`, `afl`, etc.)."
)
def execute_rizin_command(command: str) -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "No file has been opened and analyzed. Please call open_and_analyze first."})
    
    try:
        with suppress_stderr():
            output = CURRENT_RZ.cmd(command)
            
        return json.dumps({
            "status": "success",
            "command": command,
            "output": output
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Command execution failed: {str(e)}"})

@server.tool(
    name="close_file",
    description="Close the currently opened binary file and Rizin Session."
)
def close_file() -> str:
    global CURRENT_RZ, CURRENT_FILE_PATH
    if CURRENT_RZ is None:
        return json.dumps({"status": "info", "message": "No file currently open."})
    
    try:
        with suppress_stderr():
            CURRENT_RZ.quit()
        CURRENT_RZ = None
        CURRENT_FILE_PATH = None
        return json.dumps({"status": "success", "message": "Successfully closed the file and Rizin Session."})
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Failed to close file: {str(e)}"})

def main():
    """Main entry point for running the server via CLI."""
    server.run()

if __name__ == "__main__":
    main()

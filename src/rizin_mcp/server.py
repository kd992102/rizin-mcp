import os
import sys
import re
import json
import base64
import hashlib
import contextlib
import subprocess
import time
import threading
import traceback
import uuid
import concurrent.futures
from pathlib import Path
from typing import Dict, Any, Optional
import rzpipe
from mcp.server import MCPServer

import capa.rules
import capa.main
import pefile
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
    """Validate and resolve safe file paths to prevent Path Traversal attacks.

    `os.path.join(base, user_path)` discards `base` entirely whenever `user_path` is already
    absolute, so the previous implementation let any existing absolute path through unchecked.
    This version always resolves relative to ALLOWED_BASE_DIR and explicitly rejects anything
    that resolves outside of it, regardless of whether the input was relative, absolute, or used
    `..` to try to climb out.
    """
    target_path = os.path.abspath(os.path.join(ALLOWED_BASE_DIR, user_path))
    try:
        is_inside_base = os.path.commonpath([target_path, ALLOWED_BASE_DIR]) == ALLOWED_BASE_DIR
    except ValueError:
        # os.path.commonpath raises ValueError when paths are on different drives (Windows) -
        # that can only mean the target is outside ALLOWED_BASE_DIR.
        is_inside_base = False
    if not is_inside_base:
        raise ValueError(f"Access denied: path outside allowed directory: {user_path}")
    if not os.path.exists(target_path):
        raise FileNotFoundError(f"Cannot find the specified file: {user_path}")
    return target_path

def sanitize_symbol_or_address(identifier: str) -> str:
    """Sanitize address or symbol name to prevent Command Injection in Rizin command line"""
    cleaned = identifier.strip()
    if not re.match(r"^[a-zA-Z0-9_\.\+\-]+$", cleaned):
        raise ValueError(f"Security Alert: Invalid or potentially dangerous characters in address/symbol name: '{identifier}'")
    return cleaned


def _parse_rizin_numeric(raw: str) -> Optional[int]:
    """Parse a numeric value out of Rizin's textual output (`s`, `?v`, ...)."""
    if raw is None:
        return None
    value = raw.strip().splitlines()[0].strip() if raw.strip() else ""
    if not value:
        return None
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value, 0)
    except ValueError:
        return None


def resolve_seek_target(rz, target: str) -> int:
    """Resolve a symbol/address string to a concrete numeric address, and only report success
    if Rizin's cursor genuinely moved there.

    This exists because `s <target>` fails *silently* when `target` isn't a flag/symbol Rizin
    recognizes (e.g. a bare import name like `LoadResource` instead of the registered flag
    `sym.imp.KERNEL32.dll_LoadResource`): the cursor just stays wherever the previous command
    left it, and downstream queries (afxj/axtj/axfj) then return results for the *wrong*
    address without raising any error. Callers must treat a ValueError from this function as a
    hard failure rather than falling back to whatever the cursor currently points to.
    """
    safe_target = sanitize_symbol_or_address(target)

    resolved: Optional[int] = None

    # 1) Try Rizin's own numeric evaluator - it understands flags, symbols, hex and decimal.
    try:
        eval_raw = rz.cmd(f"?v {safe_target}")
        candidate = _parse_rizin_numeric(eval_raw)
        if candidate:
            resolved = candidate
    except Exception:
        pass

    # 2) Bare import names (e.g. "LoadResource") are usually not registered as flags, so fall
    #    back to matching them against the import table directly.
    if resolved is None:
        try:
            imports_raw = rz.cmd("iij")
            imports = json.loads(imports_raw) if imports_raw else []
        except Exception:
            imports = []

        target_lower = safe_target.lower()
        for imp in imports:
            name = str(imp.get("name", ""))
            if not name:
                continue
            candidates = {name.lower()}
            if "_" in name:
                candidates.add(name.split("_")[-1].lower())
            if "." in name:
                candidates.add(name.split(".")[-1].lower())
            if target_lower in candidates:
                addr = imp.get("plt") or imp.get("vaddr")
                if addr:
                    resolved = addr
                    break

    if resolved is None:
        raise ValueError(f"Symbol/address not found: '{target}'")

    # 3) Seek, then verify the cursor actually landed on the resolved address instead of
    #    trusting the seek command blindly.
    rz.cmd(f"s {hex(resolved)}")
    current_raw = rz.cmd("s")
    current_addr = _parse_rizin_numeric(current_raw)

    if current_addr != resolved:
        got = current_raw.strip() if current_raw else "<no output>"
        raise ValueError(f"Seek verification failed for '{target}' (expected 0x{resolved:x}, got '{got}')")

    return resolved


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

# P1-6: background job tracking for run_capa_analysis, so a client-side timeout no longer
# leaves the caller unable to tell "actually failed" apart from "still running, check cache
# later". Each entry is stored under both its target_path (to dedupe concurrent starts for the
# same file) and its job_id (for get_capa_status lookups) - both keys point at the same dict.
CAPA_JOBS: Dict[str, Dict[str, Any]] = {}
CAPA_JOBS_LOCK = threading.Lock()
CAPA_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="capa-job")

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

def _confidence_hint_for_meta(meta: Dict[str, Any]) -> str:
    """Classify a matched capa rule as "behavioral" (has an explicit ATT&CK/MBC technique
    mapping - a real, named attack technique), "generic-library" (a namespace-less rule with no
    such mapping - typically a generic crypto/hash/compression fingerprint like Luhn, murmur3,
    CRC32, or aPLib that shows up in almost any statically-linked C/C++ binary), or
    "unclassified" for everything else."""
    has_tags = bool(meta.get("attack")) or bool(meta.get("mbc"))
    is_generic_lib = not has_tags and not meta.get("namespace", "")
    return "behavioral" if has_tags else ("generic-library" if is_generic_lib else "unclassified")


def _summarize_capability_confidence(capabilities) -> Dict[str, int]:
    behavioral_count = sum(1 for c in capabilities if c.get("confidence_hint") == "behavioral")
    generic_library_count = sum(1 for c in capabilities if c.get("confidence_hint") == "generic-library")
    unclassified_count = len(capabilities) - behavioral_count - generic_library_count
    return {
        "behavioral_count": behavioral_count,
        "generic_library_count": generic_library_count,
        "unclassified_count": unclassified_count
    }


def _run_capa_analysis_job(rz, target_path: str, cache_file: str, cache_name: str) -> Dict[str, Any]:
    """The actual (slow) capa analysis. Runs on the CAPA_EXECUTOR background thread so a
    client-side timeout on the calling tool invocation can no longer leave the analysis running
    invisibly - callers now get an explicit job_id to poll via get_capa_status instead.

    NOTE: this reuses the single persistent `rz` (rzpipe) session set up by open_and_analyze.
    Rizin's pipe protocol is not designed for concurrent commands from multiple threads, so
    calling other tools that touch CURRENT_RZ while this job is running is not fully guarded
    against interleaving; treat this as "no more silent timeouts", not "full thread safety".
    """
    t0 = time.time()
    log_info("[INFO] Loading capa ruleset and initializing RizinFeatureExtractor (unlimited mode)...")
    rules = get_capa_ruleset()

    with suppress_stderr():
        extractor = RizinFeatureExtractor(rz, path=Path(target_path), max_functions=0, log_callback=log_info)
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

        # P2-7: separate rules with an explicit ATT&CK/MBC technique mapping from rules that are
        # just generic crypto/hash/compression library fingerprints - see
        # _confidence_hint_for_meta for the full rationale.
        confidence_hint = _confidence_hint_for_meta(meta)

        result_capabilities.append({
            "rule": rule_name,
            "namespace": meta.get("namespace", ""),
            "scopes": meta.get("scopes", []),
            "attack": meta.get("attack", []),
            "mbc": meta.get("mbc", []),
            "confidence_hint": confidence_hint,
            "matched_addresses": addresses[:5],
            "total_matches": len(addresses)
        })

    t1 = time.time()
    log_info(f"[SUCCESS] capa malicious capability matching completed! Matched {len(result_capabilities)} capabilities, took {t1 - t0:.2f} seconds.")

    response_payload = {
        "status": "success",
        "cached": False,
        "mode": "Rizin Feature Extractor (Full Complete Mode)",
        "file_path": target_path,
        "total_capabilities": len(result_capabilities),
        "summary": _summarize_capability_confidence(result_capabilities),
        "capabilities": result_capabilities
    }

    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(response_payload, f, ensure_ascii=False, indent=2)
        log_info(f"[CACHE] Analysis results written to disk cache file: {cache_name}")
    except Exception as e:
        log_info(f"[WARN] Failed to write analysis cache: {e}")

    return response_payload


@server.tool(
    name="run_capa_analysis",
    description="[Ultra-fast Rizin Extractor Mode] Use the pre-analyzed Rizin Session from open_and_analyze to match capa-rules and identify malicious capabilities. open_and_analyze must be called first. Runs in the background: if there's no disk cache yet, this returns immediately with a job_id - poll get_capa_status(job_id) or call this tool again later to read the cached result once analysis completes."
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

    # 2. No usable cache: run capa in the background instead of blocking this call, and hand the
    #    caller a job_id so a client-side timeout no longer means "no idea if this ever finished".
    with CAPA_JOBS_LOCK:
        existing = CAPA_JOBS.get(target_path)
        if existing is not None and not existing["future"].done():
            elapsed = time.time() - existing["started_at"]
            return json.dumps({
                "status": "started",
                "job_id": existing["job_id"],
                "cached": False,
                "message": f"capa analysis for '{filename}' is already running in the background (started {elapsed:.0f}s ago). Poll get_capa_status('{existing['job_id']}') for progress, or call run_capa_analysis() again later to read the cache once it's done."
            }, ensure_ascii=False, indent=2)

        job_id = uuid.uuid4().hex[:16]
        future = CAPA_EXECUTOR.submit(_run_capa_analysis_job, CURRENT_RZ, target_path, cache_file, cache_name)
        job_entry = {"job_id": job_id, "future": future, "started_at": time.time(), "target_path": target_path}
        CAPA_JOBS[target_path] = job_entry
        CAPA_JOBS[job_id] = job_entry

    log_info(f"[INFO] capa analysis started in background job {job_id}")
    return json.dumps({
        "status": "started",
        "job_id": job_id,
        "cached": False,
        "message": f"capa analysis started in the background for '{filename}'. Poll get_capa_status('{job_id}') for progress, or simply call run_capa_analysis() again later - it will return the cached result once analysis finishes."
    }, ensure_ascii=False, indent=2)


@server.tool(
    name="get_capa_status",
    description="Poll the status of a background capa analysis job started by run_capa_analysis. Returns status 'running', 'success', or 'error'; once finished it includes the full analysis result."
)
def get_capa_status(job_id: str) -> str:
    with CAPA_JOBS_LOCK:
        job = CAPA_JOBS.get(job_id)

    if job is None:
        return json.dumps({"status": "error", "message": f"Unknown job_id: '{job_id}'. It may have already completed and been superseded, or never existed."}, ensure_ascii=False)

    future = job["future"]
    if not future.done():
        elapsed = time.time() - job["started_at"]
        return json.dumps({
            "status": "running",
            "job_id": job_id,
            "elapsed_seconds": round(elapsed, 1),
            "message": "capa analysis is still running in the background. Poll again later."
        }, ensure_ascii=False, indent=2)

    exc = future.exception()
    if exc is not None:
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        log_info(f"[ERROR] capa analysis job {job_id} failed: {exc}")
        return json.dumps({
            "status": "error",
            "job_id": job_id,
            "message": f"capa analysis failed: {exc}",
            "traceback": tb
        }, ensure_ascii=False, indent=2)

    result = dict(future.result())
    result["job_id"] = job_id
    return json.dumps(result, ensure_ascii=False, indent=2)





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

def _split_ghidra_warnings(c_code: str):
    """Pull Ghidra's `// WARNING: ...` lines out of decompiled pseudocode into a separate list.

    These warnings (e.g. "Variable defined which should be unmapped", "[rz-ghidra] Detected
    overlap for variable...") repeat per-function and add no value mixed into the `code` field -
    they just eat into the response size budget on every call. Consecutive warning lines are
    merged into a single string in `warnings` for readability.
    """
    if not c_code:
        return c_code, []

    code_lines = []
    warnings = []
    for line in c_code.splitlines():
        if line.strip().startswith("// WARNING:"):
            warnings.append(line.strip()[len("// WARNING:"):].strip())
        else:
            code_lines.append(line)

    clean_code = "\n".join(code_lines)
    return clean_code, warnings


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

        clean_code, warnings = _split_ghidra_warnings(c_code)

        if not clean_code or not clean_code.strip():
            return json.dumps({
                "status": "warning",
                "message": f"Address/Name '{address_or_name}' cannot be decompiled or returned no code.",
                "code": "",
                "warnings": warnings
            })

        return json.dumps({
            "status": "success",
            "target": address_or_name,
            "code": clean_code,
            "warnings": warnings
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


# --- P1-3: PE resource (.rsrc) inspection helpers -------------------------------------------

# Common file-format magic-byte signatures used to sanity-check a resource's declared type
# against its actual content. This is the single most useful signal for spotting a resource
# that claims to be e.g. a PNG/icon but is actually an embedded/disguised executable.
_MAGIC_SIGNATURES = [
    (b"MZ", "PE/EXE"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"BM", "BMP"),
    (b"PK\x03\x04", "ZIP"),
    (b"%PDF", "PDF"),
    (b"\x00\x00\x01\x00", "ICO"),
    (b"\x00\x00\x02\x00", "CUR"),
    (b"<?xml", "XML"),
    (b"\xef\xbb\xbf<?xml", "XML"),
]

# Resource types (by pefile's RT_* name) that are expected to hold binary code/data and should
# NOT be flagged just because their content doesn't look like an image/text format.
_CODE_LIKE_RESOURCE_TYPES = {"RT_RCDATA", "RT_ANICURSOR", "RT_ANIICON", "RT_HTML", "RT_DLGINCLUDE"}


def _detect_magic(data: bytes) -> str:
    for sig, name in _MAGIC_SIGNATURES:
        if data.startswith(sig):
            return name
    return "UNKNOWN"


def _resource_type_mismatch(type_name: str, detected_magic: str) -> Optional[str]:
    """Flag when a resource's declared type is suspiciously inconsistent with its real content.

    The concrete case this exists for: a resource tagged as an image (e.g. an icon/PNG-like
    RT_RCDATA entry) whose bytes actually start with an MZ/PE header - i.e. an embedded,
    disguised executable, which is a high-signal indicator in malware analysis.
    """
    if detected_magic == "PE/EXE" and type_name not in _CODE_LIKE_RESOURCE_TYPES:
        return f"Resource declared as '{type_name}' but content starts with an MZ/PE header - possible embedded/disguised executable."
    if type_name == "RT_BITMAP" and detected_magic not in ("BMP", "UNKNOWN"):
        return f"Resource declared as RT_BITMAP but content looks like {detected_magic}, not BMP."
    if type_name in ("RT_ICON", "RT_GROUP_ICON") and detected_magic in ("PE/EXE", "ZIP", "PDF"):
        return f"Resource declared as '{type_name}' but content looks like {detected_magic}."
    return None


def _load_pe_for_resources():
    """Open the currently analyzed file with pefile for resource inspection.

    Raises ValueError with a clear message if there's no file open, or if it's not a PE.
    """
    if CURRENT_RZ is None or not CURRENT_FILE_PATH:
        raise ValueError("No file has been opened and analyzed. Please call open_and_analyze first.")
    try:
        pe = pefile.PE(CURRENT_FILE_PATH, fast_load=True)
    except pefile.PEFormatError as e:
        raise ValueError(f"Not a valid PE file, cannot inspect resources: {e}")
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    return pe


def _iter_pe_resources(pe):
    """Yield (type_name, res_id, lang_id, data_rva, size) for every leaf resource entry."""
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return
    for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if res_type.name is not None:
            type_name = str(res_type.name)
        else:
            type_id = res_type.struct.Id
            type_name = pefile.RESOURCE_TYPE.get(type_id, str(type_id))

        if not hasattr(res_type, "directory"):
            continue

        for res_id_entry in res_type.directory.entries:
            if res_id_entry.name is not None:
                res_id = str(res_id_entry.name)
            else:
                res_id = str(res_id_entry.struct.Id)

            if not hasattr(res_id_entry, "directory"):
                continue

            for res_lang_entry in res_id_entry.directory.entries:
                lang_id = getattr(res_lang_entry.data, "lang", None)
                data_rva = res_lang_entry.data.struct.OffsetToData
                size = res_lang_entry.data.struct.Size
                yield type_name, res_id, lang_id, data_rva, size


@server.tool(
    name="list_resources",
    description="List every entry in the PE resource table (.rsrc): type, ID, language, size, address, a short hex preview of the raw bytes, and whether the declared type matches the actual content (magic bytes) - a strong signal for embedded/disguised files."
)
def list_resources() -> str:
    try:
        pe = _load_pe_for_resources()
    except ValueError as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False)

    try:
        resources = []
        for type_name, res_id, lang_id, data_rva, size in _iter_pe_resources(pe):
            try:
                raw = pe.get_data(data_rva, size)
            except Exception:
                raw = b""

            detected_magic = _detect_magic(raw)
            mismatch_note = _resource_type_mismatch(type_name, detected_magic)

            resources.append({
                "type": type_name,
                "id": res_id,
                "lang": lang_id,
                "size": size,
                "address": hex(pe.OPTIONAL_HEADER.ImageBase + data_rva),
                "rva": hex(data_rva),
                "preview_hex": raw[:32].hex(),
                "detected_magic": detected_magic,
                "type_content_mismatch": mismatch_note is not None,
                "mismatch_note": mismatch_note
            })

        return json.dumps({
            "status": "success",
            "count": len(resources),
            "resources": resources
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Failed to list resources: {str(e)}"})
    finally:
        try:
            pe.close()
        except Exception:
            pass


@server.tool(
    name="extract_resource",
    description="Extract the raw bytes of a specific PE resource by type and ID (as reported by list_resources), returned base64-encoded, for further file-format/signature analysis. Truncated to max_bytes."
)
def extract_resource(res_type: str, res_id: str, max_bytes: int = 65536) -> str:
    try:
        pe = _load_pe_for_resources()
    except ValueError as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False)

    try:
        max_bytes = max(1, int(max_bytes))
        for type_name, r_id, lang_id, data_rva, size in _iter_pe_resources(pe):
            if type_name != res_type or r_id != res_id:
                continue

            try:
                raw = pe.get_data(data_rva, size)
            except Exception as e:
                return json.dumps({"status": "error", "message": f"Failed to read resource data: {str(e)}"})

            truncated = len(raw) > max_bytes
            chunk = raw[:max_bytes]
            return json.dumps({
                "status": "success",
                "type": type_name,
                "id": r_id,
                "lang": lang_id,
                "total_size": len(raw),
                "returned_size": len(chunk),
                "truncated": truncated,
                "detected_magic": _detect_magic(raw),
                "data_base64": base64.b64encode(chunk).decode("ascii")
            }, ensure_ascii=False, indent=2)

        return json.dumps({"status": "error", "message": f"Resource not found: type='{res_type}', id='{res_id}'"}, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Failed to extract resource: {str(e)}"})
    finally:
        try:
            pe.close()
        except Exception:
            pass


@server.tool(
    name="search_imports",
    description="Search the import table by function name and/or DLL keyword, returning structured JSON (not raw table text). Use this to quickly check whether a binary imports specific APIs, e.g. WriteProcessMemory/CreateRemoteThread/WinINet-family functions."
)
def search_imports(query: str = "", dll: str = "") -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "No file has been opened and analyzed. Please call open_and_analyze first."})

    try:
        with suppress_stderr():
            imports = json.loads(CURRENT_RZ.cmd("iij") or "[]")

        query_lower = query.lower().strip()
        dll_lower = dll.lower().strip()

        results = []
        for imp in imports:
            name = imp.get("name", "")
            libname = imp.get("libname", "")
            if query_lower and query_lower not in name.lower():
                continue
            if dll_lower and dll_lower not in libname.lower():
                continue
            addr = imp.get("plt") or imp.get("vaddr") or 0
            results.append({
                "name": name,
                "libname": libname,
                "vaddr": hex(addr)
            })

        return json.dumps({
            "status": "success",
            "count": len(results),
            "imports": results
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Import search failed: {str(e)}"})


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
                try:
                    resolve_seek_target(CURRENT_RZ, address_or_name)
                except ValueError as e:
                    return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False)

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


def _function_containing_address(rz, addr: int) -> Optional[Dict[str, Any]]:
    """Look up the function that contains `addr`, using Rizin's `@ addr` temporary-seek syntax
    so the global cursor is never disturbed."""
    try:
        raw = rz.cmd(f"afij @ {addr}")
        info = json.loads(raw) if raw and "ERROR" not in raw else []
    except Exception:
        info = []

    if isinstance(info, list) and info:
        f = info[0]
        return {"name": f.get("name"), "address": hex(f.get("offset", 0))}
    return None


@server.tool(
    name="find_import_callers",
    description="Given an imported function name, list every call site that references it and automatically resolve which function (name + start address) each call site belongs to. Collapses the usual 4-5 round-trip 'who calls this dangerous API' workflow into a single call."
)
def find_import_callers(import_name: str) -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "No file has been opened and analyzed. Please call open_and_analyze first."})

    try:
        with suppress_stderr():
            try:
                target_addr = resolve_seek_target(CURRENT_RZ, import_name)
            except ValueError as e:
                return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False)

            axt_raw = CURRENT_RZ.cmd(f"axtj @ {target_addr}")
            axt_items = json.loads(axt_raw) if axt_raw and "ERROR" not in axt_raw else []

            call_sites = []
            for item in axt_items:
                from_addr = item.get("from")
                if from_addr is None:
                    continue
                call_sites.append({
                    "call_site": hex(from_addr) if isinstance(from_addr, int) else str(from_addr),
                    "in_function": _function_containing_address(CURRENT_RZ, from_addr) if isinstance(from_addr, int) else None
                })

        return json.dumps({
            "status": "success",
            "import_name": import_name,
            "target_address": hex(target_addr),
            "count": len(call_sites),
            "call_sites": call_sites
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"find_import_callers failed: {str(e)}"})


def _rizin_command_denial_reason(command: str) -> Optional[str]:
    """Return a reason string if `command` must be blocked, else None.

    execute_rizin_command is intended for read-only static analysis, but a raw Rizin command
    line can also: shell out to the OS (`!...`), open/switch to an arbitrary other file on disk
    (`o`, `o+`, `oo`, ... - potentially bypassing get_safe_path entirely), or mutate the
    currently opened file (the `w*` write-command family). All three are blocked here; commands
    are split on `;`/newlines first since Rizin allows chaining several commands in one call.
    """
    if not command:
        return None
    for sub in re.split(r"[;\n]+", command):
        sub = sub.strip()
        if not sub:
            continue
        if sub.startswith("!"):
            return f"Shell-escape commands are not allowed via execute_rizin_command (read-only tool): '{sub}'"

        head_match = re.match(r"^([A-Za-z][A-Za-z0-9+]*)", sub)
        head = head_match.group(1) if head_match else ""
        if not head:
            continue
        if head[0] == "w":
            return f"Write commands are not allowed via execute_rizin_command (read-only tool): '{sub}'"
        if head[0] == "o":
            return f"File open/switch commands are not allowed via execute_rizin_command (read-only tool, and this can bypass path restrictions): '{sub}'"
    return None


@server.tool(
    name="execute_rizin_command",
    description="[High Privilege Tool - read-only] Execute custom commands directly in Rizin (e.g., `px 64 @ 0x140001000`, `afl`, etc.). Large outputs are paginated: pass `offset`/`limit` (character counts) to page through them using the `next_offset` returned when `truncated` is true. Shell-escape ('!'), file open/switch ('o*'), and write ('w*') commands are blocked."
)
def execute_rizin_command(command: str, offset: int = 0, limit: int = 20000) -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "No file has been opened and analyzed. Please call open_and_analyze first."})

    denial_reason = _rizin_command_denial_reason(command)
    if denial_reason:
        return json.dumps({"status": "error", "message": denial_reason}, ensure_ascii=False)

    try:
        offset = max(0, int(offset))
        limit = max(1, int(limit))
        with suppress_stderr():
            output = CURRENT_RZ.cmd(command)

        output = output or ""
        total = len(output)
        chunk = output[offset:offset + limit]
        next_offset = offset + len(chunk)
        truncated = next_offset < total

        return json.dumps({
            "status": "success",
            "command": command,
            "output": chunk,
            "total_length": total,
            "truncated": truncated,
            "next_offset": next_offset if truncated else None
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

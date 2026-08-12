import os
import sys
import time
import contextlib
from pathlib import Path
import rzpipe
import capa.rules
import capa.main
from rizin_mcp.rz_extractor import RizinFeatureExtractor


@contextlib.contextmanager
def suppress_stderr():
    """抑制 C 層與 stderr 輸出，保持控制台輸出乾淨"""
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


# 確保 PATH 包含專案內建的 Rizin
LOCAL_RIZIN_BIN = os.path.abspath("rizin-win-installer-clang_cl-64/bin")
if os.path.exists(LOCAL_RIZIN_BIN):
    os.environ["PATH"] = LOCAL_RIZIN_BIN + os.path.pathsep + os.environ.get("PATH", "")

target_bin = r"C:\Users\kd992\OneDrive\桌面\resume\teamt5\m2\m2.docx.exe"
if not os.path.exists(target_bin):
    target_bin = r"C:\Windows\SysWOW64\notepad.exe"

rules_path = "capa-rules"

print(f"1. Opening Rizin session for {target_bin}...")
t0 = time.time()
with suppress_stderr():
    rz = rzpipe.open(target_bin)
    rz.cmd("e log.level=0")
    rz.cmd("aaa")
t1 = time.time()
print(f"   Rizin aaa analysis done in {t1 - t0:.2f} seconds.")

print("\n2. Loading capa rules (capa 9.x compatibility)...")
rule_paths = [Path(os.path.join(root, f)) for root, _, files in os.walk(rules_path) for f in files if f.endswith((".yml", ".yaml"))]
if hasattr(capa.rules, "get_rules"):
    rules = capa.rules.get_rules(rule_paths)
else:
    rules = capa.rules.RuleSet.from_directory(rules_path)

print("\n3. Running capa with RizinFeatureExtractor...")
t2 = time.time()
with suppress_stderr():
    extractor = RizinFeatureExtractor(rz, max_functions=100)
    capabilities = capa.main.find_capabilities(rules, extractor)
t3 = time.time()
print(f"   capa matching done in {t3 - t2:.2f} seconds!")

matches = getattr(capabilities, "matches", capabilities)
print(f"\nTotal Capabilities Matched: {len(matches)}")
for r_name in list(matches.keys())[:15]:
    rule = rules[r_name]
    print(f"  - {r_name} (Namespace: {rule.meta.get('namespace')})")

with suppress_stderr():
    rz.quit()



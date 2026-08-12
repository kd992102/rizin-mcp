import os
import sys
import json
import contextlib
import rzpipe

@contextlib.contextmanager
def suppress_stderr():
    stderr_fd = sys.stderr.fileno()
    saved_stderr_fd = os.dup(stderr_fd)
    devnull = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(devnull, stderr_fd)
        yield
    finally:
        os.dup2(saved_stderr_fd, stderr_fd)
        os.close(saved_stderr_fd)
        os.close(devnull)

# 由命令行參數讀取 target_file，或預設範例檔名
target_file = sys.argv[1] if len(sys.argv) > 1 else "sample.exe"

if not os.path.exists(target_file):
    print(f"提示: 找不到測試檔案 '{target_file}'。")
    print("用法: python rizin_test.py <path_to_binary>")
    sys.exit(1)

# 自動尋找 local rizin bin
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
local_rizin_bin = os.path.join(PROJECT_ROOT, "rizin-win-installer-clang_cl-64", "bin")
if os.path.exists(local_rizin_bin):
    os.environ["PATH"] = local_rizin_bin + os.path.pathsep + os.environ.get("PATH", "")

sleigh_path = os.path.join(PROJECT_ROOT, "rizin-win-installer-clang_cl-64", "lib", "rizin", "plugins", "rz_ghidra_sleigh")

print(f"Analyzing binary: {target_file}...")
with suppress_stderr():
    rz = rzpipe.open(target_file)
    if os.path.exists(sleigh_path):
        rz.cmd(f"e ghidra.sleighhome={sleigh_path}")
    rz.cmd("e log.level=0")
    rz.cmd("aaa")
    functions = rz.cmdj("aflj")
    rz.quit()

output_data = {}
if functions:
    for fn in functions:
        name = fn.get("name")
        addr = hex(fn.get("offset", 0))
        size = fn.get("size", 0)
        output_data[name] = {
            "address": addr,
            "size": size
        }

output_file = "functions.json"
with open(output_file, "w", encoding="utf-8") as f:
    json.dump(output_data, f, indent=4, ensure_ascii=False)

print(f"=== 成功找到 {len(functions if functions else [])} 個函式，結果已儲存至 {output_file} ===")

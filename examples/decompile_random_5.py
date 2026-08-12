import os
import sys
import json
import random
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

target_file = sys.argv[1] if len(sys.argv) > 1 else "sample.exe"
json_file = "functions.json"

if not os.path.exists(target_file):
    print(f"提示: 找不到測試檔案 '{target_file}'。")
    print("用法: python decompile_random_5.py <path_to_binary>")
    sys.exit(1)

if not os.path.exists(json_file):
    print(f"錯誤: 找不到 {json_file}，請先執行 rizin_test.py 產生！")
    sys.exit(1)

with open(json_file, "r", encoding="utf-8") as f:
    all_functions = json.load(f)

if not all_functions:
    print("錯誤: functions.json 中沒有任何函式！")
    sys.exit(1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
local_rizin_bin = os.path.join(PROJECT_ROOT, "rizin-win-installer-clang_cl-64", "bin")
if os.path.exists(local_rizin_bin):
    os.environ["PATH"] = local_rizin_bin + os.path.pathsep + os.environ.get("PATH", "")

sleigh_path = os.path.join(PROJECT_ROOT, "rizin-win-installer-clang_cl-64", "lib", "rizin", "plugins", "rz_ghidra_sleigh")

num_to_sample = min(5, len(all_functions))
selected_func_names = random.sample(list(all_functions.keys()), num_to_sample)

print(f"=== 從 {json_file} 隨機挑選 {num_to_sample} 個函式進行反編譯 ===")
for name in selected_func_names:
    print(f"  - {name} (位址: {all_functions[name]['address']})")
print("=" * 60)

decompiled_results = {}

with suppress_stderr():
    rz = rzpipe.open(target_file)
    if os.path.exists(sleigh_path):
        rz.cmd(f"e ghidra.sleighhome={sleigh_path}")
    rz.cmd("e log.level=0")
    rz.cmd("aaa")

for name in selected_func_names:
    addr = all_functions[name]["address"]
    print(f"\n[+] 正在反編譯: {name} ({addr})...")
    
    with suppress_stderr():
        rz.cmd(f"s {addr}")
        rz.cmd("af")
        c_code = rz.cmd("pdg")
    
    decompiled_results[name] = {
        "address": addr,
        "size": all_functions[name]["size"],
        "code": c_code
    }
    
    print(c_code)
    print("-" * 50)

with suppress_stderr():
    rz.quit()

output_file = "decompiled_5.json"
with open(output_file, "w", encoding="utf-8") as f:
    json.dump(decompiled_results, f, indent=4, ensure_ascii=False)

print(f"\n=== 所有反編譯結果已成功儲存至 {output_file} ===")

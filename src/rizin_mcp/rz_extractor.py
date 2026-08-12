"""Rizin Feature Extractor for Mandiant capa 9.4+.

Extremely fast feature extractor that translates Rizin disassembler & analysis
data directly into capa engine features, bypassing slow Vivisect backend.
"""

import json
from pathlib import Path
from typing import Tuple, Generator, Dict, Any, Set, List, Optional, Callable

from capa.features.extractors.base_extractor import (
    StaticFeatureExtractor,
    FunctionHandle,
    BBHandle,
    InsnHandle,
    SampleHashes,
)
from capa.features.address import Address, AbsoluteVirtualAddress, NO_ADDRESS
from capa.features.common import (
    Feature,
    String,
    Substring,
    Characteristic,
    OS,
    Arch,
    Format,
    OS_WINDOWS,
    FORMAT_PE,
    FORMAT_ELF,
    ARCH_I386,
    ARCH_AMD64,
    Bytes,
)
from capa.features.file import Import, Export, Section
from capa.features.basicblock import BasicBlock
from capa.features.insn import API, Number, Offset, Mnemonic, OperandNumber
import capa.features.extractors.helpers as helpers


class RizinFeatureExtractor(StaticFeatureExtractor):
    def __init__(
        self,
        rz_instance,
        buf: Optional[bytes] = None,
        path: Optional[Path] = None,
        max_functions: int = 500,
        log_callback: Optional[Callable[[str], None]] = None,
    ):
        self.rz = rz_instance
        self.max_functions = max_functions
        self.buf = buf
        self.log_callback = log_callback
        self.analyzed_func_count = 0

        if self.buf is None and path is not None and path.exists():
            try:
                self.buf = path.read_bytes()
            except Exception:
                self.buf = None

        if self.buf is None and hasattr(self.rz, "filename") and self.rz.filename:
            try:
                p = Path(str(self.rz.filename))
                if p.exists() and p.is_file():
                    self.buf = p.read_bytes()
            except Exception:
                self.buf = None

        if self.buf is not None:
            hashes = SampleHashes.from_bytes(self.buf)
        else:
            hashes = SampleHashes(
                md5="0" * 32,
                sha1="0" * 40,
                sha256="0" * 64,
            )
        super().__init__(hashes=hashes)

        # 1. Pre-cache headers, strings, imports, exports, sections, and function info
        try:
            info_raw = self.rz.cmd("iIj")
            self.info = json.loads(info_raw) if info_raw else {}
        except Exception:
            self.info = {}

        try:
            imports_raw = self.rz.cmd("iij")
            self.imports = json.loads(imports_raw) if imports_raw else []
        except Exception:
            self.imports = []

        try:
            exports_raw = self.rz.cmd("iEj")
            self.exports = json.loads(exports_raw) if exports_raw else []
        except Exception:
            self.exports = []

        try:
            sections_raw = self.rz.cmd("iSj")
            self.sections = json.loads(sections_raw) if sections_raw else []
        except Exception:
            self.sections = []

        try:
            strings_raw = self.rz.cmd("izj")
            self.strings = json.loads(strings_raw) if strings_raw else []
        except Exception:
            self.strings = []

        try:
            funcs_raw = self.rz.cmd("aflj")
            self.funcs = json.loads(funcs_raw) if funcs_raw else []
        except Exception:
            self.funcs = []

        if self.max_functions > 0 and len(self.funcs) > self.max_functions:
            self.funcs = self.funcs[:self.max_functions]

        # Highly efficient O(1) index hash table
        self.func_by_addr: Dict[int, Dict[str, Any]] = {}
        self.func_addresses: Set[int] = set()
        for f in self.funcs:
            offset = f.get("offset")
            if offset is not None:
                self.func_by_addr[offset] = f
                self.func_addresses.add(offset)

        self.import_names: Set[str] = set()
        self.import_by_addr: Dict[int, Dict[str, Any]] = {}
        for imp in self.imports:
            name = imp.get("name", "")
            plt = imp.get("plt", 0) or imp.get("vaddr", 0)
            if plt:
                self.import_by_addr[plt] = imp
            if name:
                self.import_names.add(name)
                if "_" in name:
                    self.import_names.add(name.split("_")[-1])
                if "." in name:
                    self.import_names.add(name.split(".")[-1])

    def get_base_address(self) -> Address:
        baddr = self.info.get("baddr")
        if baddr is not None and isinstance(baddr, int) and baddr != 0:
            return AbsoluteVirtualAddress(baddr)
        vaddr = self.info.get("vaddr")
        if vaddr is not None and isinstance(vaddr, int) and vaddr != 0:
            return AbsoluteVirtualAddress(vaddr)
        return AbsoluteVirtualAddress(0x400000)

    def get_summary(self):
        return {
            "format": self.info.get("bintype", "pe"),
            "arch": self.info.get("arch", "x86"),
            "os": self.info.get("os", "windows"),
        }

    def has_function(self, addr: int) -> bool:
        return addr in self.func_addresses

    def is_library_function(self, addr: Address) -> bool:
        addr_int = int(addr)
        f = self.func_by_addr.get(addr_int)
        if f:
            name = f.get("name", "")
            if f.get("is_lib") or name.startswith(("sym.imp.", "reloc.", "imp.")):
                return True
        return False

    def get_function_name(self, addr: Address) -> str:
        addr_int = int(addr)
        f = self.func_by_addr.get(addr_int)
        if f and f.get("name"):
            return f.get("name")
        return f"sub_{addr_int:x}"

    def extract_global_features(self) -> Generator[Tuple[Feature, Address], None, None]:
        bintype = str(self.info.get("bintype", "pe")).lower()
        if "pe" in bintype:
            yield Format(FORMAT_PE), NO_ADDRESS
        elif "elf" in bintype:
            yield Format(FORMAT_ELF), NO_ADDRESS

        os_str = str(self.info.get("os", "windows")).lower()
        if "win" in os_str:
            yield OS(OS_WINDOWS), NO_ADDRESS
        elif "linux" in os_str:
            yield OS("linux"), NO_ADDRESS
        elif "darwin" in os_str or "mac" in os_str:
            yield OS("macos"), NO_ADDRESS
        else:
            yield OS(os_str), NO_ADDRESS

        arch_str = str(self.info.get("arch", "x86")).lower()
        bits = self.info.get("bits", 32)
        if "x86" in arch_str or "i386" in arch_str:
            if bits == 64:
                yield Arch(ARCH_AMD64), NO_ADDRESS
            else:
                yield Arch(ARCH_I386), NO_ADDRESS
        else:
            yield Arch(Arch(arch_str)), NO_ADDRESS

    def extract_file_features(self) -> Generator[Tuple[Feature, Address], None, None]:
        # 1. Sections
        for sec in self.sections:
            sec_name = sec.get("name", "")
            vaddr = sec.get("vaddr", 0)
            if sec_name:
                yield Section(sec_name), AbsoluteVirtualAddress(vaddr)

        # 2. Exports
        for exp in self.exports:
            exp_name = exp.get("name", "")
            vaddr = exp.get("vaddr", 0)
            if exp_name:
                yield Export(exp_name), AbsoluteVirtualAddress(vaddr)

        # 3. Imports
        for imp in self.imports:
            libname = imp.get("libname", "")
            impname = imp.get("name", "")
            vaddr = imp.get("plt", 0) or imp.get("vaddr", 0)
            addr = AbsoluteVirtualAddress(vaddr) if vaddr else NO_ADDRESS

            if impname:
                for name in helpers.generate_symbols(libname, impname, include_dll=True):
                    yield Import(name), addr

        # 4. Strings
        for s_item in self.strings:
            s_val = s_item.get("string", "")
            vaddr = s_item.get("vaddr", 0)
            if s_val:
                yield String(s_val), AbsoluteVirtualAddress(vaddr)
                yield Substring(s_val), AbsoluteVirtualAddress(vaddr)

    def get_functions(self) -> Generator[FunctionHandle, None, None]:
        for f in self.funcs:
            offset = f.get("offset")
            if offset is not None:
                yield FunctionHandle(address=AbsoluteVirtualAddress(offset), inner=f)

    def extract_function_features(self, f: FunctionHandle) -> Generator[Tuple[Feature, Address], None, None]:
        func_dict = f.inner if isinstance(f.inner, dict) else {}

        # Characteristic: calls to
        codexrefs = func_dict.get("codexrefs", [])
        if isinstance(codexrefs, list):
            for xref in codexrefs:
                if isinstance(xref, dict) and xref.get("type") == "CALL":
                    yield Characteristic("calls to"), f.address
        elif func_dict.get("indegree", 0) > 0:
            for _ in range(func_dict.get("indegree", 0)):
                yield Characteristic("calls to"), f.address

        # Characteristic: loop
        if func_dict.get("loops", 0) > 0:
            yield Characteristic("loop"), f.address

    def get_basic_blocks(self, f: FunctionHandle) -> Generator[BBHandle, None, None]:
        if "ops_by_bb" not in f.ctx:
            self.analyzed_func_count += 1
            total = len(self.funcs)
            if self.log_callback and (self.analyzed_func_count == 1 or self.analyzed_func_count % 30 == 0 or self.analyzed_func_count == total):
                f_name = f.inner.get("name", "") if isinstance(f.inner, dict) else ""
                self.log_callback(f"[PROGRESS] capa feature matching progress: [{self.analyzed_func_count}/{total}] Profiling 0x{int(f.address):x} ({f_name})...")

            addr_int = int(f.address)
            try:
                blocks_raw = self.rz.cmd(f"afbj @ {addr_int}")
                blocks = json.loads(blocks_raw) if blocks_raw else []
            except Exception:
                blocks = []

            try:
                disasm_raw = self.rz.cmd(f"pdfj @ {addr_int}")
                pdf_data = json.loads(disasm_raw) if disasm_raw else {}
                ops = pdf_data.get("ops", []) if isinstance(pdf_data, dict) else []
            except Exception:
                ops = []

            ops_by_bb: Dict[int, List[Dict[str, Any]]] = {}
            for b in blocks:
                b_addr = b.get("addr")
                b_size = b.get("size", 0)
                if b_addr is not None:
                    bb_ops = [op for op in ops if b_addr <= op.get("offset", -1) < b_addr + b_size]
                    ops_by_bb[b_addr] = bb_ops

            f.ctx["blocks"] = blocks
            f.ctx["ops_by_bb"] = ops_by_bb

        for b in f.ctx.get("blocks", []):
            addr = b.get("addr")
            if addr is not None:
                yield BBHandle(address=AbsoluteVirtualAddress(addr), inner=b)


    def extract_basic_block_features(self, f: FunctionHandle, bb: BBHandle) -> Generator[Tuple[Feature, Address], None, None]:
        yield BasicBlock(), bb.address

        bb_dict = bb.inner if isinstance(bb.inner, dict) else {}
        bb_addr = int(bb.address)

        if bb_dict.get("jump") == bb_addr:
            yield Characteristic("tight loop"), bb.address

    def extract_bb_features(self, f: FunctionHandle, bb: BBHandle) -> Generator[Tuple[Feature, Address], None, None]:
        yield from self.extract_basic_block_features(f, bb)

    def get_instructions(self, f: FunctionHandle, bb: BBHandle) -> Generator[InsnHandle, None, None]:
        ops_by_bb = f.ctx.get("ops_by_bb", {})
        ops = ops_by_bb.get(int(bb.address), [])

        for op in ops:
            op_addr = op.get("offset")
            if op_addr is not None:
                yield InsnHandle(address=AbsoluteVirtualAddress(op_addr), inner=op)

    def extract_insn_features(self, f: FunctionHandle, bb: BBHandle, insn: InsnHandle) -> Generator[Tuple[Feature, Address], None, None]:
        op = insn.inner
        if not isinstance(op, dict):
            return

        op_addr = insn.address
        disasm = op.get("disasm", "") or op.get("opcode", "")
        mnemonic = op.get("type", "") or (disasm.split()[0].lower() if disasm else "")
        if mnemonic:
            yield Mnemonic(mnemonic.lower()), op_addr

        op_type = op.get("type", "")

        # 1. API Calls
        if op_type in ["call", "ucall", "jmp", "ujmp"]:
            target_addr = op.get("ptr") or op.get("jump") or op.get("val")
            matched_import = None
            if target_addr and target_addr in self.import_by_addr:
                matched_import = self.import_by_addr[target_addr]

            if matched_import:
                libname = matched_import.get("libname", "")
                impname = matched_import.get("name", "")
                for sym in helpers.generate_symbols(libname, impname):
                    yield API(sym), op_addr
            else:
                for name in self.import_names:
                    if name.lower() in disasm.lower():
                        yield API(name), op_addr

        # 2. Indirect Call Check
        if op_type == "ucall" or (op_type == "call" and ("[" in disasm or any(r in disasm.lower() for r in ["eax", "ebx", "ecx", "edx", "esi", "edi", "rax", "rbx", "rcx", "rdx", "rsi", "rdi"]))):
            yield Characteristic("indirect call"), op_addr

        # 3. Call $+5 Check
        if op_type == "call":
            jump_addr = op.get("jump")
            size = op.get("size", 0)
            if jump_addr and jump_addr == int(op_addr) + size:
                yield Characteristic("call $+5"), op_addr

        # 4. NZXOR Check
        if op_type == "xor":
            parts = disasm.lower().replace(",", " ").split()
            regs = [p for p in parts if p in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "ax", "bx", "cx", "dx", "al", "bl", "cl", "dl"]]
            if len(regs) >= 2 and regs[0] != regs[1]:
                yield Characteristic("nzxor"), op_addr

        # 5. PEB / Segment Access Check
        if "fs:" in disasm.lower() or "gs:" in disasm.lower():
            yield Characteristic("segment access"), op_addr
            if "0x30" in disasm or "0x60" in disasm or "fs:[0x30]" in disasm.lower() or "gs:[0x60]" in disasm.lower():
                yield Characteristic("peb access"), op_addr

        # 6. Immediate Numbers & Operand Numbers
        val = op.get("val")
        if val is not None and isinstance(val, int):
            yield Number(val), op_addr
            yield OperandNumber(0, val), op_addr

        opex = op.get("opex")
        if isinstance(opex, dict) and "operands" in opex:
            operands = opex.get("operands", [])
            for idx, operand in enumerate(operands):
                if isinstance(operand, dict):
                    if operand.get("type") == "imm" and isinstance(operand.get("value"), int):
                        imm_val = operand["value"]
                        yield Number(imm_val), op_addr
                        yield OperandNumber(idx, imm_val), op_addr
                    elif operand.get("type") == "mem" and isinstance(operand.get("disp"), int):
                        disp_val = operand["disp"]
                        if disp_val != 0:
                            yield Offset(disp_val), op_addr

        # 7. Bytes
        bytes_hex = op.get("bytes")
        if bytes_hex and len(bytes_hex) >= 2:
            try:
                b_val = bytes.fromhex(bytes_hex)
                if len(b_val) > 0:
                    yield Bytes(b_val), op_addr
            except Exception:
                pass

    def extract_instruction_features(self, f: FunctionHandle, bb: BBHandle, insn: InsnHandle) -> Generator[Tuple[Feature, Address], None, None]:
        yield from self.extract_insn_features(f, bb, insn)

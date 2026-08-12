"""Rizin Feature Extractor for Mandiant capa 9.4.

Extremely fast feature extractor that translates Rizin disassembler & analysis
data directly into capa engine features, bypassing slow Vivisect backend.
"""

import json
import re
import hashlib
from typing import Tuple, List, Generator, Dict, Any, Set
from capa.features.extractors.base_extractor import (
    StaticFeatureExtractor,
    FunctionHandle,
    BBHandle,
    InsnHandle,
)
from capa.features.common import (
    Feature,
    String,
    Substring,
    Characteristic,
    OS,
    Arch,
    Format,
)
from capa.features.insn import API, Number, Offset, Mnemonic

try:
    from capa.features.freeze import Hashes
except ImportError:
    try:
        from capa.features.freeze.main import Hashes
    except ImportError:
        class Hashes:
            def __init__(self, md5: str = "0"*32, sha1: str = "0"*40, sha256: str = "0"*64):
                self.md5 = md5
                self.sha1 = sha1
                self.sha256 = sha256

class RizinFunctionHandle(FunctionHandle):
    def __init__(self, address: int, name: str, data: Dict[str, Any]):
        super().__init__(address, data)
        self.name = name
        self.data = data

class RizinBBHandle(BBHandle):
    def __init__(self, address: int, data: Dict[str, Any]):
        super().__init__(address, data)
        self.data = data

class RizinInsnHandle(InsnHandle):
    def __init__(self, address: int, data: Dict[str, Any]):
        super().__init__(address, data)
        self.data = data

class RizinFeatureExtractor(StaticFeatureExtractor):
    def __init__(self, rz_instance, max_functions: int = 500):
        hashes = Hashes(
            md5="0" * 32,
            sha1="0" * 40,
            sha256="0" * 64,
        )
        super().__init__(hashes=hashes)
        
        self.rz = rz_instance
        self.max_functions = max_functions
        
        # 1. 預先快取檔頭、字串、匯入表、函式資訊
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

        self.func_addresses: Set[int] = set()
        for f in self.funcs:
            offset = f.get("offset")
            if offset is not None:
                self.func_addresses.add(offset)

        self.import_names: Set[str] = set()
        for imp in self.imports:
            name = imp.get("name", "")
            if name:
                self.import_names.add(name)
                if "_" in name:
                    self.import_names.add(name.split("_")[-1])
                if "." in name:
                    self.import_names.add(name.split(".")[-1])

    def get_summary(self):
        return {
            "format": self.info.get("bintype", "pe"),
            "arch": self.info.get("arch", "x86"),
            "os": "windows",
        }

    def has_function(self, addr: int) -> bool:
        return addr in self.func_addresses

    def extract_global_features(self) -> Generator[Tuple[Feature, int], None, None]:
        bintype = str(self.info.get("bintype", "pe")).lower()
        if "pe" in bintype:
            yield Format("pe"), 0
        elif "elf" in bintype:
            yield Format("elf"), 0

        yield OS("windows"), 0

        bits = self.info.get("bits", 32)
        if bits == 64:
            yield Arch("amd64"), 0
        else:
            yield Arch("i386"), 0

    def extract_file_features(self) -> Generator[Tuple[Feature, int], None, None]:
        for s_item in self.strings:
            s_val = s_item.get("string", "")
            vaddr = s_item.get("vaddr", 0)
            if s_val:
                yield String(s_val), vaddr
                yield Substring(s_val), vaddr

        for name in self.import_names:
            yield API(name), 0

    def get_functions(self) -> Generator[RizinFunctionHandle, None, None]:
        for f in self.funcs:
            offset = f.get("offset")
            name = f.get("name", "")
            if offset is not None:
                yield RizinFunctionHandle(offset, name, f)

    def extract_function_features(self, f: RizinFunctionHandle) -> Generator[Tuple[Feature, int], None, None]:
        yield from ()

    def get_basic_blocks(self, f: RizinFunctionHandle) -> Generator[RizinBBHandle, None, None]:
        blocks = []
        try:
            blocks_raw = self.rz.cmd(f"afbj @ {f.address}")
            if blocks_raw:
                blocks = json.loads(blocks_raw)
        except Exception:
            blocks = []
            
        for b in blocks:
            addr = b.get("addr")
            if addr is not None:
                yield RizinBBHandle(addr, b)

    def extract_basic_block_features(self, f: RizinFunctionHandle, bb: RizinBBHandle) -> Generator[Tuple[Feature, int], None, None]:
        yield from ()

    def extract_bb_features(self, f: RizinFunctionHandle, bb: RizinBBHandle) -> Generator[Tuple[Feature, int], None, None]:
        yield from ()

    def get_instructions(self, f: RizinFunctionHandle, bb: RizinBBHandle) -> Generator[RizinInsnHandle, None, None]:
        ops = []
        try:
            addr = bb.address
            size = bb.data.get("size", 0)
            if size > 0:
                disasm_raw = self.rz.cmd(f"pDj {size} @ {addr}")
                if disasm_raw:
                    ops = json.loads(disasm_raw)
        except Exception:
            ops = []

        for op in ops:
            op_addr = op.get("offset")
            if op_addr is not None:
                yield RizinInsnHandle(op_addr, op)

    def extract_insn_features(self, f: RizinFunctionHandle, bb: RizinBBHandle, insn: RizinInsnHandle) -> Generator[Tuple[Feature, int], None, None]:
        op = insn.data
        disasm = op.get("disasm", "")
        mnemonic = op.get("mnemonic", "")
        op_addr = insn.address

        if mnemonic:
            yield Mnemonic(mnemonic.lower()), op_addr

        if op.get("type") in ["call", "ucall"]:
            for name in self.import_names:
                if name.lower() in disasm.lower():
                    yield API(name), op_addr

        val = op.get("val")
        if val is not None and isinstance(val, int):
            yield Number(val), op_addr

    def extract_instruction_features(self, f: RizinFunctionHandle, bb: RizinBBHandle, insn: RizinInsnHandle) -> Generator[Tuple[Feature, int], None, None]:
        return self.extract_insn_features(f, bb, insn)

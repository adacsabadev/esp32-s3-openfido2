"""Compile the production store for ARM and emulate capacity/power-cut tests.

Dependencies: unicorn and pyelftools, installed into build/storage-test-deps.
Flash, legacy NVS and crypto are mocked; this does not prove physical flash
timing, cryptography, or browser interoperability.
"""
from pathlib import Path
import subprocess
import sys
import time

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / "build/storage-test-deps"))
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
                              UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)

cm = "--cm" in sys.argv
if cm:
    sys.argv.remove("--cm")
output = root / ("build/cm-test.elf" if cm else "build/storage-test.elf")
sources = [root / "tests/storage/test_cm.c"] if cm else [root / "tests/storage/test_store.c"]
if cm:
    sources += [root / ("main/" + name + ".c") for name in
                ("ctap2", "cred_mgmt", "pin_token", "cbor_min",
                 "fido_ble_framing", "u2f", "u2f_attestation", "ctaphid")]
compiler = Path(r"C:\Program Files (x86)\Arm GNU Toolchain arm-none-eabi\14.2 rel1\bin\arm-none-eabi-gcc.exe")
subprocess.run([str(compiler), "-mcpu=cortex-m3", "-mthumb", "-O2", "-g",
               "-ffreestanding", "-fno-builtin", "-nostdlib", *(["-DTEST_WITH_HID"] if cm else []),
               "-I" + str(root / "tests/storage"), "-I" + str(root / "main"),
               "-Wl,-e,test_basic,-Ttext=0x10000", *map(str,sources),
               "-lgcc", "-o", str(output)], check=True)
with output.open("rb") as stream:
    elf = ELFFile(stream)
    segments = [(seg["p_vaddr"], seg.data()) for seg in elf.iter_segments()
                if seg["p_type"] == "PT_LOAD"]
    symbols = {sym.name: sym["st_value"] for sym in
               elf.get_section_by_name(".symtab").iter_symbols()}

def libc(uc, address, size, name):
    a, b, n = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
    if name == "memcpy":
        if n:
            uc.mem_write(a, bytes(uc.mem_read(b, n)))
        result = a
    elif name == "memset":
        if n:
            uc.mem_write(a, bytes([b & 255]) * n)
        result = a
    else:
        left, right = bytes(uc.mem_read(a, n)), bytes(uc.mem_read(b, n))
        result = next((x-y for x, y in zip(left, right) if x != y), 0)
    uc.reg_write(UC_ARM_REG_R0, result & 0xffffffff)
    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

tests = sys.argv[1:] or (["test_credential_management", "test_scoped_client_pin", "test_cm_capacity", "test_authenticator_identity", "test_ble_framing", "test_u2f_apdu", "test_u2f_operations", "test_u2f_failures", "test_u2f_hid"] if cm else
                         ["test_basic", "test_backup_import", "test_migration", "test_powerloss", "test_capacity", "test_bank_migration"])
for name in tests:
    print("Running " + name, flush=True)
    started = time.monotonic()
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(0x10000, 0x3000000)
    cpu.mem_map(0x20000000, 0x40000)
    cpu.mem_map(0x30000000, 0x1000)
    for address, data in segments:
        cpu.mem_write(address, data)
    for function in ("memcpy", "memset", "memcmp"):
        address = symbols[function] & ~1
        cpu.hook_add(UC_HOOK_CODE, libc, user_data=function, begin=address, end=address)
    cpu.reg_write(UC_ARM_REG_SP, 0x2003fff0)
    cpu.reg_write(UC_ARM_REG_LR, 0x30000001)
    cpu.emu_start(symbols[name] | 1, 0x30000000, timeout=600000000, count=4000000000)
    if cpu.reg_read(UC_ARM_REG_PC) != 0x30000000:
        raise SystemExit(name + ": instruction/time limit reached")
    result = cpu.reg_read(UC_ARM_REG_R0)
    if result:
        raise SystemExit(f"{name}: regression failed at test_store.c:{result}")
    print(f"PASS {name} ({time.monotonic()-started:.1f}s)", flush=True)

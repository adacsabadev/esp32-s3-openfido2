"""Run production U2F/certificate/storage code in Unicorn with real host P-256.

This verifies wire signatures independently. ESP-IDF's PSA driver, GPIO and
physical flash still require hardware verification. No private keys are saved.
"""
import hashlib
import os
from pathlib import Path
import runpy
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

runner = Path(__file__).with_name("run.py")
sys.argv = [str(runner), "--cm", "test_u2f_crypto_prepare"]
env = runpy.run_path(str(runner))
Uc, symbols, segments = env["Uc"], env["symbols"], env["segments"]
from unicorn import UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
cpu.mem_map(0x10000, 0x3000000)
cpu.mem_map(0x20000000, 0x40000)
cpu.mem_map(0x30000000, 0x1000)
for address, data in segments:
    cpu.mem_write(address, data)
for name in ("memcpy", "memset", "memcmp"):
    address = symbols[name] & ~1
    cpu.hook_add(UC_HOOK_CODE, env["libc"], user_data=name, begin=address, end=address)

def read(address, size):
    return bytes(cpu.mem_read(address, size))

def scalar(address):
    return ec.derive_private_key(int.from_bytes(read(address+72, 32), "big"), ec.SECP256R1())

def hook(uc, address, size, name):
    a, b, c, d = [uc.reg_read(r) for r in
                  (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
    result = 1
    if name == "crypto_hash":
        uc.mem_write(c, hashlib.sha256(read(a, b)).digest())
    elif name == "crypto_generate":
        key = ec.generate_private_key(ec.SECP256R1())
        uc.mem_write(a+8, os.urandom(32))
        uc.mem_write(a+72, key.private_numbers().private_value.to_bytes(32, "big"))
        point = key.public_key().public_bytes(serialization.Encoding.X962,
                                              serialization.PublicFormat.UncompressedPoint)
        uc.mem_write(b, point[1:33]);uc.mem_write(c, point[33:])
    elif name == "crypto_public_key":
        point = scalar(a).public_key().public_bytes(serialization.Encoding.X962,
                                                   serialization.PublicFormat.UncompressedPoint)
        uc.mem_write(b, point[1:33]);uc.mem_write(c, point[33:])
    elif name == "crypto_sign":
        signature = scalar(a).sign(read(b, c), ec.ECDSA(hashes.SHA256()))
        length_pointer = struct.unpack("<I", read(uc.reg_read(UC_ARM_REG_SP), 4))[0]
        uc.mem_write(d, signature)
        uc.mem_write(length_pointer, struct.pack("<I", len(signature)))
    uc.reg_write(UC_ARM_REG_R0, result)
    uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

for name in ("crypto_hash", "crypto_generate", "crypto_public_key", "crypto_sign"):
    address = symbols[name] & ~1
    cpu.hook_add(UC_HOOK_CODE, hook, user_data=name, begin=address, end=address)

def call(name):
    cpu.reg_write(UC_ARM_REG_SP, 0x2003fff0)
    cpu.reg_write(UC_ARM_REG_LR, 0x30000001)
    cpu.emu_start(symbols[name] | 1, 0x30000000, timeout=60000000, count=100000000)
    assert cpu.reg_read(UC_ARM_REG_PC) == 0x30000000, name+": timed out"
    return cpu.reg_read(UC_ARM_REG_R0)

def response(length):
    return read(symbols["cm_response"], length)

assert call("test_u2f_crypto_prepare") == 0
assert response(call("test_u2f_crypto_register")) == b"\x69\x85"
cpu.mem_write(symbols["pressed"], b"\x01")
registration = response(call("test_u2f_crypto_register"))
assert registration[0:2] == b"\x05\x04" and registration[-2:] == b"\x90\x00"
handle = registration[67:67+registration[66]]
offset = 67+len(handle)
assert registration[offset:offset+2] == b"\x30\x82"
cert_length = int.from_bytes(registration[offset+2:offset+4], "big")+4
cert_bytes = registration[offset:offset+cert_length]
cert = x509.load_der_x509_certificate(cert_bytes)
cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
cert.public_key().verify(registration[offset+cert_length:-2],
                         b"\0"+bytes([41])*32+bytes([31])*32+handle+registration[1:66],
                         ec.ECDSA(hashes.SHA256()))
public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), registration[1:66])
print("PASS real P-256 certificate self-signature and registration attestation")

def authenticate(control):
    challenge = os.urandom(32)
    apdu = bytes([0,2,control,0,0,0,65+len(handle)])+challenge+bytes([41])*32+bytes([len(handle)])+handle
    cpu.mem_write(symbols["cm_request"], apdu)
    if control == 3:
        assert response(call("test_u2f_crypto_authenticate")) == b"\x69\x85"
        cpu.mem_write(symbols["pressed"], b"\x01")
    answer = response(call("test_u2f_crypto_authenticate"))
    assert answer[-2:] == b"\x90\x00" and answer[0] == (1 if control == 3 else 0)
    public.verify(answer[5:-2], bytes([41])*32+answer[:5]+challenge, ec.ECDSA(hashes.SHA256()))
    return int.from_bytes(answer[1:5], "big")

assert authenticate(3) == 1
# Reinitialize production flash index, discarding its RAM view.
assert call("credential_store_init") == 1
assert authenticate(8) == 2
# Discard the certificate cache and scalar, forcing an NVS identity reload.
cpu.mem_write(symbols["certificate_length"], bytes(4))
cpu.mem_write(symbols["attestation"], bytes(144))
cpu.mem_write(symbols["cm_request"], bytes([0,1,0,0,0,0,64])+bytes([31])*32+bytes([41])*32)
assert response(call("test_u2f_crypto_register")) == b"\x69\x85"
cpu.mem_write(symbols["pressed"], b"\x01")
again = response(call("test_u2f_crypto_register"))
new_offset = 67+again[66]
new_length = int.from_bytes(again[new_offset+2:new_offset+4], "big")+4
new_cert = x509.load_der_x509_certificate(again[new_offset:new_offset+new_length])
assert new_cert.public_key().public_numbers() == cert.public_key().public_numbers()
assert new_cert.serial_number == cert.serial_number
new_cert.public_key().verify(new_cert.signature, new_cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
assert call("credential_store_init") == 1
assert authenticate(3) == 3
print("PASS real P-256 authentication, durable counters 1/2/3, persistent attestation identity")

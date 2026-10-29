"""COM6 validation of the flashed database, with an optional reversible test.

--exercise temporarily deletes one existing active lab credential, compacts,
reboots, undeletes it, and reboots again. No PIN values or private keys are read.
All received bytes are saved to the lab's logs directory.
"""
import argparse
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import time
import serial

parser = argparse.ArgumentParser()
parser.add_argument("--exercise", action="store_true")
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
log_dir = root.parent / "logs"
log_dir.mkdir(parents=True, exist_ok=True)
log_path = log_dir / f"dual-bank-check-{stamp}.log"
port = serial.Serial(port=None, baudrate=115200, timeout=0.1)
port.port = "COM6"
port.dtr = port.rts = False
log = log_path.open("xb")

def receive(markers, timeout=60):
    data = bytearray()
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        chunk = port.read(4096)
        if not chunk:
            continue
        log.write(chunk)
        log.flush()
        data.extend(chunk)
        if b"Guru Meditation" in data or b"Credential storage initialization failed" in data:
            raise RuntimeError("Device failure; inspect " + str(log_path))
        if any(marker in data for marker in markers):
            text = data.decode("utf-8", errors="replace")
            # Preserve every byte in the file; omit stale pre-flash UART noise
            # from tool output when a clean console reply is available.
            start = text.find("Console command begin:")
            print(text[start:] if start >= 0 else text, flush=True)
            return text
    raise TimeoutError("No complete device response; inspect " + str(log_path))

def command(text, timeout=60):
    print("> " + text, flush=True)
    port.write(text.encode("ascii") + b"\n")
    port.flush()
    if text == "keys list":
        markers = [b"End of credential list", b"No credential records"]
    else:
        name = ("keys delete" if text.startswith("keys delete ") else
                "keys undelete" if text.startswith("keys undelete ") else
                "keys compact" if text == "keys compact confirm" else text)
        markers = [("Console command end: " + name).encode("ascii")]
    response = receive(markers, timeout)
    if "ERR " in response:
        raise RuntimeError("Console command failed; inspect " + str(log_path))
    return response

def status():
    text = command("status")
    values = {key: int(value) for key, value in re.findall(r"(\w+)=(\d+)", text)}
    assert values["active_capacity"] == values["deleted_capacity"] == 2048, values
    return values

def reboot():
    print("Resetting board to verify persistence", flush=True)
    port.rts = True
    time.sleep(0.1)
    port.rts = False
    text = receive([b"ESP32-S3 OpenFIDO2 initialized"], timeout=90)
    match = re.search(r"ELF file SHA256:\s+([a-fA-F0-9]+)", text)
    if match:
        expected = hashlib.sha256((root / "build/esp32_s3_openfido2.elf").read_bytes()).hexdigest()
        assert expected.startswith(match[1].lower()), "Device ELF differs from local build"

try:
    port.open()
    port.reset_input_buffer()
    before = status()
    pin_before = "PIN is configured" in command("pin status")
    listing = command("keys list")
    if args.exercise:
        match = re.search(r"key id=([0-9a-fA-F]{8}) rp=([0-9a-fA-F]{8}) state=active counter=(\d+)", listing)
        if not match:
            raise RuntimeError("No existing active lab credential for the reversible test")
        selector = match[1] + " " + match[2]
        command("keys delete " + selector)
        deleted = status()
        assert deleted["keys_active"] == before["keys_active"] - 1
        assert deleted["keys_deleted"] == before["keys_deleted"] + 1
        command("keys compact confirm", timeout=90)
        compacted = status()
        assert compacted["keys_deleted"] == deleted["keys_deleted"]
        assert compacted["bank_generation"] == before["bank_generation"] + 1
        reboot()
        after_reset = status()
        assert after_reset["keys_deleted"] == deleted["keys_deleted"]
        command("keys undelete " + selector)
        restored = status()
        assert restored["keys_active"] == before["keys_active"]
        assert restored["keys_deleted"] == before["keys_deleted"]
        reboot()
        final = status()
        assert final["keys_active"] == before["keys_active"]
        assert final["keys_deleted"] == before["keys_deleted"]
        assert ("PIN is configured" in command("pin status")) == pin_before
        final_listing = command("keys list")
        assert f"key id={match[1]} rp={match[2]} state=active counter={match[3]}" in final_listing
        print("PASS: delete -> compact -> reboot -> undelete -> reboot; counts, counter and PIN preserved", flush=True)
    print(f"Log: {log_path}", flush=True)
finally:
    port.close()
    log.close()

"""Hardware U2F smoke/exercise using python-fido2. Run elevated on Windows.

--exercise creates one lab credential and needs two real BOOT-button presses.
Only public registration data is saved for recovery/retesting; no PIN is used.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build/device-test-deps"))
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.ctap1 import Ctap1, ApduError, RegistrationData, SignatureData
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice
import serial
from esp_pylib.serial_reset import hard_reset

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--exercise", action="store_true")
args = parser.parse_args()
log = (ROOT / "build/device-u2f-test.log").open("w", encoding="utf-8", buffering=1)

def report(message):
    log.write(message+"\n")
    print(message, flush=True)

def connect():
    candidates = []
    for device in CtapHidDevice.list_devices():
        if (device.descriptor.vid, device.descriptor.pid) == (0x1209, 0xf201):
            candidates.append(device)
        else:
            device.close()
    if len(candidates) != 1:
        for device in candidates: device.close()
        raise RuntimeError(f"Expected one lab FIDO device; found {len(candidates)}")
    return candidates[0]

def rejected(action, code):
    try:
        action()
    except ApduError as error:
        assert error.code == code, repr(error)
    else:
        raise AssertionError(f"Expected APDU {code:04x}")

def touch(action, description):
    report("WAIT: press and release BOOT once while purple: "+description)
    deadline = time.monotonic()+180
    while time.monotonic() < deadline:
        try:
            return action()
        except ApduError as error:
            if error.code != 0x6985: raise
            time.sleep(.15)
    raise TimeoutError("No physical BOOT approval: "+description)

def reset():
    port = serial.Serial();port.port="COM6";port.baudrate=115200
    port.dtr=False;port.rts=False;port.timeout=.1;port.open()
    try:
        hard_reset(port)
        data=b"";deadline=time.monotonic()+3
        while time.monotonic()<deadline:data+=port.read(port.in_waiting or 1)
        port.write(b"status\nble status\n");deadline=time.monotonic()+1
        while time.monotonic()<deadline:data+=port.read(port.in_waiting or 1)
        with (ROOT/"build/device-u2f-resets.log").open("ab") as output:output.write(data)
        assert b"BLE disabled in build configuration" in data
        assert b"Guru Meditation" not in data and b"panic" not in data.lower()
    finally:
        port.close()

device=None
try:
    report(f"Windows administrator={bool(ctypes.windll.shell32.IsUserAnAdmin())}")
    device=connect();ctap=Ctap1(device)
    assert ctap.get_version()=="U2F_V2"
    info=Ctap2(device).info
    assert "U2F_V2" in info.versions and "FIDO_2_0" in info.versions
    assert info.transports==["usb"]
    assert int(device.capabilities)&4 and not int(device.capabilities)&8
    report(f"PASS U2F_VERSION, HID capabilities={int(device.capabilities):02x}, GetInfo versions={info.versions}, transports={info.transports}")
    rejected(lambda:ctap.send_apdu(ins=0x7f),0x6d00)
    rejected(lambda:ctap.send_apdu(ins=3,cla=1),0x6e00)
    rejected(lambda:ctap.send_apdu(ins=3,p1=1),0x6a86)
    report("PASS invalid U2F instruction/class/parameters rejected")
    if args.exercise:
        app=hashlib.sha256(b"https://openfido2-u2f-lab.invalid").digest()
        challenge=hashlib.sha256(b"OpenFIDO2 physical registration test").digest()
        state_path=ROOT/"build/device-u2f-public.json"
        if state_path.exists():
            state=json.loads(state_path.read_text())
            reg=RegistrationData(bytes.fromhex(state["registration"]))
            report("Resuming with the previously created lab credential")
        else:
            reg=touch(lambda:ctap.register(challenge,app),"U2F registration")
            # Save only public wire data immediately, even if a later check fails.
            state={"registration":bytes(reg).hex(),"app":app.hex(),"challenge":challenge.hex()}
            state_path.write_text(json.dumps(state,indent=2),encoding="ascii")
        reg.verify(app,challenge)
        certificate=x509.load_der_x509_certificate(reg.certificate)
        certificate.public_key().verify(certificate.signature,certificate.tbs_certificate_bytes,ec.ECDSA(hashes.SHA256()))
        report("PASS physical registration; python-fido2 verified attestation and X.509 self-signature")
        rejected(lambda:ctap.authenticate(challenge,app,reg.key_handle,True),0x6985)
        rejected(lambda:ctap.authenticate(challenge,bytes(32),reg.key_handle,True),0x6a80)
        bad=bytes([reg.key_handle[0]^1])+reg.key_handle[1:]
        rejected(lambda:ctap.authenticate(challenge,app,bad,True),0x6a80)
        report("PASS check-only, wrong application and damaged handle")
        challenge2=hashlib.sha256(b"physical user presence authentication").digest()
        signed=touch(lambda:ctap.authenticate(challenge2,app,reg.key_handle),"U2F authentication")
        signed.verify(app,challenge2,reg.public_key)
        assert signed.user_presence==1
        previous=signed.counter
        report(f"PASS physical BOOT authentication and signature; counter={previous}")
        device.close();device=None;reset();device=connect();ctap=Ctap1(device)
        challenge3=hashlib.sha256(b"post-reset U2F counter verification").digest()
        data=challenge3+app+bytes([len(reg.key_handle)])+reg.key_handle
        signed=SignatureData(ctap.send_apdu(ins=2,p1=8,data=data))
        signed.verify(app,challenge3,reg.public_key)
        assert signed.user_presence==0 and signed.counter==previous+1
        previous=signed.counter
        report(f"PASS real reset: credential and counter persisted; touchless signature counter={previous}")
        device.close();device=None;reset();device=connect();ctap=Ctap1(device)
        signed=SignatureData(ctap.send_apdu(ins=2,p1=8,data=data))
        signed.verify(app,challenge3,reg.public_key)
        assert signed.counter==previous+1
        report(f"PASS second real reset: durable counter={signed.counter}; Bluetooth remains disabled")
    report("COMPLETE")
except BaseException:
    log.write(traceback.format_exc());log.flush()
    raise
finally:
    if device:device.close()
    log.close()

"""Read-only interoperability check using python-fido2's standard CM client.

Install python-fido2 (`python -m pip install fido2`). Run elevated on Windows
if HID access is denied. --list prompts locally for the PIN; never log it.
"""
import argparse
import getpass
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric import ec
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import ClientPin
from fido2.hid import CtapHidDevice


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="prompt for PIN and enumerate credentials")
    args = parser.parse_args()
    candidates = [d for d in CtapHidDevice.list_devices()
                  if (d.descriptor.vid, d.descriptor.pid) == (0x1209, 0xF201)]
    if len(candidates) != 1:
        for device in candidates:
            device.close()
        raise SystemExit(f"Expected exactly one OpenFIDO2 HID device; found {len(candidates)}")
    device = candidates[0]
    try:
        ctap = Ctap2(device)
        expected_aaguid = UUID("adacdef0-3644-43dd-84da-d27bda711983")
        if bytes(ctap.info.aaguid) != expected_aaguid.bytes:
            raise SystemExit(f"Unexpected AAGUID: {UUID(bytes=bytes(ctap.info.aaguid))}")
        if ctap.info.transports != ["usb"]:
            raise SystemExit(f"Unexpected transports: {ctap.info.transports!r}")
        print(f"PASS: AAGUID {expected_aaguid}; transports {ctap.info.transports}")
        if not CredentialManagement.is_supported(ctap.info) or not ClientPin.is_token_supported(ctap.info):
            raise SystemExit("Firmware does not advertise standard credential management and scoped tokens")
        try:
            ctap.credential_mgmt(sub_cmd=1)
        except CtapError as exc:
            if int(exc.code) != 0x36:
                raise
        else:
            raise SystemExit("FAIL: unauthenticated metadata request was accepted")
        print("PASS: GetInfo advertises CM; unauthenticated metadata is rejected")
        if not args.list:
            return
        pin = getpass.getpass("Authenticator PIN: ")
        client_pin = ClientPin(ctap)
        try:
            token = client_pin.get_pin_token(pin, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
        finally:
            del pin
        manager = CredentialManagement(ctap, client_pin.protocol, token)
        result = CredentialManagement.RESULT
        metadata = manager.get_metadata()
        expected = metadata[result.EXISTING_CRED_COUNT]
        print(f"Discoverable keys: {expected}; remaining slots: {metadata[result.MAX_REMAINING_COUNT]}")
        seen = set()
        for rp in manager.enumerate_rps():
            rp_name = rp[result.RP].get("id", "(RP label unavailable)")
            credentials = manager.enumerate_creds(rp[result.RP_ID_HASH])
            print(f"{rp_name}: {len(credentials)} credential(s)")
            for credential in credentials:
                ident = credential[result.CREDENTIAL_ID]["id"]
                if ident in seen:
                    raise SystemExit("FAIL: duplicate credential returned")
                seen.add(ident)
                key = credential[result.PUBLIC_KEY]
                if key[1] != 2 or key[3] != -7 or key[-1] != 1 or len(key[-2]) != 32 or len(key[-3]) != 32:
                    raise SystemExit("FAIL: malformed ES256 public key")
                ec.EllipticCurvePublicNumbers(int.from_bytes(key[-2], "big"),
                                             int.from_bytes(key[-3], "big"), ec.SECP256R1()).public_key()
                user = credential[result.USER]
                print(f"  {ident.hex()}  name={user.get('name', '')!r}  displayName={user.get('displayName', '')!r}")
        if len(seen) != expected:
            raise SystemExit(f"FAIL: metadata reports {expected}, enumeration returned {len(seen)}")
        print("PASS: standard PIN exchange, RP/credential enumeration, counts and P-256 public keys")
    finally:
        device.close()


if __name__ == "__main__":
    main()

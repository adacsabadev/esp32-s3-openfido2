"""Generate a public DER template; no private key is retained or embedded."""
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OpenFIDO2 Research U2F")])
serial = bytes.fromhex("112233445566778899aabbccddeeff0011223344")
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(int.from_bytes(serial, "big"))
        .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2126, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
tbs = bytearray(cert.tbs_certificate_bytes)
point = key.public_key().public_bytes(serialization.Encoding.X962,
                                      serialization.PublicFormat.UncompressedPoint)
point_offset = tbs.index(point)
serial_offset = tbs.index(serial)
tbs[point_offset:point_offset+65] = bytes(65)
tbs[serial_offset:serial_offset+20] = bytes(20)
lines = ["/* Generated public template; contains no private key. */", "#pragma once",
         f"#define U2F_CERT_POINT_OFFSET {point_offset}u",
         f"#define U2F_CERT_SERIAL_OFFSET {serial_offset}u",
         "static const uint8_t u2f_cert_tbs_template[] = {"]
for offset in range(0, len(tbs), 12):
    lines.append("    " + ", ".join(f"0x{x:02x}" for x in tbs[offset:offset+12]) + ",")
lines.append("};\n")
target = Path(__file__).resolve().parents[1] / "main/u2f_cert_template.h"
target.write_text("\n".join(lines), encoding="ascii")
print(f"Generated {target.name}: {len(tbs)} TBS bytes, no private key")

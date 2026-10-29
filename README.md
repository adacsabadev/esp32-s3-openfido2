# ESP32-S3 OpenFIDO2

This repository is the stable ESP32-S3 OpenFIDO2 firmware line. Changes are
promoted here after development and validation in the separate
[`esp32-s3-openfido2-unstable`](https://github.com/adacsabadev/esp32-s3-openfido2-unstable)
repository.

**Programming workflow:** use COM6 DTR/RTS to enter download mode, flash through
native USB COM7, then reset through COM6 RTS. See [project memory](MEMORY.md)
for the verified commands and USB device identities.

This is an ESP-IDF port of
[`stm32-openfido2`](https://github.com/adacsabadev/stm32-openfido2) for
ESP32-S3. The project exposes a FIDO HID authenticator over native USB OTG and
a two-way diagnostic console exclusively over the FTDI UART monitoring port.

This is a research prototype, not hardened security-key firmware. Do not
register important accounts or store important credentials with it. The default
CTAPHID logging intentionally omits request and response payloads because they
can contain sensitive authenticator data.

Flash is split into an 8 MiB firmware/system half and an 8 MiB credential half.
The database holds up to **2,048 active credentials and 2,048 deleted credentials**.
Deleting a key frees an active slot and retains its complete record for undelete.
Neither quota silently evicts a key when full. Undelete requires a free active
slot; deletion requires a free deleted slot.

The credential half contains two 4 MiB append-only banks. Every record has a
CRC and a commit word written last. Compaction copies and verifies all retained
active and deleted keys before publishing the next bank generation. Boot uses
the newest committed bank, ignores an incomplete tail write, and refuses to
roll back to older counters when committed data is corrupt. Only a 64 KiB index
is retained in RAM; individual credential records are read from flash.

`keys list` includes active and deleted keys. `keys compact confirm` reclaims
obsolete record versions **without removing deleted keys**. To permanently
remove retained deleted keys from the database, use
`keys purge <id8> <rp8> confirm` or `keys purge-deleted confirm`.
`keys erase-all confirm` removes both sets. Purge and erase-all publish the
replacement bank before erasing the previous bank; they do not change the PIN.
These are database removal operations, not a guarantee of forensic erasure of
credentials previously held in legacy NVS flash pages.

`keys export` writes every active and deleted credential as a `key <base64>`
line preceded by a `# rp_id=... user_name=...` comment. The comment is for
people and backup tools may ignore it. The payload is a versioned,
CRC-protected canonical record and standard
Base64 always includes its required `=` padding. Restore one line with
`keys import <base64>`. Import preserves resident labels, deleted/discoverable
state, and the private key. Re-importing the same identity never rolls its
signature counter backward; an identity collision with a different private key
is rejected. Exported text contains private keys and must be protected like the
authenticator itself.

Console logging defaults to a concise operation result. Use `debug on` for
comment-prefixed, maximally verbose credential-flash diagnostics, `debug off`
to return to concise logging, and `debug` to show the current setting. The
setting is stored in NVS and survives resets. Because diagnostics begin with
`#`, an export remains a comment-friendly backup document while debug is on.

The existing single-slot/16-slot NVS credentials migrate on first startup; NVS
credential entries are removed only after the new database is committed. The
PIN verifier stays in its existing NVS partition. Active PIN tokens, retries,
and protocol key-agreement material remain RAM-only and clear on reset.

**Research-device PIN retry policy:** the failure/retry counter must always stay
in RAM. Each boot starts with 8 attempts. Failed PIN verification reduces that
allowance only for the current boot; reaching zero blocks PIN verification only
until the device is reset or power-cycled. Resetting or removing power clears
the failure history and restores all 8 attempts. Never write PIN failure counts,
retry allowances, or PIN lockout state to NVS, the credential journal, or any
other persistent storage. This is deliberate research behavior, not unfinished
production hardening; do not add permanent lockout as part of security work.

The configured PIN verifier remains persistent, so a reboot does not remove or
change the PIN. Authentication **signature counters** are separate: CTAP2/U2F
signature counters must remain persistent to prevent rollback. Do not make them
RAM-only when changing PIN handling. See [project memory](MEMORY.md).

## Hardware

The primary board is the YD-ESP32-23 clone described in the repository's
`COOPER.md`:

- Native USB OTG is the preferred connection for HID and CDC.
- GPIO0 (BOOT) is the physical user-presence button. A fresh press is required
  for operations that request user presence.
- GPIO48 drives the onboard addressable RGB LED for presence and status.
- LED channel level is 4: errors flash red three times, presence wait blinks
  purple, and successful CTAP responses flash green three times.
- HID WINK identifies the device with red -> white -> green -> off, repeated
  three times. Each phase lasts 300 ms, with direct transitions between colors
  and an off pause between sequences. It runs without blocking USB processing and yields to
  presence and result indications; it cannot grant or consume presence approval.
- The configured flash layout assumes 16 MB flash.

## Build

Build from this project directory with ESP-IDF 6.1:

```powershell
idf.py build
```

The project uses ESP-IDF's `esp_tinyusb` component for composite USB HID/CDC,
an optional ESP-NimBLE encrypted FIDO BLE GATT transport (currently disabled),
Espressif's `led_strip` component for the board LED, and the ESP-IDF PSA
cryptography stack (`psa/crypto.h`) for P-256, AES-CBC, HMAC-SHA256, and
SHA-256.

Cryptography uses ESP-IDF's own PSA Crypto provider, supplied by its `mbedtls`
component. There is no project-vendored crypto implementation. The defaults
explicitly enable Espressif's hardware AES, SHA and MPI drivers. The ESP32-S3
does not have the dedicated ECC/ECDSA peripherals available on some other ESP
targets, so P-256 signing and ECDH still require software operations. Keeping
the IDF `mbedtls` dependency is necessary for this provider; it does not select
the old standalone Mbed TLS sources from the STM32 port.

The application enables the ESP32-S3 hardware RNG entropy source before
generating keys. The reference project's STM32F411 research PRNG is not used.
Do not enable another ADC/RF client while relying on this entropy source.

## USB and setup

Connect the board's FTDI monitoring port (COM6) at 115200 8N1 with no flow
control. The two-way UART console accepts the reference commands (`help`, `status`, `pin status`,
`pin set`, credential listing, deletion/undelete, explicit purge, and database
maintenance). Set a 4-63 digit PIN with `pin set <digits>` before using PIN-based
user verification. The console masks PIN input. On the ESP32-S3 DevKit, the
FTDI UART path uses UART0 on GPIO43 (TX) and GPIO44 (RX). Native USB OTG exposes
FIDO HID only and remains the programming connection.

CTAP2 supports GetInfo, MakeCredential, GetAssertion, ClientPIN protocol 1,
and standard CredentialManagement (`0x0A`), with ES256, discoverable credentials,
and physical user presence. Extensions, enterprise attestation, and
other algorithms are not implemented. Assertions return at most one credential.

U2F/CTAP1 over USB CTAPHID `MSG` implements registration, authentication and
`U2F_VERSION`. GetInfo advertises both `FIDO_2_0` and `U2F_V2`; the HID INIT
capabilities advertise CBOR and WINK with `NMSG` clear. Bluetooth stays disabled.

U2F registration and normal authentication require a fresh BOOT-button press.
Clients poll the same APDU after `6985` (presence required). Approval is bound to
the complete APDU and HID channel and expires after 30 seconds. A changed request,
channel INIT/CANCEL, or expiry cannot reuse an earlier approval. Check-only
authentication (`P1=07`) validates the application and handle without consuming a
touch or changing a counter. U2F 1.2 `P1=08` signs without presence and reports
the presence bit as zero; normal `P1=03` reports it as one.

Each U2F handle has a versioned prefix and a random 32-byte credential ID.
Application-bound, non-discoverable keys use the existing journal and active-key
quota. Registration starts the per-credential counter at zero; authentication
increments and commits it before returning the signature. Exhaustion or a failed
counter write returns an error. Delete/undelete and compaction retain the existing
database behavior; no storage format or PIN retry policy changes are required.

The device generates its own P-256 attestation scalar on first registration and
persists it under NVS namespace `u2f_attest`, key `scalar`. It builds a self-signed
X.509 research certificate (valid 2026-2126) with a public-key-derived serial.
The firmware contains only a public certificate template, with no shared private
attestation key. Reboots retain the same public identity, though the certificate
signature may differ. This is untrusted research attestation, not a manufacturer
CA or certification claim. Like the existing credential keys, the scalar has no
additional protection from physical flash access. Erasing all NVS resets this
identity; credential database erase/purge commands do not erase it.

Run `python tests/storage/run.py --cm` for protocol, touch-isolation, counter,
and torn-write tests. Run `python tests/storage/run_u2f_crypto.py` for independent
P-256 verification of the production U2F/certificate/storage code in Unicorn.
The latter uses host cryptography for the crypto primitives and verifies the
certificate, registration and authentication signatures, counter persistence and
attestation identity reload. These checks do not establish physical GPIO/flash,
the ESP-IDF PSA driver, or browser/OS interoperability on a flashed device.

The model AAGUID is `adacdef0-3644-43dd-84da-d27bda711983`, shared by this
project's devices and used consistently in GetInfo and new registrations.
GetInfo advertises `transports: ["usb"]` in the default Bluetooth-disabled build.
The BLE source remains in place; enabling both `CONFIG_BT_ENABLED` and
`CONFIG_BT_NIMBLE_ENABLED` restores the transport and its GetInfo advertisement.
This project identity does not imply
certification or a metadata-service entry; websites may still show an unknown
provider. Browser/OS transport handling and attestation privacy policies can
affect what a website records. Existing registrations retain their old metadata.

When enabled, BLE exposes the standard FIDO service (`0xFFFD`) with encrypted control-point,
status, control-point-length, and FIDO2 revision-bitfield characteristics. It
uses LE Secure Connections, stores up to three LTK bonds in NVS, advertises with
a resolvable private address, and accepts one connection at a time. A device
with no bonds starts in pairing mode. Use `ble pair` on the serial console to
open a 60-second pairing window for another client; `ble status` reports the
current connection, encryption, notification, pairing, and bond state.

Credential management implements all seven standard subcommands: metadata,
RP enumeration, credential enumeration, deletion, and user-information updates.
It exposes active **discoverable** credentials, including their user handles,
names, display names and ES256 public keys. Non-discoverable and deleted keys
remain available through the diagnostic console. Standard deletion moves the
complete record to the existing undelete database; a full deleted quota returns
`KEY_STORE_FULL`, preserving both sets. User updates require the existing user
handle and replace both optional labels (64 bytes each); omitted/empty labels
are removed. Credential IDs, RP bindings, private keys and counters stay intact.

GetInfo advertises `credMgmt` and `pinUvAuthToken`. ClientPIN subcommand 9 issues
permission-scoped tokens (`mc`, `ga`, `cm`); unsupported defined permissions are
rejected. Management requires `cm`. Global enumeration requires an unbound
token, while RP-bound management tokens can access only their associated RP.
Legacy subcommand 5 tokens grant only `mc` and `ga`. Tokens expire after 30
seconds, and PIN changes and successful PIN-authorized presence operations
invalidate them. Enumeration continuations are bound to the HID channel,
token generation and database revision and expire after 30 seconds.
The base advertised protocol remains `FIDO_2_0`; these additions do not claim
complete CTAP 2.1 support. Built-in `uv` is no longer advertised: verification
uses `clientPin`, rather than an on-device biometric verifier.

Database format 2 adds persistent display names. Existing format 1 flash banks
migrate through a verified replacement bank, preserving active/deleted keys,
counters and PIN state, including after interrupted migration. Older firmware
cannot read format 2; avoid downgrading it over a migrated database.

The first half contains boot/system data and a factory application partition
at `0x10000` of size `0x7f0000`. The `openfido` data partition is exactly 8 MiB
at `0x800000`; bank A starts there and bank B starts at `0xc00000`. PIN/settings
NVS remains at `0x9000`, size `0x6000`. Flashing this project's partition table
changes the layout, so the matching new firmware must be flashed with it.

Storage regression tests compile the production database code for ARM and run
in Unicorn with simulated NOR flash and legacy NVS:

```powershell
python -m pip install --target build/storage-test-deps unicorn pyelftools
python tests/storage/run.py
python tests/storage/run.py --cm
```

The test runner uses the workstation's installed ARM GNU compiler. Tests cover
both capacity limits, counter updates at capacity, migration, torn appends,
interrupted bank replacement/purge, deleted-key retention, and corruption
rejection. They do not substitute for device flash and browser tests.
The CM suite executes the production CTAP/CBOR/management/token/store code
with simulated cryptographic primitives and hardware. It checks permission,
RP and channel isolation, expiry, full-ID deletion, label replacement and
enumeration at the full 2,048-credential capacity.

For a read-only standard-client HID check, install `fido2` and run
`python tests/credential_management_device.py`. Add `--list` to enter the PIN
locally using a masked prompt and enumerate all discoverable credentials. This
also checks returned counts and validates the P-256 public points. It does not
modify keys or PIN state. Windows may require an elevated terminal for HID
access. The PIN is never accepted on the command line or written to a log.

For a reversible test on a connected lab device, stop its serial monitor and run
`python tests/storage/device_check.py --exercise` using the ESP-IDF Python
environment. This temporarily deletes one active key, compacts, resets the
board, undeletes that key, and resets again. It verifies counts, counter and PIN
status and saves the raw serial transcript under `logs/`.

The USB VID/PID is inherited from the STM32 reference for lab compatibility.
Do not distribute this identity in a product; use a VID/PID assigned to your
project before distribution.

## Attribution

The portable CTAP2, CTAPHID, CBOR, credential-journal, PIN/UV, and diagnostic
console code is adapted from
[adacsabadev/stm32-openfido2](https://github.com/adacsabadev/stm32-openfido2),
licensed under Apache-2.0; see [LICENSE](./LICENSE). ESP-IDF and its managed
components retain their respective licenses.

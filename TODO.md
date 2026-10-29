# Development TODO

Updated: 2026-10-23.

**Status: development paused at the user's request.** These items are a backlog
for a future session, not instructions to resume work automatically. Bluetooth
remains disabled, with its implementation preserved.

**Research PIN policy:** failure counts, retry allowances, and PIN lockout state
must always remain in RAM. Every reset/power cycle restores 8 PIN attempts;
there must be no persistent or permanent PIN lockout. The configured PIN verifier
and CTAP2/U2F authentication signature counters remain persistent. Preserve this
distinction in all future security and Bluetooth work.

## 1. Browser registration and login tests

- [ ] Test through Edge and Chrome using disposable accounts or a WebAuthn test page.
- [ ] Cover PIN-based verification, fresh BOOT-button approval, and cancellation.
- [ ] Verify unplug/replug and login after a device reset.
- [ ] Record browser/OS versions and results separately from direct HID tests.

Direct python-fido2 hardware tests passed; browser/OS interoperability remains
unverified.

## 2. U2F-to-CTAP2 credential compatibility

- [ ] Add a regression test for a U2F-created credential used through CTAP2.
- [ ] Investigate the 36-byte U2F handle versus CTAP2's current 32-byte allow-list ID requirement.
- [ ] Implement the required handle mapping and application/RP binding checks.
- [ ] Verify signatures, counters, and rejection of malformed or unrelated handles.

Do not assume cross-protocol credential compatibility from the separate U2F and
CTAP2 tests already completed.

## 3. Implement visible WINK behavior

- [x] Add a short, distinctive LED pattern for the advertised HID WINK command: red, white, green.
- [x] Keep presence approval and result indication behavior intact.
- [x] Verify HID WINK on the device and check that WINK cannot approve an operation.
- [ ] Visually confirm the revised continuous-color, 300 ms pattern.

The handler now starts a nonblocking red -> white -> green -> off pattern,
repeated three times with 300 ms per phase. Presence and result
indications take priority. Physical LED verification remains to be completed.

## 4. Physical interruption tests

- [ ] Use a spare board and disposable credentials for interruption testing.
- [ ] Interrupt registration, authentication counter updates, and database compaction.
- [ ] Verify recovery, retained credentials, and absence of counter rollback.
- [ ] Save firmware identity, interruption conditions, and serial evidence.

Normal hardware resets and emulated torn writes passed. Physical interruption
during flash operations remains unverified.

## 5. Plan and validate flash protection

- [ ] Design a Secure Boot, flash encryption, and attestation-scalar protection workflow.
- [ ] Test the provisioning and firmware-update procedure on a spare board.
- [ ] Document recovery/debug restrictions and key handling before changing eFuses.
- [ ] Keep the current development board recoverable until the workflow is proven.

Treat irreversible eFuse changes as a separate, explicitly authorized step.
Preserve the intentional RAM-only PIN retry policy.

## 6. Continue Bluetooth implementation in the near future

- [ ] Resume review and development of the preserved BLE transport in a future session.
- [ ] Review pairing, bonding, encrypted links, reconnect behavior, and transport arbitration with USB/U2F.
- [ ] Test user-presence isolation, cancellation, and credential/counter behavior across transports.
- [ ] Verify BLE interoperability on hardware before enabling it in the default configuration.

Bluetooth development is paused for now. Leave Bluetooth disabled until work is
explicitly resumed and the relevant tests pass.

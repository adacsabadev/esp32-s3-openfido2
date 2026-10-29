# Project memory

## Intentional PIN retry policy — 2026-10-21

The user explicitly wants PIN retry counting to remain **RAM-only**. A reboot
restores the retry allowance, preventing an accidental persistent PIN lockout.
This is a deliberate project policy, not unfinished work or a defect to fix.
Do not persist retry counts, add a permanent lockout, or change this behavior
unless the user explicitly requests it. The configured PIN verifier remains
persistent; this decision concerns the retry allowance only.

## Verified programming procedure — 2026-10-21

Use **COM6 for reset/BOOT control and monitoring**, and **native USB COM7 for
flashing**. This exact sequence was tested successfully without pressing any
buttons. The user explicitly selected this workflow; do not resume investigating
COM6 UART download failures unless asked.

Both USB cables must be connected. Stop any serial monitor holding COM6 first.
Port numbers can change after reconnecting; verify device identities:

- FTDI: VID `0403`, PID `6001`, serial `A5069RR4` (COM6).
- Native ROM USB Serial/JTAG: VID `303A`, PID `1001`, serial
  `28:84:85:9D:AD:BC` (COM7 while in download mode).
- Running application: FIDO HID VID `1209`, PID `F201`, serial `2884859DADBC`.
  The application does not expose a native serial COM port.

### 1. Enter download mode through COM6

Use the installed ESP-IDF Python environment. From this project directory:

```powershell
$idfPython = 'C:\Espressif\tools\python\v6.1\venv\Scripts\python.exe'
& $idfPython -c "import serial,time; from esp_pylib.serial_reset import classic_bootloader_reset; p=serial.Serial(); p.port='COM6'; p.baudrate=115200; p.dtr=False; p.rts=False; p.open(); classic_bootloader_reset(p,enter_boot_delay=.2,reset_delay=.1); p.close(); time.sleep(1)"
& $idfPython -m serial.tools.list_ports -v
```

This drives DTR/RTS in the normal Espressif sequence: deassert DTR, assert RTS
to hold EN low, assert DTR for BOOT, release RTS, wait, then release DTR.
Pyserial `True` means asserted/active-low; `False` means deasserted/high.
CTS is an input, not a reset/BOOT control output.

### 2. Flash through native USB, leaving reset control to COM6

Build the desired firmware first. Flash the matching application image:

```powershell
& $idfPython -m esptool --chip esp32s3 --port COM7 --baud 460800 --before no-reset --after no-reset write-flash --flash-mode dio --flash-freq 80m --flash-size 16MB 0x10000 build/esp32_s3_openfido2.bin
```

Require successful write/hash verification. The `no-reset` options deliberately
leave the board in download mode for the final COM6 reset. This is flashing
through the USB Serial/JTAG interface using esptool, not an OpenOCD JTAG session.
The application-only write preserves NVS and both credential banks. If a future
change requires bootloader/partition-table updates, flash the matching generated
artifacts through this same native USB path; do not erase credential storage.

### 3. Boot normally through COM6

Deassert DTR before pulsing RTS/EN:

```powershell
& $idfPython -c "import serial,time; from esp_pylib.serial_reset import hard_reset; p=serial.Serial(); p.port='COM6'; p.baudrate=115200; p.dtr=False; p.rts=False; p.open(); hard_reset(p); time.sleep(2); p.close()"
```

Verify the application boot banner and `status` through COM6, then release the
port so the VS Code monitor task can use it. Keep DTR/RTS deasserted when opening
the normal monitor; do not enable hardware flow control.

### Observed result and troubleshooting boundaries

The verified run flashed 422,432 bytes, passed esptool hash verification, and
booted ELF SHA256 prefix `1ee5dd423`. Status preserved 2 active keys, 0 deleted,
and database generation 3. Boot/status evidence is saved in the parent lab at
`logs/com6-reset-native-flash.log`.

COM6 UART loader uploads had intermittent checksum failures during investigation.
They do not prevent COM6 from controlling download mode/reset. The root cause
was not established. The user aborted that investigation and selected the
working two-interface procedure above.

VMware can capture USB devices on reconnect or mode changes; check ownership
when a port is missing. Do not assume every missing HID result means VMware
took the device: the python-fido2 check returned an empty list when Windows
denied access. An administrator-level HID smoke test passed. VMware USB
Arbitration was restored to Running after the investigation.

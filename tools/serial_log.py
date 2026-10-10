#!/usr/bin/env python3
"""Capture the board's serial output for a fixed time (non-interactive serial monitor).

Usage:
    python tools/serial_log.py PORT [-b BAUD] [-t SECONDS] [-o FILE] [-s CMD ...] [--reset]

Examples:
    python tools/serial_log.py COM3 -t 10
    python tools/serial_log.py COM3 -t 5 -s stat -s "log 1" -o logs/run1.txt
    python tools/serial_log.py COM3 -t 8 --reset

Each received line is printed with a host timestamp (seconds since start). Commands given with
-s are sent one after another (newline-terminated) after a short delay. --reset pulses RTS
(EN on adapters that wire it); without it, the board keeps running and only the output from now
on is seen. Needs pyserial (`pip install pyserial`).
"""
import argparse
import sys
import time

import serial


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("port")
    ap.add_argument("-b", "--baud", type=int, default=115200)
    ap.add_argument("-t", "--time", type=float, default=10.0, help="capture duration in seconds")
    ap.add_argument("-o", "--out", help="also append the output to this file")
    ap.add_argument("-s", "--send", action="append", default=[], help="command to send (repeatable)")
    ap.add_argument("--reset", action="store_true", help="pulse RTS to reset the board first")
    args = ap.parse_args()
    # Garbage bytes (e.g. at reset) must not crash the output on a cp1252 Windows console
    sys.stdout.reconfigure(errors="replace")

    out = open(args.out, "a", encoding="utf-8") if args.out else None
    with serial.Serial() as ser:
        ser.port = args.port
        ser.baudrate = args.baud
        ser.timeout = 0.1
        # Keep DTR/RTS released, so opening the port does not hold the board in reset/boot mode.
        ser.dtr = False
        ser.rts = False
        ser.open()
        if args.reset:
            # Writing DTR again after each RTS change makes the RTS change take effect with the
            # Windows usbser driver (same workaround as esptool)
            ser.rts = True
            ser.dtr = ser.dtr
            time.sleep(0.1)
            ser.rts = False
            ser.dtr = ser.dtr

        t0 = time.time()
        pending = list(args.send)
        next_send = t0 + 1.0
        buf = b""
        while time.time() - t0 < args.time:
            if pending and time.time() >= next_send:
                ser.write((pending.pop(0) + "\n").encode())
                next_send = time.time() + 0.5
            buf += ser.read(4096)
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                line = "%8.3f %s" % (time.time() - t0, raw.decode("utf-8", "replace").rstrip("\r"))
                print(line)
                if out:
                    out.write(line + "\n")
        if buf:
            line = "%8.3f %s" % (time.time() - t0, buf.decode("utf-8", "replace"))
            print(line)
            if out:
                out.write(line + "\n")
    if out:
        out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

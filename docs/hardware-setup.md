# Hardware setup

## Parts

| Part | Notes |
|---|---|
| WT32-ETH01 | ESP32-WROOM-32 + LAN8720 Ethernet PHY. No USB on board. |
| USB-to-serial adapter, 3.3 V | for flashing and serial log |
| TP-Link TL-PA4010P V2 (AR7420) | tested: V2.0 and V2.4 with stock firmware 1.1.0.844 |
| Ethernet patch cable | modem ↔ WT32-ETH01 |
| Coupling of the modem to the CP line, and a modem power supply | see below |
| Tablet or phone with a browser | any recent browser |

## WT32-ETH01

### Ethernet pins (LAN8720, fixed by the board)

| Signal | GPIO |
|---|---|
| MDC | 23 |
| MDIO | 18 |
| PHY address | 1 |
| PHY power / oscillator enable | 16 |
| RMII reference clock | GPIO0, **input** from the board's 50 MHz oscillator |

Arduino-ESP32 3.x, for example:
`ETH.begin(ETH_PHY_LAN8720, 1, 23, 18, 16, ETH_CLOCK_GPIO0_IN);`

Board revisions differ slightly. Check the silkscreen version of your board (for example v1.4) and
the schematic if Ethernet does not come up.

### Flashing

The board has no USB interface. Connect a 3.3 V USB-to-serial adapter:

| Adapter | WT32-ETH01 |
|---|---|
| TX | RX0 |
| RX | TX0 |
| GND | GND |
| 3.3 V (or 5 V) | 3V3 (or 5V) pin, check that your adapter supplies enough current |

To enter the boot loader, tie **IO0 to GND** while you power up or reset (EN), then flash. Remove
the bridge and reset to run. GPIO0 also carries the Ethernet clock, so leave it unconnected during
normal operation.

Plain USB-to-serial adapters usually don't wire RTS/DTR to EN/IO0. Then the "hard resetting via
RTS" at the end of an upload does nothing, and the board stays silent in the flasher until you
remove the IO0 bridge and reset it by hand (EN to GND briefly, or power cycle).

### Build, upload, serial log (arduino-cli)

The board package is `esp32:esp32` 3.x. The Arduino IDE 2.x includes `arduino-cli`.

```sh
arduino-cli compile --fqbn esp32:esp32:wt32-eth01 --output-dir build .
arduino-cli upload  --fqbn esp32:esp32:wt32-eth01 -p <port> --input-dir build .
```

For a timed, non-interactive capture of the serial log (115200 baud), with optional commands:

```sh
python tools/serial_log.py <port> -t 10
python tools/serial_log.py <port> -t 5 -s stat -s "log 0"
```

Serial commands: `log 0|1` (one line per frame on/off), `hex <n>` (also dump the first n bytes of
each frame), `stat` (summary line now), `modem` (local modem status), `modem retag` (ask for the
sniffer build tag again), `session` (print the session state as the UI gets it), `sniffer` (status block),
`versions` / `versions clear` (version scan). Diagnostics for the sniffer firmware (v146+, contract range 146..199,
see `LocalModem` in `local_modem.h`): `passive on|off` (hold the ping-pong disarmed; off by default,
`SNIFFER_PASSIVE_DEFAULT` 0), `arm <charger> <car> <own>` (start the ping-pong mid-session; lacks the first
OWN_TEI flip, so it does not flip yet), `own <tei>` / `own 0` (hold OWN_TEI at a fixed TEI / back to the real
one). A held OWN_TEI survives an ebony reset and is re-written after a modem restart: power-cycle the modem
(and reset ebony) to get rid of it. OWN_TEI consumer mask (v152+ only, refused on older builds; contract
qca7000-transparency `plans/interface-ardut-ebony.md` §6): `tshow` (list the 41 sites), `tmask real|follow` (all),
`tsite <n> real|follow` (one site), `modemreset` (VS_RS_DEV soft reset of the modem; held follows are re-applied
after every modem restart). A summary
line `S …` is printed every second, and decoded messages (`D …`) are always printed.

Settings: copy `ebony_config.example.h` to `ebony_config.h` and edit it. Without the copy, the
sketch builds with the defaults from the example file.

### Power

The WT32-ETH01 accepts 5 V or 3.3 V on its supply pins. Wi-Fi AP plus Ethernet draws a few hundred
mA at peak, so plan for at least 500 mA.

## Powerline modem

### Firmware

The modem must run the **transparent AR7420 sniffer firmware**. It is published as a patch script
in [pyPLC](https://github.com/uhi22/pyPLC), folder `ar7420-sniffer-patch/`. Its README covers:

- downloading the stock TP-Link firmware yourself (the patch contains no vendor firmware),
- building the patched image (input and output SHA-256 are verified),
- flashing over Ethernet with `plctool` from open-plc-utils, **with your own PIB**,
- the PIB must be set up in the **PEV role** (pyPLC's PIB setup guide),
- checking the sniffer build tag, and rolling back.

Follow that README. It is the authoritative source and will change as the sniffer evolves. Back up
your PIB before you flash.

ccs32ebony detects the firmware at runtime. The status area shows whether the local modem answers,
and whether it reports the sniffer build tag or looks like stock firmware.

### Coupling to the charging line and power

A TL-PA4010P is built to plug into a mains socket. To sniff CCS, the modem must be coupled to the
**control pilot (CP) and PE** lines instead, and powered from a low-voltage supply. pyPLC's
documentation describes hardware modifications of TP-Link adapters for this. This project does not
document a specific modification. You are responsible for safe isolation from mains and from the
vehicle/charger.

### Connection

Connect the modem's Ethernet port directly to the WT32-ETH01's RJ45 jack, with no switch in
between. A switch may filter or learn the foreign MAC addresses the sniffer forwards.

## Tablet

1. Power the box. The serial log shows the Wi-Fi AP starting.
2. On the tablet, join the Wi-Fi network. The SSID and password are the ones set in
   `ebony_config.h`, and the default SSID is `ccs32ebony`.
3. Open `http://192.168.4.1/` in the browser. Any other `http://` address leads to the UI too,
   because the box answers every DNS name with its own address.
4. Recommended: "Add to Home Screen". The UI then opens full screen, like an app, with one tap.

The box answers the tablet's "is there internet?" check positively (`WIFI_CAPTIVE_PORTAL 0`,
the default), so the tablet joins like any normal Wi-Fi network. With `WIFI_CAPTIVE_PORTAL 1` the
UI pops up by itself after joining. On iOS/iPadOS, though, it then opens in a sign-in sheet that
offers only "Cancel", which leaves the network, so this is not recommended there.

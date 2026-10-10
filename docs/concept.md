# Concept

## Goal

A small, self-contained box that you place next to a CCS charging session. A tablet connects to
the box over Wi-Fi and shows the live charging data, with no laptop, no internet and no app install.

Requirements:

1. **Passive.** Do not disturb the charging session. Never send V2G traffic.
2. **Both directions.** Show requests from the car and responses from the charger.
3. **Standalone.** The box opens its own Wi-Fi access point. The tablet only needs a browser.
4. **Tablet first.** Use a large touch screen better than ccs32dave's 240×320 TFT: big values,
   real charts, a whole-session history, touch navigation, and export.
5. **Publishable.** No private data (MAC addresses, keys, passwords) in code defaults or docs.

Non-goals (for now): acting as a PEV or EVSE, ISO 15118-20, TLS decryption, cloud upload.

## Data path

```
AR7420 sniffer  ──Ethernet──►  LAN8720 PHY ──RMII──► ESP32 EMAC
                                                       │  promiscuous, raw frames
                                                       ▼
                                             frame input hook (no lwIP on Ethernet)
                                                       │
                       ┌───────────────────────────────┼────────────────────────┐
                       ▼                               ▼                        ▼
               EtherType 0x88E1                 EtherType 0x86DD           other
               HomePlug MME                     IPv6                       (count only)
               - SLAC (PARAM, ATTEN_CHAR,       ├─ UDP 15118 → SDP (V2GTP 0x9000/0x9001)
                 MATCH, …)                      └─ TCP → per-direction reassembly
               - local modem answers                     → V2GTP framing
                 (GET_SW, NW_INFO)                       → EXI decode (DIN 70121, AppHandshake)
                       │                               │
                       └──────────────► session model ◄┘
                                    (phases, values, modems, counters, event log)
                                               │
                                               ▼
                              WebSocket push (JSON) ──Wi-Fi AP──► tablet browser
```

### Receiving raw Ethernet frames

The sniffer firmware forwards frames with their **original** destination MAC addresses (car,
charger, multicast). The ESP32 must therefore:

- put the EMAC into promiscuous mode (`esp_eth_ioctl(…, ETH_CMD_S_PROMISCUOUS, …)`), and
- take all received frames directly from the Ethernet driver (`esp_eth_update_input_path()`),
  instead of passing them to lwIP.

No IP stack is used on the Ethernet side. The board does not need an IP address on Ethernet.
Frames that the sketch sends to its own modem (HomePlug MMEs) go out with `esp_eth_transmit()`.

The driver is installed with plain ESP-IDF calls (`eth_sniff.cpp`), **not** with the Arduino
`ETH.begin()`. `ETH.begin()` always attaches lwIP, and lwIP would send DHCP, ARP and IPv6 frames
toward the modem on its own. Without a netif, the board sends nothing on Ethernet unless the
sketch explicitly transmits a frame. `Network.begin()` is still called, for the default event loop
that the Wi-Fi AP needs as well.

### Talking to the local modem

As in ccs32dave, the sketch sends a few management queries to its own modem, never onto the
powerline session:

- `GET_SW`: is the modem alive, which firmware version is it. The sniffer build answers a
  `GET_SW` request that carries a magic pattern with its **build tag**, so the UI can show
  "sniffer firmware detected" rather than "stock firmware".
- `NW_INFO`: joined or not, network members.

The local modem's MAC address is learned at runtime, from its answers. It is never hard-coded.

How it is done (`local_modem.cpp`), and what was seen on the hardware:

1. `GET_SW.REQ` to the Qualcomm local management address `00:B0:52:00:00:01`. Only the attached
   modem answers, and the answer carries its MAC address and version string.
2. `GET_SW.REQ` with the payload `GST1` to that MAC address. The sniffer answers with a
   `GET_SW.CNF` that has zeros where the OUI and the length byte would be, and the 16-character
   build tag (`YYMMDD-Vnnn-0844`) at byte 23. If no tag arrives after 5 tries, the modem counts as
   stock firmware.
3. `VS_NW_INFO.REQ` to that MAC address, every second. This tells whether the modem is alive,
   joined or not joined, and gives the CCo and the station list. While the sniffer runs, its
   reported "own TEI" switches back and forth (that's how it receives both directions), so it is
   not shown as meaningful. The modem's real TEI is its entry in the station list.

All queries are unicast to the local modem. Nothing is broadcast onto the powerline.

### Decoding

Ported from ccs32dave, with small adaptations:

| Layer | Module | Notes |
|---|---|---|
| HomePlug MME parse and names | `homeplug.*` (from ccs32dave) | requests always unicast to the local modem; sniffer tag request and answer added |
| Local modem state | `local_modem.*` | replaces ccs32dave's modem table: `VS_NW_INFO` already lists the stations |
| IPv6 / UDP / SDP | sketch | V2GTP `0x9000` / `0x9001` over UDP |
| TCP reassembly, V2GTP | `v2gtp.*` (from ccs32dave) | one stream per peer MAC; on a gap it drops the partial message and resyncs on the next V2GTP header |
| EXI decode | `v2g_exi.*` + `src/exi/` (OpenV2G, from ccs32dave) | DIN 70121 + app handshake; ISO 15118-2 later |
| Serial diagnosis | sketch | `log`, `hex`, `stat`, `modem`, `modem retag`, `session` |

The QCA7000 SPI driver of ccs32dave is replaced by the Ethernet receiver (`eth_sniff.*`), and the
TFT code by the web server. Measured on the bench: every V2G message of a session decoded, with
0 decode failures.

### Session model

`session.*` holds everything the UI shows. The decoders feed it, and it produces two kinds of
WebSocket messages (details in [web-ui.md](web-ui.md)):

- **`session`**: the whole current state, sent once per second and on connect. It is idempotent,
  so a tablet that joins late or misses messages is still consistent:
  - **Phases:** SLAC, join, SDP, handshake, setup, CableCheck, PreCharge, CurrentDemand, stop,
    each with start and end (the phase model of ccs32dave). A PowerDelivery before the first
    CurrentDemand counts as PreCharge, because it starts the charging rather than stopping it.
  - **Live values:** target and present voltage and current, SoC, last message and response code,
    each with the time it was last seen, so the UI can mark stale values.
  - **Negotiated data:** SDP (TLS, transport, charger address and port), offered and selected
    schemas, ChargeParameterDiscovery request and response, identity (EVCCID, SessionID, modem
    MACs, NID, NMK).
  - **Energy:** Wh, Ah, peak power and time with current, integrated over CurrentDemandRes.
  - **SLAC attenuation profile.**
- **`msg` / `event`**: each decoded V2G message, and each SLAC or SDP event, sent at once. The
  last 100 are kept in a ring and replayed to a tablet that connects.

**Session boundaries:** a session begins at the SLAC match (`begin`). Its SLAC run starts with
the first SLAC message after a pause of more than 5 s. That is not always `SLAC_PARAM.REQ`: the
sniffer can miss the car's first request, and then the charger's CNF comes first. The UI moves the
SLAC messages of the run into the new session, so its log starts with SLAC. If the box sees V2G or
SDP without a preceding match (it was reset mid-session, or the sniffer joined late), the session
is marked `late`.

### Web layer

- Wi-Fi **SoftAP** with a configurable SSID and **WPA2** password. The UI shows session keys and
  vehicle identifiers, so an open network is not acceptable. There is no default password in the
  published code: it is set in `ebony_config.h`, and a password shorter than 8 characters
  refuses to start the AP.
- Fixed AP address (ESP32 default `192.168.4.1`). DNS answers every name with that address. The
  OS connectivity checks are answered as "internet OK", so tablets join without a sign-in sheet
  (an iOS captive-portal sheet can only be cancelled, which leaves the network). The UI is opened
  in the browser, best as a home-screen icon. A captive-portal mode is available as a switch.
- HTTP server for the single-page app. All HTML, CSS and JS are **embedded in flash**
  (gzip-compressed, about 17 KB), with no CDN, because the tablet has no internet on this
  network.
- **WebSocket** for live data. The server is our own (`webui.*`, no library). Each viewer has a
  4 KB output queue that is flushed non-blocking, so a slow tablet never stalls frame processing.
  Several tablets can watch at the same time (up to 4 Wi-Fi stations).

### Division of work: ESP32 vs. browser

The WT32-ETH01 has an ESP32-WROOM-32 with about 520 KB SRAM, **no PSRAM** and 4 MB flash. The
tablet has plenty of memory and CPU. So:

- **ESP32:** receive, decode, keep the *current* session state and a ring of the last 100
  messages, push them.
- **Browser:** keep the *full* session history (values over time, the complete message list),
  draw charts, compute derived values for display (power, durations), and export. It applies
  each `msg` to tiles and phases at once (the 1 Hz snapshot alone feels slow), and a message only
  wins if it is newer than the snapshot's value.

A tablet that connects mid-session gets the current snapshot plus the last 100 messages. A
full-history replay from the ESP32 is not planned.

## Firmware structure

```
ccs32ebony-arduino-wt32eth01.ino   setup/loop, frame dispatch, SDP/V2G decoding glue, JSON, serial commands
ebony_config.example.h             configuration template (committed)
ebony_config.h                     local copy with your Wi-Fi password etc. (not committed)
eth_sniff.h/.cpp                   LAN8720 init, promiscuous mode, raw RX queue, TX for MMEs (no lwIP on Ethernet)
local_modem.h/.cpp                 local modem: MAC, version, sniffer tag, joined / stations
homeplug.h/.cpp                    HomePlug MMEs (from ccs32dave)
v2gtp.h/.cpp                       TCP reassembly + V2GTP framing (from ccs32dave)
v2g_exi.h/.cpp, src/exi/           EXI decoding, OpenV2G (from ccs32dave)
session.h/.cpp                     session model, phases, energy, message ring
json_out.h                         JSON writer into fixed buffers
webui.h/.cpp                       SoftAP, DNS, HTTP, WebSocket, output queues
webui_assets.h                     the packed UI (generated from web/ by tools/pack_web.py, committed)
web/index.html                     UI source (HTML/CSS/JS in one file)
tools/serial_log.py                timed serial capture with commands
tools/pack_web.py                  packs web/index.html into webui_assets.h
docs/
```

Toolchain: Arduino IDE 2.x or `arduino-cli`, esp32 core 3.x (tested with 3.0.2), board
"WT32-ETH01 Ethernet Module" (`esp32:esp32:wt32-eth01`). No external Arduino libraries.

Resources (as of the current build): app about 1,033 KB of the 1.25 MB default app partition,
static RAM about 114 KB, free heap about 125–185 KB while running with Wi-Fi and one viewer.

## Risks and open questions

1. **Raw RX on the Arduino core.** Solved: the driver is installed with ESP-IDF calls, and frames
   with foreign MAC addresses from the sniffer arrive (verified on bench sessions).
2. **RAM for EXI decoding.** Solved for DIN: the OpenV2G document is a static struct (about
   28 KB). ISO 15118-2 would add a second document type, so check the RAM again then.
3. **Wi-Fi and Ethernet load at the same time.** Verified: 0 frames dropped by the box with Wi-Fi
   and a viewer running. The RX callback only queues, and decoding and sending run in `loop()`.
4. **Flash budget.** About 220 KB are left in the default app partition. ISO 15118-2 or OTA may
   need a different partition scheme (see backlog).
5. **Capture completeness.** The sniffer is not lossless. Seen on the bench: a missed first
   `SLAC_PARAM.REQ`, a missed SDP when the sniffer joined late, and missing TCP ACKs. The decoder
   resyncs, the UI marks late sessions, and stale values fade instead of showing old numbers as
   current.
6. **Firmware variants.** The published sniffer patch is a draft release for the TL-PA4010P V2
   (stock firmware 1.1.0.844). Other modem revisions or firmware versions are out of scope until
   tested.

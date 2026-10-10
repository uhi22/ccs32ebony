# Backlog

Planned work, roughly in order. Check an item off with a one-line result; do not delete it.

## Milestone 1: frames in

- [x] Arduino project skeleton for WT32-ETH01, serial log, config template (no secrets committed).
  Builds with arduino-cli and core 3.0.2, and uploads. `tools/serial_log.py` captures the log.
- [x] Ethernet up with LAN8720, promiscuous mode, raw RX hook. Count frames by EtherType.
  Verified on hardware (2026-10-10): link 100 Mbit/s full duplex, `eth_sniff.*`, no lwIP on Ethernet.
- [x] Prove that foreign-MAC frames from the sniffer modem arrive (SLAC MMEs, IPv6 multicast SDP).
  Verified on a bench session (2026-10-10): full SLAC sequence, SDP request and response, and the
  TCP/V2G exchange in both directions, 0 frames dropped. A few TCP segments were missing
  (SYN-ACK, some ACKs), which matches the sniffer firmware not being lossless. The decoder has to
  handle that.
- [x] Send `GET_SW` / `NW_INFO` to the local modem, parse the answers, detect the sniffer build tag.
  Verified (2026-10-10, `local_modem.*`): `GET_SW` to the local management address returns the
  modem's MAC address and version. The `GST1` request returns the tag (v142 build). `VS_NW_INFO`
  every second shows joined or not joined, the CCo and the stations. Serial `modem` / `modem retag`.

## Milestone 2: decode

- [x] Port HomePlug, SDP, TCP reassembly and V2GTP from ccs32dave. Verified on bench sessions
  (2026-10-10): serial `D` lines for SLAC match, SDP and every V2G message. The modem list isn't
  needed: the local modem's `VS_NW_INFO` already lists the stations.
- [x] Port the OpenV2G EXI decoder (DIN 70121 + AppHandshake). Measure RAM usage on the ESP32.
  Verified: 46 of 46 messages decoded across two bench sessions, 0 failures. Static RAM +36 KB,
  free heap about 186 KB with Wi-Fi running. App size about 1,012 KB of 1.25 MB.
  Note: in one session the sniffer joined about 1.7 s after the SLAC match and missed SDP (2 TCP
  gaps at the start). The reassembler recovered, and the UI must show "SDP not seen" for that case.
- [x] Session model and phase tracking (`session.*`). Verified on bench sessions (2026-10-10):
  phases, live values, SDP, handshake, ChargeParameterDiscovery, identity, energy, attenuation.
  Late sessions (no SLAC match seen) are marked `late`; TCP gaps are counted.
- [x] Fixed: the SLAC duration grew from session to session. The sniffer sometimes misses the car's
  first `SLAC_PARAM.REQ`, and the charger's CNF arrives first; the run start was only taken from a
  REQ. Now any SLAC message after a 5 s pause starts a run, and each match clears it. Verified:
  SLAC about 5.6 s per session on the bench, stable.
- [x] Serial diagnosis commands: `log 0|1`, `hex <n>`, `stat`, `modem`, `modem retag`, `session`.

## Milestone 3: tablet UI

- [x] SoftAP (WPA2, password from config), captive-portal DNS, HTTP server for embedded assets.
  Verified with a tablet (2026-10-10): page loads, WebSocket live, 0 frames dropped and 0 viewers
  dropped during a bench session. Free heap went from about 308 KB to about 214 KB with Wi-Fi and
  one viewer.
- [x] Choose the WebSocket implementation: our own minimal server on `NetworkServer` (`webui.cpp`),
  with no library. Each viewer has a 4 KB output queue, flushed non-blocking; a viewer that
  overflows it is disconnected and reconnects.
- [x] WebSocket protocol v1: `hello`, `status`, `session`, `begin`, `msg`, `event`, `live`, `get`,
  `ping` (docs/web-ui.md). The last 100 messages are replayed on connect, paced by the queue.
- [x] UI: status bar and Live tab: Present/Target tiles, power, SoC ring, phase strip with
  durations, last message, 2-minute chart. Tiles and phases follow each `msg` at once.
- [x] UI: Chart (U, I, P, SoC panels, synced crosshair, range, table view), Session (timeline,
  ladder, message detail), Details, Network (with SLAC attenuation), Log (filters, search).
  Times: Log 0.01 s, ladder and durations 0.1 s.
- [x] Export: JSON (session + messages) and CSV (values); identifiers left out unless ticked.
- [x] iPad: the captive-portal sign-in sheet could only be cancelled, which left the network. The
  OS connectivity checks are now answered as "internet OK" (switch `WIFI_CAPTIVE_PORTAL`).
- [x] The page detects a box that went silent (reset, flash mode): "Box not responding" after 3 s,
  new connection after 5 s.
- [ ] Flash budget: the app is about 1,033 KB of the 1.25 MB default app partition. Before
  ISO 15118-2 or OTA, switch to a partition scheme with a bigger app (e.g. "No OTA", 2 MB) or
  plan OTA around it.
- [ ] Mock box: replay a recorded session for UI development without hardware.
- [ ] Field test with a real car and charger (so far: bench sessions with pyPLC only).
- [ ] Licence file: add `LICENSE` (GPL-3.0) before publishing; `src/exi/` stays under its own
  LGPL-3.0 headers (OpenV2G).

## Later / ideas

- [ ] ISO 15118-2 decoding
- [ ] Keep earlier sessions in the browser (selectable list) instead of starting each session
  with an empty log
- [ ] Keep the session in IndexedDB, so a page reload keeps the full history (now: snapshot +
  last 100 messages)
- [ ] Chart: pinch zoom and pan, series toggles
- [ ] Beacon indicator (charger in range) in the status bar, as in ccs32dave
- [ ] Settings page in the UI (SSID, password, theme), stored in NVS
- [ ] OTA firmware update over the AP
- [ ] Raw-frame streaming to the browser and download as `.pcap` for Wireshark
- [ ] Support for other sniffer-capable modems or firmware versions, once they are tested

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
- [x] Sniffer tab: the sniffer firmware's status block (TEI learning and timing, traffic per
  direction, modem uptime and restarts, dropped management messages). Read with `RDM1` every
  0.5 s (`local_modem.*`), WebSocket message `sniffer`, serial `sniffer`. Verified (2026-10-11)
  with build v147 on a bench session: 2 reads/s, 0 timeouts, car TEI 3 learned 0.8 s after the
  join, first SDP response 0.9 s.
- [x] Network tab: "Read modem versions" button (one GET_SW broadcast on request, not cyclic as in
  ccs32dave), list with role, MAC, TEI and version, non-answering stations as "no answer".
  Verified (2026-10-11): sniffer V2.4 (844) and the pyPLC charger modem (1.4.0.20) answer.
- [x] Why the car modem (and a second sniffer) were missing from the version read: the sniffer's
  TEI switching. Every modem answers to the sniffer's own TEI, but while the sniffer follows a
  session it accepts the charger's or the car's TEI instead. Shown (2026-10-11): with the
  sniffer's own TEI set back to its real TEI the second sniffer answers; from the charger side all
  four modems answer, the Foccci as QCA7005 1.1.0.730. The paired Foccci sends an SDP request
  right after joining, which switches the sniffer again.
- [x] Version read pauses the sniffer's ping-pong (owner decision, contract section 5): armed = 0,
  OWN_TEI = nat_own, broadcast, 200 ms collection, armed = 1. Accepted cost: the V2G frames of
  ~0.3 s are not caught.
  Verified (2026-10-11, bench, two sniffers, 3 sessions, a read every 12 s): during a session a read
  gets the sniffer, the charger and the car (or the sniffer and the second sniffer: with two
  sniffers both switch, a bench-only case); no session lost, the ping-pong resumed every time.
- [x] Version list accumulates over the reads (box RAM, up to 16 modems, latest version and "last
  answer ... ago" per modem; modems that left the network stay as "not in the network now"); a
  Clear button (serial `versions clear`) empties it. Verified (2026-10-11): with the Foccci joined
  and no session running, one read got all four modems (both sniffers, charger 1.4.0.20, Foccci
  QCA7005 1.1.0.730).
- [ ] Mock box: replay a recorded session for UI development without hardware.
- [ ] Field test with a real car and charger (so far: bench sessions with pyPLC only).
- [ ] **Session tab blocks tab switching during a fast charge (field 2026-10-12, Tesla Supercharger).**
  CurrentDemand time and count kept updating (~30 CurrentDemand per second), but tapping another tab
  only grayed its name briefly; the tab stayed on "Session" for 1-2 min until the session was
  stopped at the station. Same item in the transparency repo: `backlog-0146`.
  What the code says: the tab switch is client-only (`web/index.html` tab click handler, no
  round trip to the box), so the page itself was stuck. On the Session tab every animation frame
  that a new message schedules runs `renderSession()`, which rebuilds the whole ladder from all
  `S.items` (`buildLadder()`, up to 20000 items, two regex replaces each) and recreates the
  timeline and 60 rows. At ~60 messages/s that is several thousand items per frame after 2 min.
  Hypotheses: (H1) `renderSession` saturates the main thread, clicks wait - only on the Session
  tab, worse with session length; (H2) the message flood alone saturates the page - other tabs
  block too; (H3) box side (WebSocket stall, heap) - unlikely, the click needs no server.
  Plan:
  1. Reproduce without a car: a Python mock box (see "Mock box" above) serves `web/index.html` and
     speaks the WebSocket protocol (`docs/web-ui.md`): hello/status/session at 1 Hz plus
     CurrentDemandReq/Res `msg` items at 10, 30, 60 pairs/s. Replay the field session instead if
     a page export ("save") from the Supercharger exists. Test on the real tablet and in desktop
     Chrome with CPU throttling.
  2. Measure: Chrome Performance profile (render time, `buildLadder` share, input delay); for the
     tablet (no console) a debug readout behind a flag in the status bar: render ms, renders/s,
     messages/s. Each rate on each tab; note the item count at which switching starts to block.
  3. Rule out H3: the same load through the real box (pyPLC bench with a fast CurrentDemand loop,
     or the mock feeding the box), watch serial `S` lines for ws / wsdrop / heap.
  4. Fix after confirming: incremental ladder (extend the last row, process only new items,
     cache `baseName`), throttle Session-tab rendering to ~4 Hz, skip render when nothing is
     dirty. Verify with the same reproduction at 30 and 60 pairs/s on the tablet.
  **Quick fix applied 2026-10-13 without steps 1-3:** incremental `buildLadder()` (full rebuild
  only after a session reset or the 20000-item trim) and Session-tab rebuild at most every
  250 ms and only when dirty (`SESSION_RENDER_MS`). Headless Chrome on the desktop: `renderSession`
  8.8 ms at 15000 items (x60/s before) -> ~0.1 ms (max 4/s); incremental == full rebuild,
  checked across the trim. **Log tab too:** same 250 ms throttle (`HEAVY_RENDER_MS`, shared
  with Session); while following, only new rows are appended and the oldest dropped beyond 500
  (full rebuild only on filter/search/jump/tab switch, trim, session reset; the newest 500
  matches are searched from the end); while scrolled up the table no longer follows new items
  (use "jump"). Render 17.7 ms -> 0.4 ms; incremental == full rebuild in 48 checks over four
  filters, a search and the trim. Built and uploaded to the box 2026-10-13 (boots, serial `S` lines
  normal). Not yet verified on the tablet or in a real fast charge - next field session.
  Open questions for the owner: which tablet/browser was used; did the counter on the page match
  the box's real rate (serial `session`), or did the page lag behind?
- [x] Licence file: `LICENSE` (GPL-3.0, text as in ccs32dave); `src/exi/` stays under its own
  LGPL-3.0 headers (OpenV2G).

## Later / ideas

- [ ] **Cloud status / debug upload via a second Wi-Fi (to be discussed, owner 2026-10-11).** The ESP32 supports
  AP+STA (`WIFI_AP_STA`, esp32 core 3.0.2): keep the `ccs32ebony` AP and additionally join an existing
  Wi-Fi as a client; the Ethernet stays sniff-only (no IP), so this client is the only way out.
  Known constraints:
  - One radio, one channel: the AP follows the joined network's channel; a tablet on the AP drops
    briefly when that happens (the page reconnects by itself).
  - Heap: about 140 KB free with one viewer; TLS (HTTPS / MQTT over TLS) costs about 40-50 KB per
    connection - measure.
  - Flash: app about 1.04 MB of 1.25 MB; an HTTPS/MQTT client adds about 100-200 KB, so the
    partition scheme probably has to change first (see "Flash budget" above).
  - In the field there is no site Wi-Fi: realistic is a phone hotspot. If the tablet itself is the
    hotspot, ebony could join it and the AP would mostly be a fallback.
  Open questions:
  1. Which network in the field: phone hotspot, the tablet's hotspot, something else?
  2. Cloud target: MQTT broker, HTTPS POST to an own server, an existing service (Google Sheet,
     InfluxDB, ...)? With or without TLS?
  3. What and how often: e.g. the sniffer status block every 10 s plus events (modem restart, SDP
     miss, rejected MME), and/or a session summary at the end?
  4. Credentials: in `ebony_config.h` at build time, or entered on the page and stored in NVS
     (needs the settings page below)?

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

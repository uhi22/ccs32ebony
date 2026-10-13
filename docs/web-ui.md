# Tablet web UI

The UI replaces ccs32dave's nine TFT pages with one touch-friendly single-page app. All of
ccs32dave's information is still there, rearranged for a 10" landscape screen. It also works in
portrait and on phones.

## Design principles

- **Glanceable.** The most important numbers (voltage, current, power, SoC, phase) are readable
  from a metre away.
- **Never lie.** If a value is stale (no update for a few seconds) or a message was missed, the UI
  shows this: values fade, and gaps are marked in charts and in the ladder.
- **Offline.** All assets come from the ESP32. No external fonts, CDNs or tracking.
- **Times as fine as they are meaningful.** The box stamps each message to the millisecond when
  it decodes it. The Log shows `m:ss.cc` (0.01 s), because a request and its response are often
  only 30–40 ms apart. The ladder and all durations use 0.1 s.
- **One colour per measurement, everywhere.** Voltage blue, current aqua, power violet, SoC
  green, in the Live tiles and in the charts alike. Target values are always orange. Each chart
  panel has a single y-axis (no dual-axis charts), and the panels share the time axis.
- **Light and dark theme.** Follows the system setting and can be toggled with the ◐ button.
- **No secrets visible by default.** NMK, NID, EVCCID and SessionID are masked until you tap them.
  Screenshots shared online stay clean.

## Layout

A persistent **status bar** at the top, with the tabs directly below it (they scroll sideways on
narrow screens). The last tab and the theme are remembered on the device.

### Status bar (always visible)

- connection to the box: connected / "Box not responding" (no message for 3 s) / reconnecting
- local modem: sniffer build tag, "stock firmware?", or not answering; Ethernet down
- session network: joined or not
- session phase: running phase, "Stopped in <phase>" or "Finished"
- TLS warning when the charger selected TLS (V2G content cannot be decoded then)

### Tabs

1. **Live** (default)
   Large tiles: **Present** (charger) and **Target** (car), each showing voltage and current at
   the same size, then power (computed) and SoC as a ring. Below them: a phase progress strip
   (SLAC → SDP → … → CurrentDemand → stop) with the duration of each phase (the running one counts
   up), and the last message with its response code. A mini chart shows the last 2 minutes of U/I.
   Tiles and phases follow every decoded message at once. The 1 Hz `session` snapshot is the
   reference, and a message only updates a value or the phase if it is newer.
2. **Chart**
   Voltage, current, power and SoC over the whole session, or the last 10 or 2 minutes. One
   panel per measurement, present and target in the same panel. Drag or tap to move the
   crosshair: all panels follow it, and each panel's header shows the values at that time (the
   latest values otherwise). Lines break where no value came for more than 3 s. "Show table"
   lists the values every 5 s.
3. **Session**
   - Timeline: one bar per phase with its duration and status (running, stopped, not reached),
     as in ccs32dave page 4.
   - Message ladder between car and charger (ccs32dave page 9). Consecutive messages of the same
     exchange collapse into one row with a count. Tap a row to see the decoded fields of its last
     message.
   - Redrawn at most 4 times per second (up to ~60 messages/s arrive in a fast charge), so the
     newest row may lag by up to 0.25 s.
4. **Details**
   - SDP request and response, charger address
   - Protocol handshake: offered schemas, the selected one, the result (ccs32dave page 2)
   - ChargeParameterDiscovery, car vs. charger side by side (ccs32dave page 3)
   - Energy: kWh, Ah, peak and average power, time with current flowing (ccs32dave page 8)
   - Identity and keys, masked until tapped (ccs32dave page 7)
5. **Network**
   Frame counters by type with rates, decode results and TCP gaps. The local modem (version,
   sniffer tag, joined, station list) and the box (firmware, uptime, memory, viewers). SLAC
   attenuation profile per carrier group as a bar chart (ccs32dave page 5).
   **Modems in the network:** the button "Read modem versions" makes the box send one GET_SW
   broadcast. The list accumulates over the reads (kept in the box's RAM until "Clear" or a box
   restart), each modem with its latest version and when it last answered ("12 s ago"); a modem
   that is no longer in the network shows as "not in the network now". Listed with role (this sniffer, charger (CCo), car =
   the station with the sniffer's learned car TEI, other station), MAC, TEI and firmware version.
   Stations of the network that did not answer are listed as "no answer". Read only on request,
   never cyclically (unlike ccs32dave). The other modems answer to the sniffer's own TEI, which the
   sniffer does not accept while it follows a session; so the box pauses the sniffer's ping-pong
   for the read (about 0.3 s: pause, broadcast, 200 ms collection, resume) and the page says so.
   V2G frames of that moment are not caught; the charging session itself is not affected.
6. **Sniffer**
   The sniffer firmware's status block (sniffer builds v146..v199), refreshed every 0.5 s: TEI
   learning (state, car / charger / own TEI, candidates, found or missed at the SDP request,
   fallback retries), timing after the join (SDP request, car TEI learned, first SDP response),
   join state, traffic caught (all frames, V2G TCP to the charger and to the car, SDP) with rates,
   foreign management messages dropped (v147+), and the firmware (build, modem uptime, time since
   its last restart, restarts seen by the box). Unexpected values (a miss, more than one car
   candidate, dropped messages, restarts) are shown in red. When a car TEI is known, the status bar
   shows it next to "Joined session network".
7. **Log**
   All SLAC, SDP and V2G messages of the session, starting with its first SLAC message.
   Filterable (SLAC / SDP / V2G / errors) and searchable; the table shows the newest 500 matching
   messages. While at the bottom it follows new messages (redrawn at most 4 times per second);
   when you scroll up, the table holds still for reading and "jump" returns to following.

### Export

From the Log tab:

- **JSON**: the session state and all messages as the browser recorded them (for later analysis
  or bug reports).
- **CSV**: time series of U, I, P and SoC, for spreadsheets.
- Keys and identifiers are left out unless you tick "include identifiers".

The browser keeps the current session in memory. A page reload starts from the box's snapshot
and its last 100 messages.

## WebSocket protocol (version 1)

Endpoint `ws://<box>/ws`. Text frames, one JSON object per frame, with a `t` field for the type.
All times are milliseconds since the ESP32 booted (`ms`). The browser maps them to wall-clock
time.

| `t` | Direction | Content |
|---|---|---|
| `hello` | box → UI | firmware version, build date, protocol version, uptime |
| `status` | box → UI | link, modem, frame and decoder counters, viewers; 1 Hz and on connect |
| `session` | box → UI | the whole current session state (idempotent); 1 Hz and on connect |
| `begin` | box → UI | a new session starts (at the SLAC match): `id`, `late` (the box came in mid-session), `slac` (start of its SLAC run; the UI moves the SLAC messages from then on into the new session, so Log and ladder start with `SLAC_PARAM`) |
| `msg` | box → UI | one decoded V2G message: `dir` (car/charger), `name`, `ok`, `rc`, `tU` `tI` `pU` `pI` `soc` if present |
| `event` | box → UI | one SLAC or SDP event: `dir`, `name` (e.g. `SLAC_PARAM.REQ`, `SDPRes none TCP port 15118`) |
| `live` | box → UI | the replay after connecting is complete |
| `get` | UI → box | request `status` and `session` now |
| `sniffer` | box → UI | the sniffer's status block, after each read (2 Hz) and on connect; see below |
| `versions` | box → UI | the accumulated version list: `running`, `started` (box ms of the last read), `answers` (in the last read), `paused` (the sniffer's ping-pong was paused for it), `resumeFailed`, `list` (`mac`, `ver`, `seen` = box ms of its last answer); when a read starts, when it ends, after a clear, and on connect |
| `clearVersions` | UI → box | empty the version list |
| `readVersions` | UI → box | start a version read (pause the sniffer's ping-pong, one GET_SW broadcast, answers collected for 200 ms, resume) |
| `ping` | UI → box | keep-alive, every 10 s |

`status`: `ms`, Ethernet `link`/`speed`/`fd`, frame counters `rx`, `drop`, `mme`, `ipv6`, `ipv4`,
`other`, decoder counters `v2gOk`, `v2gFail`, `gaps`, `heap`, WebSocket clients `ws`, Wi-Fi
stations `sta`, and `modem` with `alive`, `mac`, `ver`, `fw` (`sniffer` / `stock` / `unknown`),
`tag`, `joined`, `cco`, `ccoMac`, `stations` (`mac`, `tei`).

`session`: `id`, `start`, `late`, `phases` (name, start, end; 0 = not reached), `current`,
`live` (last message, response code, target/present values and SoC with the time each was
last seen), `sdp`, `hs` (offered protocols, result, schema), `cpd` (request and response
limits), `ident` (EVCCID, SessionID, modem MACs, NID, NMK), `energy` (Wh, Ah, peak W, seconds
with current), `atten` (sounds, dB per carrier group).

`sniffer`: `ms`, `state` (`off` no sniffer build v146..v199 / `reading` / `valid` / `notRefreshed` modem
just restarted / `badLayout` / `noAnswer`), `reads`, `timeouts`, `restarts` (modem restarts seen by the
box), `lastRestart` (modem uptime ms at the last one), and `b` with the decoded block: `build`, `size`,
`up` (modem uptime ms), `seq` (10 Hz since the modem's last firmware start), `tJoin` `tSdp` `tLearned`
`tFirstResp` (modem uptime ms, 0 = not yet), `own`, `cco`, `assoc`, `fsm`, `teiA`, `teiB`, `natOwn`,
`cands`, `found`, `miss`, `retryOk`, `pending`, `retryMiss`, `clears`, `nSt`, `maxTei`, `tcpCharger`,
`tcpCar`, `frames`, `sdpReq`, `sdpResp`, and from v147 `rej` and `rejLast` (MMTYPE). The block's meaning
is defined by the sniffer firmware (see concept.md, "Talking to the local modem"); the times in `b`
are the modem's, not the box's. Added without a protocol version change: an older page ignores it.

All times are box milliseconds. The UI derives the session state: running while messages
arrive, then "stopped in <phase>" or "finished" after 10 s of silence.

Example:

```json
{"t":"msg","ms":123456,"dir":"charger","ok":true,"name":"CurrentDemandRes","rc":0,"pU":398.5,"pI":102.0}
```

The format is versioned in `hello`. The UI refuses to run against an incompatible box version
and tells you why.

## Implementation notes

- Plain HTML, CSS and JavaScript with no framework, so the packed size stays small (target: under
  100 KB gzip). Charts are drawn on `<canvas>` by our own small code.
- The UI source lives in `web/index.html`. After every change, run `python tools/pack_web.py`. It
  writes `webui_assets.h` (gzip byte array), which is committed so the sketch builds without
  Python.
- The server (`webui.cpp`) is our own minimal HTTP + WebSocket implementation, with no library.
  `GET /` serves the page and `/ws` is the WebSocket. The operating systems' connectivity
  checks (Apple `hotspot-detect.html`, Android `generate_204`, Windows `connecttest.txt`, ...)
  are answered as "internet OK" (`WIFI_CAPTIVE_PORTAL 0`). Every other path redirects to `/`.
  With `WIFI_CAPTIVE_PORTAL 1` the checks are redirected too, and the UI pops up as a captive
  portal.
- Each WebSocket client has a 4 KB output queue, flushed non-blocking from `loop()`. A client
  whose queue overflows is disconnected rather than stalling frame processing, and the page
  reconnects by itself. The page sends `{"t":"ping"}` every 10 s, and the box closes connections
  that stay silent for 30 s.
- The 1 Hz `status` is also the heartbeat. With no message for 3 s the page shows "Box not
  responding". After 5 s it drops the socket and connects again. When the box resets or its
  Wi-Fi disappears, browsers (Safari in particular) often deliver no close event for minutes, so
  the page can't rely on one.
- On connect the box sends `hello`, `status` and `session`, then replays its last 100
  `begin`/`msg`/`event` messages, paced by the client's queue, then `live`. Only after that does
  the client get live messages, so the history arrives in order and without duplicates.
- Planned: develop the UI in a desktop browser against a **mock box**, a small script that replays
  a recorded session over WebSocket. Then UI work needs no hardware.

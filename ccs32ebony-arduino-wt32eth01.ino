// ccs32ebony: passive CCS charging-session viewer on the WT32-ETH01 (ESP32 + LAN8720).
//
// Milestone 1 (current): receive all Ethernet frames from the sniffer modem and log them on the
// serial port. The only frames sent on Ethernet are queries to the local modem (local_modem.h).
//
// Board:  WT32-ETH01 Ethernet Module (esp32 core 3.x, FQBN esp32:esp32:wt32-eth01)
// Wiring: see docs/hardware-setup.md

#if __has_include("ebony_config.h")
#include "ebony_config.h"
#else
#include "ebony_config.example.h"
#endif
#ifndef WIFI_CAPTIVE_PORTAL  // older local configs
#define WIFI_CAPTIVE_PORTAL 0
#endif

#include "eth_sniff.h"
#include "homeplug.h"
#include "local_modem.h"
#include "webui.h"
#include "v2gtp.h"
#include "v2g_exi.h"
#include "session.h"
#include "json_out.h"

#define FW_NAME "ccs32ebony"
#define FW_VERSION "0.1.0"

#define SUMMARY_INTERVAL_MS 1000
#define WEB_STATUS_INTERVAL_MS 1000
#define WEB_PROTOCOL_VERSION 1  // WebSocket message format, see docs/web-ui.md

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_HOMEPLUG 0x88E1
#define ETHERTYPE_HOMEPLUG_MEDIAXTREAM 0x8912

#define IPV6_NEXT_TCP 6
#define IPV6_NEXT_UDP 17
#define IPV6_NEXT_ICMPV6 58

EthSniffer eth;
LocalModem modem(eth);
WebUi web;
V2gtpReassembler v2gtp;
Session session;

// Decoder results, counted in loop() context
struct {
  uint32_t ok = 0;    // V2G messages decoded
  uint32_t fail = 0;  // V2G messages that did not decode (often a wrong message boundary after a gap)
  uint32_t sdp = 0;   // SDP requests and responses
} decoded;

// Frame counters by type, counted in loop() context
struct {
  uint32_t mme = 0;
  uint32_t ipv6 = 0;
  uint32_t ipv4 = 0;
  uint32_t other = 0;
  uint32_t local = 0;  // answers of the local modem to our queries (not logged as F lines)
} counts;

bool logFrames = true;   // one line per frame ("log 0|1")
uint8_t hexBytes = 0;    // additionally dump the first n bytes of each frame ("hex <n>")

static uint16_t be16(const uint8_t *p) { return (p[0] << 8) | p[1]; }
static uint16_t le16(const uint8_t *p) { return p[0] | (p[1] << 8); }

static void printMac(const uint8_t *m) {
  Serial.printf("%02x%02x%02x%02x%02x%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

// Short protocol summary: MME type for HomePlug, transport and ports for IPv6
static void printInfo(uint16_t etherType, const uint8_t *frame, uint16_t len) {
  if (etherType == ETHERTYPE_HOMEPLUG && len >= 17) {
    char name[32];
    homeplug::describeMmtype(le16(frame + 15), name, sizeof(name));
    Serial.printf(" %s", name);
  } else if (etherType == ETHERTYPE_IPV6 && len >= 54) {
    const uint8_t *ip = frame + 14;
    uint8_t next = ip[6];
    const uint8_t *l4 = ip + 40;
    if (next == IPV6_NEXT_UDP && len >= 62) {
      Serial.printf(" UDP %u>%u", be16(l4), be16(l4 + 2));
    } else if (next == IPV6_NEXT_TCP && len >= 74) {
      uint8_t dataOffset = (l4[12] >> 4) * 4;
      int payload = be16(ip + 4) - dataOffset;
      Serial.printf(" TCP %u>%u flags 0x%02x payload %d", be16(l4), be16(l4 + 2), l4[13], payload);
    } else if (next == IPV6_NEXT_ICMPV6) {
      Serial.printf(" ICMPv6 type %u", l4[0]);
    } else {
      Serial.printf(" next %u", next);
    }
  }
}

// ---- Decoding (lines "D ..." on the serial port, printed regardless of "log") -----------------

static const char *sdpSecurityName(uint8_t s) { return s == 0x00 ? "TLS" : s == 0x10 ? "no-TLS" : "sec?"; }
static const char *sdpTransportName(uint8_t t) { return t == 0x00 ? "TCP" : t == 0x10 ? "UDP" : "?"; }

// SDP: V2GTP over UDP - header 01 FE, payload type (2), length (4), then request 0x9000 =
// security, transport; response 0x9001 = IPv6 address (16), port (2), security, transport
static void decodeSdp(const uint8_t *frame, uint16_t len, uint16_t ipPayloadLen) {
  static const uint16_t OFS_V2GTP = 14 + 40 + 8;  // Ethernet, IPv6, UDP headers
  if (ipPayloadLen < 8 + 8 || 54u + ipPayloadLen > len) {
    return;
  }
  const uint8_t *p = &frame[OFS_V2GTP];
  if (p[0] != 0x01 || p[1] != 0xFE) {
    return;
  }
  uint16_t type = be16(p + 2);
  uint32_t payloadLen = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) | (p[6] << 8) | p[7];
  if (8u + 8u + payloadLen > ipPayloadLen) {
    return;
  }
  const uint8_t *d = &p[8];
  if (type == 0x9000 && payloadLen == 2) {
    decoded.sdp++;
    Serial.printf("D %lu car     SDPReq %s %s\n", millis(), sdpSecurityName(d[0]), sdpTransportName(d[1]));
    session.onSdpReq(d[0], d[1], millis());
  } else if (type == 0x9001 && payloadLen == 20) {
    decoded.sdp++;
    Serial.printf("D %lu charger SDPRes %s %s port %u\n", millis(), sdpSecurityName(d[18]),
                  sdpTransportName(d[19]), be16(d + 16));
    session.onSdpRes(d, be16(d + 16), d[18], d[19], millis());
  }
}

static void printV2g(const V2gValues &v, bool ok) {
  size_t n = strlen(v.msgName);
  bool isRes = n >= 3 && strcmp(v.msgName + n - 3, "Res") == 0;
  Serial.printf("D %lu %s %s%s", millis(), !ok ? "?      " : isRes ? "charger" : "car    ",
                ok ? "" : "decode failed: ", v.msgName);
  if (v.hasResponseCode) Serial.printf(" rc %u", v.responseCode);
  if (v.hasTargetVoltage) Serial.printf(" target %.1fV", v.targetVoltage);
  if (v.hasTargetCurrent) Serial.printf(" %.1fA", v.targetCurrent);
  if (v.hasPresentVoltage) Serial.printf(" present %.1fV", v.presentVoltage);
  if (v.hasPresentCurrent) Serial.printf(" %.1fA", v.presentCurrent);
  if (v.hasSoc) Serial.printf(" SoC %d%%", v.soc);
  if (v.hasEvLimits) Serial.printf(" EVmax %.1fV %.1fA", v.evMaxVoltage, v.evMaxCurrent);
  if (v.hasEvseLimits) {
    Serial.printf(" EVSEmax %.1fV %.1fA min %.1fV %.1fA", v.evseMaxVoltage, v.evseMaxCurrent,
                  v.evseMinVoltage, v.evseMinCurrent);
  }
  if (v.hasEvseMaxPower) Serial.printf(" %.0fW", v.evseMaxPower);
  for (uint8_t i = 0; i < v.appProtocolCount; i++) {
    const V2gValues::AppProtocol &a = v.appProtocols[i];
    Serial.printf(" [%s v%u.%u id %u prio %u]", a.ns, a.versionMajor, a.versionMinor, a.schemaId, a.priority);
  }
  if (v.hasHandshakeResult) Serial.printf(" result %u", v.handshakeResponseCode);
  if (v.hasSelectedSchema) Serial.printf(" schema %u", v.selectedSchemaId);
  Serial.println();
}

// TCP segments go to the V2GTP reassembler; a complete V2GTP message is EXI-decoded
static void decodeIpv6(const uint8_t *frame, uint16_t len) {
  if (len < 14 + 40 + 8) {
    return;
  }
  uint16_t ipPayloadLen = be16(frame + 18);
  if (54u + ipPayloadLen > len) {
    return;  // truncated frame
  }
  uint8_t next = frame[20];
  if (next == IPV6_NEXT_UDP) {
    decodeSdp(frame, len, ipPayloadLen);
    return;
  }
  if (next != IPV6_NEXT_TCP || ipPayloadLen < 20) {
    return;
  }
  const uint8_t *tcp = frame + 54;
  uint32_t seq = ((uint32_t)tcp[4] << 24) | ((uint32_t)tcp[5] << 16) | (tcp[6] << 8) | tcp[7];
  uint8_t headerLen = (tcp[12] >> 4) * 4;
  if (headerLen < 20 || headerLen > ipPayloadLen) {
    return;
  }
  uint16_t payloadLen = ipPayloadLen - headerLen;
  const uint8_t *msg;
  uint16_t msgLen;
  if (payloadLen > 0 && v2gtp.feed(frame + 6, seq, tcp + headerLen, payloadLen, &msg, &msgLen)) {
    V2gValues v;
    bool ok = decodeV2gExiPayload(msg + 8, msgLen - 8, v);  // skip the V2GTP header
    if (ok) decoded.ok++; else decoded.fail++;
    printV2g(v, ok);
    session.onV2g(v, ok, millis());
  }
}

static void logFrame(const uint8_t *frame, uint16_t len, uint16_t etherType);

static void onFrame(const uint8_t *frame, uint16_t len) {
  if (len < 14) {
    counts.other++;
    return;
  }
  if (modem.handleFrame(frame, len, millis())) {
    counts.local++;
    return;
  }
  uint16_t etherType = be16(frame + 12);
  switch (etherType) {
    case ETHERTYPE_HOMEPLUG: counts.mme++; break;
    case ETHERTYPE_IPV6: counts.ipv6++; break;
    case ETHERTYPE_IPV4:
    case ETHERTYPE_ARP: counts.ipv4++; break;
    default: counts.other++; break;
  }
  if (logFrames) {
    logFrame(frame, len, etherType);
  }
  if (etherType == ETHERTYPE_IPV6) {
    decodeIpv6(frame, len);
  } else if (etherType == ETHERTYPE_HOMEPLUG) {
    session.onHomeplug(frame, len, millis());
    homeplug::SlacMatch match;
    if (homeplug::parseSlacMatchCnf(frame, len, match)) {
      Serial.printf("D %lu charger SLAC match, car ", millis());
      printMac(match.pevMac);
      Serial.print(" charger ");
      printMac(match.evseMac);
      Serial.println();  // NID and NMK are not logged
    }
  }
}

// F <ms> <dst> <src> <ethertype> <len> <info>
static void logFrame(const uint8_t *frame, uint16_t len, uint16_t etherType) {
  Serial.printf("F %lu ", millis());
  printMac(frame);
  Serial.print(' ');
  printMac(frame + 6);
  Serial.printf(" %04x %u", etherType, len);
  printInfo(etherType, frame, len);
  Serial.println();
  if (hexBytes > 0) {
    uint16_t n = min<uint16_t>(hexBytes, len);
    Serial.print("  ");
    for (uint16_t i = 0; i < n; i++) {
      Serial.printf("%02x%s", frame[i], (i % 16 == 15 && i + 1 < n) ? "\n  " : " ");
    }
    Serial.println();
  }
}

static void printSummary() {
  // S <ms> link <up/down> rx <n> drop <n> mme <n> ipv6 <n> ipv4 <n> other <n> local <n> tx <n>
  //   modem <ok/-> sta <Wi-Fi stations> ws <WebSocket clients> wsdrop <n>
  //   v2g <decoded>/<failed> sdp <n> gaps <TCP gaps> resync <n> heap <bytes>
  Serial.printf("S %lu link %s", millis(), eth.linkUp() ? "up" : "down");
  if (eth.linkUp()) {
    Serial.printf(" %lu%s", eth.linkSpeedMbps(), eth.fullDuplex() ? "FD" : "HD");
  }
  Serial.printf(" v2g %lu/%lu sdp %lu gaps %lu resync %lu", decoded.ok, decoded.fail, decoded.sdp,
                v2gtp.gaps(), v2gtp.resyncs());
  Serial.printf(" rx %lu drop %lu mme %lu ipv6 %lu ipv4 %lu other %lu local %lu tx %lu modem %s"
                " sta %u ws %u wsdrop %lu heap %lu\n",
                eth.rxFrames(), eth.rxDropped(), counts.mme, counts.ipv6, counts.ipv4, counts.other,
                counts.local, eth.txFrames(), modem.alive(millis()) ? "ok" : "-", web.apStations(),
                web.wsClients(), web.wsDropped(), (unsigned long)ESP.getFreeHeap());
}

// ---- WebSocket messages (JSON, see docs/web-ui.md) ----------------------------------------

static void sendHello(uint8_t id) {
  char buf[160];
  JsonOut j(buf, sizeof(buf));
  j.raw("{\"t\":\"hello\",\"fw\":\"%s\",\"ver\":\"%s\",\"build\":\"%s %s\",\"proto\":%u,\"ms\":%lu}",
        FW_NAME, FW_VERSION, __DATE__, __TIME__, WEB_PROTOCOL_VERSION, millis());
  web.sendTo(id, buf);
}

static bool buildStatus(char *buf, size_t size) {
  uint32_t now = millis();
  JsonOut j(buf, size);
  j.raw("{\"t\":\"status\",\"ms\":%lu,\"link\":%s,\"speed\":%lu,\"fd\":%s,"
        "\"rx\":%lu,\"drop\":%lu,\"mme\":%lu,\"ipv6\":%lu,\"ipv4\":%lu,\"other\":%lu,"
        "\"v2gOk\":%lu,\"v2gFail\":%lu,\"gaps\":%lu,"
        "\"heap\":%lu,\"ws\":%u,\"sta\":%u,\"modem\":{\"alive\":%s",
        now, eth.linkUp() ? "true" : "false", eth.linkSpeedMbps(), eth.fullDuplex() ? "true" : "false",
        eth.rxFrames(), eth.rxDropped(), counts.mme, counts.ipv6, counts.ipv4, counts.other,
        decoded.ok, decoded.fail, v2gtp.gaps(),
        (unsigned long)ESP.getFreeHeap(), web.wsClients(), web.apStations(),
        modem.alive(now) ? "true" : "false");
  if (modem.known()) {
    j.raw(",\"mac\":").mac(modem.mac());
    j.raw(",\"ver\":").str(modem.version());
  }
  const char *fw = modem.firmware() == LocalModem::Firmware::Sniffer ? "sniffer"
                 : modem.firmware() == LocalModem::Firmware::Stock   ? "stock"
                                                                      : "unknown";
  j.raw(",\"fw\":\"%s\",\"tag\":", fw).str(modem.snifferTag());
  j.raw(",\"joined\":").boolean(modem.joined());
  if (modem.joined()) {
    const homeplug::VsNetworkInfo &nw = modem.networkInfo();
    j.raw(",\"cco\":%u,\"ccoMac\":", nw.ccoTei).mac(nw.ccoMac).raw(",\"stations\":[");
    for (uint8_t i = 0; i < nw.numStations; i++) {
      j.raw("%s{\"mac\":", i ? "," : "").mac(nw.stations[i].mac).raw(",\"tei\":%u}", nw.stations[i].tei);
    }
    j.raw("]");
  }
  j.raw("}}");
  return !j.truncated();
}

// id < 0: to all clients
static void sendTo(int id, const char *json) {
  if (id < 0) {
    web.broadcast(json);
  } else {
    web.sendTo(id, json);
  }
}

static void sendStatus(int id) {
  char buf[768];
  if (buildStatus(buf, sizeof(buf))) {
    sendTo(id, buf);
  } else {
    log_e("status message truncated");
  }
}

// The sniffer's status block (LocalModem, sniffer builds v146..v199); 2 Hz, after each block read
static bool buildSniffer(char *buf, size_t size) {
  static const char *const STATE[] = {"off", "reading", "valid", "notRefreshed", "badLayout", "noAnswer"};
  JsonOut j(buf, size);
  j.raw("{\"t\":\"sniffer\",\"ms\":%lu,\"state\":\"%s\",\"reads\":%lu,\"timeouts\":%lu,\"restarts\":%lu",
        millis(), STATE[(int)modem.blockState()], (unsigned long)modem.blockReads(),
        (unsigned long)modem.blockTimeouts(), (unsigned long)modem.modemRestarts());
  if (modem.modemRestarts() > 0) {
    j.raw(",\"lastRestart\":%lu", (unsigned long)modem.lastRestartUptimeMs());
  }
  if (modem.blockReads() > 0) {
    const SnifferStatus &b = modem.sniffer();
    j.raw(",\"b\":{\"build\":%u,\"size\":%u,\"up\":%lu,\"seq\":%lu,\"tJoin\":%lu,\"tSdp\":%lu,\"tLearned\":%lu,"
          "\"tFirstResp\":%lu,\"own\":%u,\"cco\":%u,\"assoc\":%u,\"fsm\":%u,\"teiA\":%u,\"teiB\":%u,"
          "\"natOwn\":%u,\"cands\":%u,\"found\":%u,\"miss\":%u,\"retryOk\":%u,\"pending\":%u,"
          "\"retryMiss\":%u,\"clears\":%u,\"nSt\":%u,\"maxTei\":%u,\"tcpCharger\":%u,\"tcpCar\":%u,"
          "\"frames\":%lu,\"sdpReq\":%u,\"sdpResp\":%u",
          b.build, b.size, (unsigned long)b.uptimeMs, (unsigned long)b.seq, (unsigned long)b.tJoin,
          (unsigned long)b.tSdp, (unsigned long)b.tLearned, (unsigned long)b.tFirstResp, b.ownTei, b.ccoTei,
          b.assoc, b.fsm, b.teiA, b.teiB, b.natOwn, b.cands, b.foundAtSdp, b.missAtSdp, b.foundByRetry,
          b.pending, b.retryMisses, b.clears, b.nStations, b.maxTei, b.tcpToCharger, b.tcpToCar,
          (unsigned long)b.frames, b.sdpReq, b.sdpResp);
    if (b.hasRejected) {
      j.raw(",\"rej\":%u,\"rejLast\":%u", b.rejectedMme, b.lastRejectedMmtype);
    }
    j.raw("}");
  }
  j.raw("}");
  return !j.truncated();
}

static void sendSniffer(int id) {
  char buf[768];
  if (buildSniffer(buf, sizeof(buf))) {
    sendTo(id, buf);
  } else {
    log_e("sniffer message truncated");
  }
}

// Result of the on-demand version scan (button "Read modem versions")
static void sendVersions(int id) {
  if (!modem.hasVersionResult()) {
    return;
  }
  static char buf[2048];  // up to 16 modems; static: too big for the loop task's stack
  JsonOut j(buf, sizeof(buf));
  j.raw("{\"t\":\"versions\",\"ms\":%lu,\"running\":%s,\"started\":%lu,\"paused\":%s,\"resumeFailed\":%s,"
        "\"answers\":%u,\"list\":[", millis(), modem.versionScanRunning() ? "true" : "false",
        (unsigned long)modem.versionScanStartedMs(), modem.versionScanPaused() ? "true" : "false",
        modem.versionScanResumeFailed() ? "true" : "false", modem.lastScanAnswers());
  for (uint8_t i = 0; i < modem.versionCount(); i++) {
    const ModemVersion &v = modem.versionAt(i);
    j.raw("%s{\"mac\":", i ? "," : "").mac(v.mac).raw(",\"ver\":").str(v.version)
        .raw(",\"seen\":%lu}", (unsigned long)v.lastSeenMs);
  }
  j.raw("]}");
  if (j.truncated()) {
    log_e("versions message truncated");
  } else {
    sendTo(id, buf);
  }
}

static void sendSession(int id) {
  static char buf[2048];  // static: too big for the loop task's stack
  if (session.snapshot(buf, sizeof(buf), millis())) {
    sendTo(id, buf);
  } else {
    log_e("session message truncated");
  }
}

// A new viewer first gets the recent msg/event messages from the session's ring, paced by its
// output queue, and only then the live ones - so they arrive in order and without duplicates
static uint32_t replayCursor[WebUi::MAX_CONNECTIONS];  // next sequence number to send
static bool replayDone[WebUi::MAX_CONNECTIONS];
static const size_t REPLAY_HEADROOM = 2560;  // queue space kept free for the status/session messages

// A new msg/event from the session model goes to all viewers that are live
static void onSessionMessage(const char *json) {
  for (uint8_t id = 0; id < WebUi::MAX_CONNECTIONS; id++) {
    if (web.isWebSocket(id) && replayDone[id]) {
      web.sendTo(id, json);
    }
  }
}

static void onWebConnect(uint8_t id) {
  sendHello(id);
  sendStatus(id);
  sendSniffer(id);
  sendVersions(id);
  sendSession(id);
  replayCursor[id] = session.oldestSeq();
  replayDone[id] = false;
}

static void feedReplay() {
  for (uint8_t id = 0; id < WebUi::MAX_CONNECTIONS; id++) {
    if (!web.isWebSocket(id) || replayDone[id]) {
      continue;
    }
    if (replayCursor[id] < session.oldestSeq()) {
      replayCursor[id] = session.oldestSeq();  // fell behind the ring: skip what was overwritten
    }
    while (replayCursor[id] <= session.newestSeq() &&
           web.txFree(id) > REPLAY_HEADROOM + Session::MESSAGE_LEN) {
      const char *json = session.bySeq(replayCursor[id]++);
      if (json != nullptr && !web.sendTo(id, json)) {
        break;
      }
    }
    if (web.isWebSocket(id) && replayCursor[id] > session.newestSeq()) {
      replayDone[id] = true;
      web.sendTo(id, "{\"t\":\"live\"}");
    }
  }
}

static void onWebText(uint8_t id, const char *text) {
  if (strstr(text, "\"t\":\"get\"") != nullptr) {
    sendStatus(id);
    sendSniffer(id);
    sendSession(id);
  }
  if (strstr(text, "\"t\":\"readVersions\"") != nullptr) {
    modem.startVersionScan(millis());
  }
  if (strstr(text, "\"t\":\"clearVersions\"") != nullptr) {
    modem.clearVersions();
  }
  // "ping" only keeps the connection alive
}

// ---- Serial commands -------------------------------------------------------------------------

static void handleCommand(String cmd) {
  cmd.trim();
  if (cmd == "log 0" || cmd == "log 1") {
    logFrames = cmd.endsWith("1");
    Serial.printf("log %u\n", logFrames);
  } else if (cmd.startsWith("hex")) {
    hexBytes = (uint8_t)constrain(cmd.substring(3).toInt(), 0, 255);
    Serial.printf("hex %u\n", hexBytes);
  } else if (cmd == "stat") {
    printSummary();
  } else if (cmd == "modem") {
    modem.printStatus(Serial);
  } else if (cmd == "versions") {
    modem.startVersionScan(millis());
  } else if (cmd == "versions clear") {
    modem.clearVersions();
    Serial.println("Modem versions: list cleared");
  } else if (cmd == "sniffer") {
    modem.printSniffer(Serial);
  } else if (cmd == "modem retag") {
    modem.retag();
    Serial.println("Modem: asking for the sniffer tag again");
  } else if (cmd == "session") {
    static char buf[2048];  // the same "session" message the UI gets
    if (session.snapshot(buf, sizeof(buf), millis())) {
      Serial.println(buf);
    } else {
      Serial.println("session message truncated");
    }
  } else if (cmd.length() > 0) {
    Serial.println("commands: log 0|1, hex <n>, stat, modem, modem retag, sniffer, versions, versions clear, session");
  }
}

static void pollSerial() {
  static String line;
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      if (line.length() > 0) {
        handleCommand(line);
      }
      line = "";
    } else if (line.length() < 80) {
      line += c;
    }
  }
}

void setup() {
  Serial.setTxBufferSize(8192);  // bursts of frame log lines
  Serial.begin(SERIAL_BAUD);
  delay(100);
  Serial.printf("\n%s %s, build %s %s\n", FW_NAME, FW_VERSION, __DATE__, __TIME__);
  Serial.printf("reset reason %d, free heap %lu\n", (int)esp_reset_reason(),
                (unsigned long)ESP.getFreeHeap());

  if (eth.begin()) {
    Serial.print("Ethernet started, promiscuous, own MAC ");
    printMac(eth.ownMac());
    Serial.println();
  } else {
    Serial.println("Ethernet start FAILED");
  }

  session.onMessage(onSessionMessage);
  web.onConnect(onWebConnect);
  web.onText(onWebText);
  if (web.begin(WIFI_AP_SSID, WIFI_AP_PASSWORD, WIFI_CAPTIVE_PORTAL)) {
    Serial.printf("Wi-Fi AP \"%s\" started, http://%s/\n", WIFI_AP_SSID, web.ip().toString().c_str());
  } else {
    Serial.println("Wi-Fi AP NOT started (password must have at least 8 characters, see ebony_config.h)");
  }
}

void loop() {
  static uint32_t lastSummary = 0;
  static uint32_t lastWebStatus = 0;
  static bool lastLink = false;

  eth.poll(onFrame);
  pollSerial();
  web.loop();
  feedReplay();

  uint32_t now = millis();
  modem.cycle(now);
  if (modem.takeBlockUpdate()) {
    sendSniffer(-1);
  }
  if (modem.takeVersionUpdate()) {
    sendVersions(-1);
  }
  if (now - lastWebStatus >= WEB_STATUS_INTERVAL_MS) {
    lastWebStatus = now;
    sendStatus(-1);
    sendSession(-1);
  }
  if (eth.linkUp() != lastLink) {
    lastLink = eth.linkUp();
    Serial.printf("Link %s\n", lastLink ? "up" : "down");
  }
  if (now - lastSummary >= SUMMARY_INTERVAL_MS) {
    lastSummary = now;
    printSummary();
  }
  delay(1);
}

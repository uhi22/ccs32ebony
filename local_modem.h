// State of the local powerline modem (the sniffer on our Ethernet port), learned by queries that
// only this modem answers:
//   1. GET_SW.REQ to the local management address -> the modem's MAC and version string
//   2. GET_SW.REQ "GST1" to that MAC             -> sniffer build tag, or none (stock firmware)
//   3. VS_NW_INFO.REQ to that MAC, every second    -> alive, joined / not joined
//   4. GET_SW.REQ "RDM1" x 5 to that MAC, every 0.5 s (sniffer builds v157..v199 only)
//                                                  -> the sniffer's 80-byte status block
// Nothing is broadcast cyclically, so these queries never reach the powerline session. The one
// exception is the version scan (startVersionScan, on demand only): a single GET_SW.REQ broadcast
// that every modem in the session network answers with its MAC and firmware version. The answers are
// addressed to the sniffer's own (real) TEI, which the sniffer does not accept while its ping-pong follows a
// session, so the scan pauses the ping-pong around the broadcast (contract section 5, "WRM1" writes):
// armed = 0, OWN_TEI = nat_own, broadcast, collect 200 ms, armed = 1. The firmware makes the first flip again
// within 100 ms (v157); the V2G frames of those ~0.3 s are not caught.
//
//
// Sniffer mode (v158, the firmware's mode byte at 0x22c4f8, contract section 5): 0 passive (silent on the real
// TEI), 1 ping-pong (the firmware's own init value), 2 selfIsCar (OWN_TEI held = the car's TEI), 3 selfIsCharger
// (held = the charger's TEI). The firmware learns the TEIs in every mode and holds OWN_TEI per mode itself; it
// re-inits the byte to 1 after each of its restarts, so modes 0/2/3 are re-written every 0.5 s. Switching to 1 is
// one write: the firmware makes the first flip within 100 ms.
//
// The status block is a contract with the sniffer firmware (source of truth: qca7000-transparency
// plans/interface-ardut-ebony.md): address 0x22c2a8, magic 'EBS1', layout 1, 80 bytes, v157 fields at 0x44..0x4a,
// the mode at 0x4d (v158). Only builds v158..v199 are supported (firmware and ebony are kept in sync).

#pragma once

#include <Arduino.h>

#include "eth_sniff.h"
#include "homeplug.h"

// Decoded status block (layout 1). Times are the modem's uptime in ms (since its power-on).
struct SnifferStatus {
  uint16_t build = 0;
  uint8_t size = 0;
  uint32_t uptimeMs = 0;
  uint32_t tJoin = 0, tSdp = 0, tLearned = 0, tFirstResp = 0;  // 0 = not (yet) in this join
  uint8_t ownTei = 0, ccoTei = 0, assoc = 0, fsm = 0;
  uint8_t teiA = 0, teiB = 0, natOwn = 0, cands = 0;
  uint8_t foundAtSdp = 0, missAtSdp = 0, foundByRetry = 0, pending = 0;
  uint8_t retryMisses = 0, clears = 0, nStations = 0, maxTei = 0;
  uint16_t tcpToCharger = 0, tcpToCar = 0;
  uint32_t frames = 0;
  uint16_t sdpReq = 0, sdpResp = 0;
  uint32_t seq = 0;                    // 10 Hz since the modem's last firmware start
  uint16_t rejectedMme = 0, lastRejectedMmtype = 0;
  // v157: learning independent of armed, tick fallback, firmware first flip
  uint8_t learnSrc = 0;                // 0 none, 1 SDP request, 2 per-frame retry, 3 tick fallback (this join)
  uint8_t c5Score = 0;                 // re-check counter (display only)
  uint8_t firstFlips = 0;              // first flips made by the firmware (since its last start)
  uint8_t disarmFixes = 0;             // OWN_TEI put back to nat_own while armed = 0 (since its last start)
  uint8_t sdpSeen = 0;                 // an SDP request was seen in this join
  uint8_t relearns = 0;                // car TEI corrected by the re-check (since its last start)
  uint8_t candAge = 0;                 // tick fallback: 100 ms ticks a car candidate has existed (255 = saturated)
  uint8_t mode = 1;                    // v158: the mode as the firmware's tick saw it
};

struct ModemVersion {
  uint8_t mac[6];
  char version[homeplug::VERSION_MAX_LEN + 1];  // the latest answer
  uint32_t lastSeenMs;                           // box millis() of the latest answer
};

class LocalModem {
public:
  // Status block reading
  enum class BlockState : uint8_t { Off, Reading, Valid, NotRefreshed, BadLayout, NoAnswer };
  enum class Firmware : uint8_t { Unknown, Sniffer, Stock };

  explicit LocalModem(EthSniffer &eth) : _eth(eth) {}

  // Sends the next query when due; call from loop()
  void cycle(uint32_t now);

  // Returns true if frame is an answer of the local modem to one of our queries (it is then
  // consumed: the caller does not need to log it as sniffed traffic)
  bool handleFrame(const uint8_t *frame, uint16_t len, uint32_t now);

  void printStatus(Print &out) const;

  // Asks for the sniffer build tag again (serial "modem retag"), e.g. after re-flashing the modem
  void retag();

  bool known() const { return _macKnown; }
  bool alive(uint32_t now) const { return _macKnown && now - _lastAnswerMs < ALIVE_TIMEOUT_MS; }
  const uint8_t *mac() const { return _mac; }
  const char *version() const { return _version; }
  Firmware firmware() const { return _firmware; }
  const char *snifferTag() const { return _tag; }
  bool joined() const { return _nwInfoValid && _nwInfo.numAvlns > 0; }
  const homeplug::VsNetworkInfo &networkInfo() const { return _nwInfo; }

  BlockState blockState() const { return _blockState; }
  const SnifferStatus &sniffer() const { return _sb; }
  uint32_t blockReads() const { return _blockReads; }          // complete blocks read
  uint32_t blockTimeouts() const { return _blockTimeouts; }    // block reads abandoned (no answer)
  uint32_t modemRestarts() const { return _restarts; }         // seq drops seen since the box started
  uint32_t lastRestartUptimeMs() const { return _lastRestartUptimeMs; }  // modem uptime at that restart
  // True once after each new complete block (the caller then sends it to the UI)
  bool takeBlockUpdate() { bool u = _blockUpdated; _blockUpdated = false; return u; }
  void printSniffer(Print &out) const;

  // Version scan: one GET_SW.REQ broadcast, answers collected for VERSION_SCAN_MS. The list accumulates
  // over the scans (RAM only) until clearVersions().
  void startVersionScan(uint32_t now);
  void clearVersions();
  uint8_t lastScanAnswers() const { return _lastScanAnswers; }
  bool versionScanRunning() const { return _scanPhase != ScanPhase::Idle; }
  bool versionScanPaused() const { return _scanPaused; }       // the ping-pong was paused for it
  bool versionScanResumeFailed() const { return _resumeFailed; }  // armed = 1 not confirmed
  uint32_t versionScanStartedMs() const { return _scanStartMs; }
  bool hasVersionResult() const { return _scanStartMs != 0 || _versionsCleared; }
  uint8_t versionCount() const { return _nVersions; }
  const ModemVersion &versionAt(uint8_t i) const { return _versions[i]; }
  // True once after a scan started and once after it finished (the caller then informs the UI)
  bool takeVersionUpdate() { bool u = _versionUpdated; _versionUpdated = false; return u; }
  void printVersions(Print &out) const;

  // Sniffer mode (see above)
  enum Mode : uint8_t { MODE_PASSIVE = 0, MODE_PINGPONG = 1, MODE_SELF_IS_CAR = 2, MODE_SELF_IS_CHARGER = 3 };
  static const char *modeName(uint8_t m);
  static int modeFromName(const char *name);                  // -1 = unknown
  void setMode(uint8_t m);
  uint8_t mode() const { return _mode; }
  bool modeConfirmed() const { return _modeOk; }              // the last mode write was read back
  uint32_t modeWrites() const { return _modeWrites; }         // confirmed re-writes since the mode was set
  uint32_t modeTimeouts() const { return _modeTimeouts; }
  // OWN_TEI is not what the mode wants right now (the firmware corrects it within 100 ms; holds only once learned)
  bool modeBreached() const;

  // OWN_TEI consumer mask (contract section 6). The firmware bakes all 41 sites to "real"; these flip
  // individual sites (or all) back to "follow" (the held/foreign TEI) for field bisection of the Alpitronic abort.
  // The override is a bit set (bit = "held follow"); it is re-applied after every modem restart.
  static constexpr uint8_t TEI_SITES = 41;
  void teiMaskSite(uint8_t site, bool follow);   // one site
  void teiMaskAll(bool follow);                  // all 41
  void teiMaskShow(Print &out) const;
  uint64_t teiMask() const { return _teiMask; }
  void resetModem();                             // VS_RS_DEV soft reset (seq restarts; triggers mask re-apply)

  // Raw memory access of the sniffer (serial "rd <addr> [len]" / "wr <addr> <value> [1|4]"), RDM1/WRM1 over GET_SW.
  // Only inside the mapped ranges (qca7000-transparency readme fact (z)): an unmapped read resets the modem, and the
  // V2.4 has no SPI recovery. One request at a time, after any outstanding block read / write / scan; output on Serial.
  bool memRead(uint32_t addr, uint16_t len);
  bool memWrite(uint32_t addr, uint32_t value, uint8_t width);
  static bool memMapped(uint32_t addr, uint32_t len);

private:
  bool teiMaskAllowed() const;                   // build in the contract range, else prints why and refuses
  static constexpr uint32_t QUERY_INTERVAL_MS = 1000;
  static constexpr uint32_t ALIVE_TIMEOUT_MS = 3500;
  static constexpr uint32_t FORGET_TIMEOUT_MS = 10000;  // re-learn the MAC (modem swapped/reset)
  static constexpr uint8_t TAG_REQUEST_TRIES = 5;
  static constexpr uint32_t BLOCK_INTERVAL_MS = 500;
  static constexpr uint32_t BLOCK_READ_TIMEOUT_MS = 300;    // per 16-byte read
  static constexpr uint32_t BLOCK_ADDR = 0x22c2a8;
  static constexpr uint8_t BLOCK_READS = 5;                 // 80 bytes
  static constexpr int BUILD_MIN = 158, BUILD_MAX = 199;    // contract range (kept in sync with the firmware)
  static constexpr uint32_t VERSION_SCAN_MS = 200;          // answers come within ~100 ms
  static constexpr uint32_t WRITE_TIMEOUT_MS = 300;
  static constexpr uint8_t RESUME_TRIES = 5;
  static constexpr uint32_t ADDR_ARMED = 0x22c4f8;           // contract section 5
  static constexpr uint32_t ADDR_OWN_TEI = 0x8bdec;
  static constexpr uint8_t MAX_VERSIONS = 16;
  static constexpr uint32_t PASSIVE_INTERVAL_MS = 500;

  void send(const uint8_t *frame, uint16_t len);
  void forget();
  void sendBlockRead();
  void decodeBlock();
  void sendWrite(uint32_t addr, uint32_t value, uint8_t width, uint32_t now);
  void sendWrite(uint32_t addr, uint8_t value, uint32_t now) { sendWrite(addr, (uint32_t)value, (uint8_t)1, now); }
  void queueMaskWrite(uint8_t site, bool follow);   // append one slot write to _queue
  void reapplyTeiMask();                            // re-queue the held-follow overrides after a restart
  void scanStep(uint32_t now);
  void finishScan();
  void passiveStep(uint32_t now);
  bool passiveConfirm(const uint8_t *readBack);
  void memStep(uint32_t now);
  void memAnswer(const uint8_t *content);

  EthSniffer &_eth;
  uint32_t _lastQueryMs = 0;
  uint32_t _lastAnswerMs = 0;

  bool _macKnown = false;
  uint8_t _mac[6] = {};
  char _version[homeplug::VERSION_MAX_LEN + 1] = "";

  Firmware _firmware = Firmware::Unknown;
  bool _tagPending = false;   // the next GET_SW.CNF answers the "GST1" request
  uint8_t _tagRequests = 0;
  char _tag[homeplug::VERSION_MAX_LEN + 1] = "";

  bool _nwInfoValid = false;
  bool _nwInfoDumped = false;  // first VS_NW_INFO.CNF is hex-dumped once, to check the layout
  bool _tagDumped = false;     // same for the first answer to the tag request
  homeplug::VsNetworkInfo _nwInfo = {};

  BlockState _blockState = BlockState::Off;
  bool _readPending = false;           // an "RDM1" request is outstanding
  uint8_t _readIndex = 0;              // which 16-byte part of the block
  uint32_t _readSentMs = 0;
  uint32_t _lastBlockStartMs = 0;
  uint8_t _raw[16 * BLOCK_READS] = {};
  SnifferStatus _sb;
  bool _sbValid = false;
  bool _blockUpdated = false;
  uint32_t _blockReads = 0, _blockTimeouts = 0;
  uint32_t _restarts = 0, _lastRestartUptimeMs = 0;

  enum class ScanPhase : uint8_t { Idle, Queued, Disarm, SetOwn, Collect, Rearm };
  ScanPhase _scanPhase = ScanPhase::Idle;
  uint32_t _scanStartMs = 0;
  uint32_t _collectStartMs = 0;
  bool _writePending = false;
  uint32_t _writeSentMs = 0;
  uint8_t _resumeTries = 0;
  bool _scanPaused = false, _resumeFailed = false;
  uint8_t _lastScanAnswers = 0;
  bool _versionsCleared = false;
  uint8_t _nVersions = 0;
  ModemVersion _versions[MAX_VERSIONS] = {};
  bool _versionUpdated = false;

  enum class HoldWrite : uint8_t { None, Armed, Queued };
  static constexpr uint32_t TEI_SLOT_REAL = 0x0022c4ea;   // slot value -> site reads nat_own (baked default)
  static constexpr uint32_t TEI_SLOT_FOLLOW = 0x0008bdd8;  // slot value -> site reads OWN_TEI (the override)
  static const uint32_t TEI_SLOT_ADDR[TEI_SITES];          // the 41 slot write addresses (local_modem.cpp)
  struct QueuedWrite { uint32_t addr; uint32_t value; uint8_t width; };
  QueuedWrite _queue[TEI_SITES] = {};                   // up to 41 mask writes
  uint8_t _queueLen = 0, _queuePos = 0, _queueTries = 0;
  uint64_t _teiMask = 0;     // bit i set = site i held "follow" (overriding the baked "real"); 0 = all real
  uint8_t _mode = MODE_PINGPONG;
  bool _modeOk = false;
  HoldWrite _holdWrite = HoldWrite::None;   // which mode / queued write is outstanding
  uint32_t _lastPassiveMs = 0;
  uint32_t _modeWrites = 0, _modeTimeouts = 0;

  static constexpr uint16_t MEM_READ_MAX = 256;
  bool _memActive = false, _memPending = false, _memWrite = false;
  uint32_t _memAddr = 0, _memValue = 0, _memSentMs = 0;
  uint16_t _memLeft = 0;
  uint8_t _memWidth = 1, _memTries = 0;
};

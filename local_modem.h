// State of the local powerline modem (the sniffer on our Ethernet port), learned by queries that
// only this modem answers:
//   1. GET_SW.REQ to the local management address -> the modem's MAC and version string
//   2. GET_SW.REQ "GST1" to that MAC             -> sniffer build tag, or none (stock firmware)
//   3. VS_NW_INFO.REQ to that MAC, every second    -> alive, joined / not joined
//   4. GET_SW.REQ "RDM1" x 5 to that MAC, every 0.5 s (sniffer builds v146..v199 only)
//                                                  -> the sniffer's 80-byte status block
// Nothing is broadcast cyclically, so these queries never reach the powerline session. The one
// exception is the version scan (startVersionScan, on demand only): a single GET_SW.REQ broadcast
// that every modem in the session network answers with its MAC and firmware version. The answers are
// addressed to the sniffer's own (real) TEI, which the sniffer does not accept while its ping-pong follows a
// session, so the scan pauses the ping-pong around the broadcast (contract section 5, "WRM1" writes):
// armed = 0, OWN_TEI = nat_own, broadcast, collect 200 ms, armed = 1. The ping-pong resynchronises on the
// next V2G frame; the V2G frames of those ~0.3 s are not caught.
//
//
// Passive test mode (diagnostic, off by default; qca7000-transparency plans/plan-alpitronic-abort.md, field
// matrix item 3): keeps the ping-pong disarmed by writing armed = 0 every 0.5 s. The firmware re-arms itself on
// the first frame after each of its restarts, hence the repetition. The sniffer then joins as usual (the key and
// NID pickup does not depend on armed) but never learns TEIs and never switches OWN_TEI: a joined, passive
// station that catches no V2G. Proof per session in the status block: teiA = teiB = 0, no TCP frames caught.
//
// The status block is a contract with the sniffer firmware (pyPLC AR7420 sniffer patch; source of truth:
// qca7000-transparency plans/interface-ardut-ebony.md): address 0x22c2a8, magic 'EBS1', layout 1, 64 bytes in
// v146 and 80 bytes from v147. Only fields below the block's size byte are used.

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
  bool hasRejected = false;            // size >= 0x44 (v147+)
  uint16_t rejectedMme = 0, lastRejectedMmtype = 0;
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

  // Passive test mode (see above)
  void setPassive(bool on);
  bool passive() const { return _passive; }
  bool passiveConfirmed() const { return _passiveOk; }        // the last armed = 0 write was read back as 0
  uint32_t passiveWrites() const { return _passiveWrites; }   // confirmed writes since switched on
  uint32_t passiveTimeouts() const { return _passiveTimeouts; }
  // The ping-pong learned TEIs in this join although passive (a write came too late): not a passive run
  bool passiveBreached() const { return _passive && _sbValid && (_sb.teiA || _sb.teiB || _sb.pending); }
  // Diagnostic: start the ping-pong in the middle of a session (serial "arm <charger> <car> <own>"). It
  // normally learns the TEIs at the SDP request, which is long past then, so the TEIs are written into its
  // control block (PPCB 0x22c4ec +0x10/+0x11/+0x12, v145..v147 layout, NOT part of the contract), then
  // armed = 1 and OWN_TEI = charger (the first flip: on its real TEI the sniffer never receives the unicast V2G
  // frames the ping-pong flips on). Switches the passive mode off.
  void armLive(uint8_t teiCharger, uint8_t teiCar, uint8_t teiOwn);
  // Diagnostic (plan matrix items 4/5): hold OWN_TEI at a fixed TEI (e.g. the car's or the charger's) with the
  // ping-pong disarmed, re-written every 0.5 s (serial "own <tei>"; "own 0" ends it). Implies passive mode.
  void holdOwnTei(uint8_t tei);
  uint8_t heldOwnTei() const { return _holdOwn; }

  // OWN_TEI consumer mask (contract section 6, v152+; refused on older builds). The firmware bakes all 41 sites to "real"; these flip
  // individual sites (or all) back to "follow" (the held/foreign TEI) for field bisection of the Alpitronic abort.
  // The override is a bit set (bit = "held follow"); it is re-applied after every modem restart.
  static constexpr uint8_t TEI_SITES = 41;
  void teiMaskSite(uint8_t site, bool follow);   // one site
  void teiMaskAll(bool follow);                  // all 41
  void teiMaskShow(Print &out) const;
  uint64_t teiMask() const { return _teiMask; }
  void resetModem();                             // VS_RS_DEV soft reset (seq restarts; triggers mask re-apply)

private:
  bool teiMaskAllowed() const;                   // build >= TEI_MASK_MIN_BUILD, else prints why and refuses
  static constexpr uint32_t QUERY_INTERVAL_MS = 1000;
  static constexpr uint32_t ALIVE_TIMEOUT_MS = 3500;
  static constexpr uint32_t FORGET_TIMEOUT_MS = 10000;  // re-learn the MAC (modem swapped/reset)
  static constexpr uint8_t TAG_REQUEST_TRIES = 5;
  static constexpr uint32_t BLOCK_INTERVAL_MS = 500;
  static constexpr uint32_t BLOCK_READ_TIMEOUT_MS = 300;    // per 16-byte read
  static constexpr uint32_t BLOCK_ADDR = 0x22c2a8;
  static constexpr uint8_t BLOCK_READS = 5;                 // 80 bytes
  static constexpr int BUILD_MIN = 146, BUILD_MAX = 199;    // contract range
  // v152+ only: before it, nat_own is not seeded in passive mode, so "real" sites would read TEI 0 (no association)
  static constexpr int TEI_MASK_MIN_BUILD = 152;
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

  enum class HoldWrite : uint8_t { None, Armed, OwnTei, Queued };
  static constexpr uint32_t ADDR_PPCB_TEIA = 0x22c4fc;  // PPCB +0x10 teiA, +0x11 teiB, +0x12 nat_own
  static constexpr uint32_t TEI_SLOT_REAL = 0x0022c4ea;   // slot value -> site reads nat_own (baked default)
  static constexpr uint32_t TEI_SLOT_FOLLOW = 0x0008bdd8;  // slot value -> site reads OWN_TEI (the override)
  static const uint32_t TEI_SLOT_ADDR[TEI_SITES];          // the 41 slot write addresses (local_modem.cpp)
  struct QueuedWrite { uint32_t addr; uint32_t value; uint8_t width; };
  QueuedWrite _queue[TEI_SITES + 8] = {};               // up to 41 mask writes, plus headroom for the live-arm queue
  uint8_t _queueLen = 0, _queuePos = 0, _queueTries = 0;
  uint64_t _teiMask = 0;     // bit i set = site i held "follow" (overriding the baked "real"); 0 = all real
  uint8_t _holdOwn = 0;      // 0 = not holding
  uint8_t _realOwn = 0;      // the sniffer's real TEI when the hold started
  bool _holdOwnTurn = false; // alternate armed = 0 and OWN_TEI writes
  bool _passive = false, _passiveOk = false;
  HoldWrite _holdWrite = HoldWrite::None;   // which passive write is outstanding
  uint32_t _lastPassiveMs = 0;
  uint32_t _passiveWrites = 0, _passiveTimeouts = 0;
};

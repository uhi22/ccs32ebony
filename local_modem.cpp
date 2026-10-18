#include "local_modem.h"

static void printMac(Print &out, const uint8_t *m) {
  out.printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void LocalModem::send(const uint8_t *frame, uint16_t len) {
  _eth.sendEthFrame(frame, len);
}

static void dumpFrame(const char *what, const uint8_t *frame, uint16_t len, uint16_t maxBytes) {
  uint16_t n = min(len, maxBytes);
  Serial.printf("Modem: first %s, %u bytes%s:", what, len, n < len ? " (start)" : "");
  for (uint16_t i = 0; i < n; i++) {
    Serial.printf("%s%02x", (i % 16 == 0) ? "\n  " : " ", frame[i]);
  }
  Serial.println();
}

static uint32_t le32(const uint8_t *p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }
static uint16_t le16(const uint8_t *p) { return p[0] | (p[1] << 8); }

void LocalModem::retag() {
  _blockState = BlockState::Off;
  _readPending = false;
  _firmware = Firmware::Unknown;
  _tagPending = false;
  _tagRequests = 0;
  _tag[0] = '\0';
  _tagDumped = false;
}

void LocalModem::forget() {
  _blockState = BlockState::Off;
  _readPending = false;
  _macKnown = false;
  _version[0] = '\0';
  _firmware = Firmware::Unknown;
  _tagPending = false;
  _tagRequests = 0;
  _tag[0] = '\0';
  _nwInfoValid = false;
}

void LocalModem::sendBlockRead() {
  uint8_t frame[homeplug::MIN_ETH_FRAME_LEN];
  send(frame, homeplug::composeSnifferReadReq(frame, _mac, _eth.ownMac(), BLOCK_ADDR + 16 * _readIndex));
  _readPending = true;
  _readSentMs = millis();
}

void LocalModem::decodeBlock() {
  _blockUpdated = true;
  uint32_t magic = le32(&_raw[0]);
  uint8_t layout = _raw[4], size = _raw[5];
  if (magic == 0) {
    _blockState = BlockState::NotRefreshed;  // first 100 ms after a modem firmware start
    return;
  }
  if (magic != 0x31534245 || layout != 1 || size < 80) {  // 'EBS1', v157+ (80 bytes)
    _blockState = BlockState::BadLayout;
    return;
  }
  const uint8_t *r = _raw;
  SnifferStatus n;
  n.size = size;
  n.build = le16(&r[0x06]);
  n.uptimeMs = le32(&r[0x08]);
  n.tJoin = le32(&r[0x0c]);
  n.tSdp = le32(&r[0x10]);
  n.tLearned = le32(&r[0x14]);
  n.tFirstResp = le32(&r[0x18]);
  n.ownTei = r[0x1c]; n.ccoTei = r[0x1d]; n.assoc = r[0x1e]; n.fsm = r[0x1f];
  n.teiA = r[0x20]; n.teiB = r[0x21]; n.natOwn = r[0x22]; n.cands = r[0x23];
  n.foundAtSdp = r[0x24]; n.missAtSdp = r[0x25]; n.foundByRetry = r[0x26]; n.pending = r[0x27];
  n.retryMisses = r[0x28]; n.clears = r[0x29]; n.nStations = r[0x2a]; n.maxTei = r[0x2b];
  n.tcpToCharger = le16(&r[0x2c]);
  n.tcpToCar = le16(&r[0x2e]);
  n.frames = le32(&r[0x30]);
  n.sdpReq = le16(&r[0x38]);
  n.sdpResp = le16(&r[0x3a]);
  n.seq = le32(&r[0x3c]);
  n.rejectedMme = le16(&r[0x40]);
  n.lastRejectedMmtype = le16(&r[0x42]);
  n.learnSrc = r[0x44]; n.c5Score = r[0x45]; n.firstFlips = r[0x46]; n.disarmFixes = r[0x47];
  n.sdpSeen = r[0x48]; n.relearns = r[0x49]; n.candAge = r[0x4a]; n.mode = r[0x4d];
  // seq counts 10 Hz since the modem's last firmware start: a drop means it restarted
  if (_sbValid && n.seq < _sb.seq) {
    _restarts++;
    _lastRestartUptimeMs = n.uptimeMs - n.seq * 100;
    Serial.printf("Modem: sniffer restarted (seq %lu -> %lu), at modem uptime %lu s\n",
                  (unsigned long)_sb.seq, (unsigned long)n.seq, (unsigned long)(_lastRestartUptimeMs / 1000));
    reapplyTeiMask();  // the restart reloaded the image = all sites back to the baked "real"; re-apply our follows
  }
  _sb = n;
  _sbValid = true;
  _blockState = BlockState::Valid;
  _blockReads++;
}

static const uint8_t MAC_BROADCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

void LocalModem::startVersionScan(uint32_t now) {
  if (_scanPhase != ScanPhase::Idle) {
    return;  // one at a time
  }
  _scanPhase = ScanPhase::Queued;  // starts when no status-block read is outstanding
  _scanStartMs = now ? now : 1;    // 0 means "never scanned"
  _lastScanAnswers = 0;            // the list itself accumulates
  _scanPaused = false;
  _resumeFailed = false;
  _versionUpdated = true;
}

void LocalModem::clearVersions() {
  _nVersions = 0;
  _versionsCleared = true;
  _versionUpdated = true;
}

void LocalModem::sendWrite(uint32_t addr, uint32_t value, uint8_t width, uint32_t now) {
  uint8_t frame[homeplug::MIN_ETH_FRAME_LEN];
  if (width == 4) {
    send(frame, homeplug::composeSnifferWriteReq32(frame, _mac, _eth.ownMac(), addr, value));
  } else {
    send(frame, homeplug::composeSnifferWriteReq(frame, _mac, _eth.ownMac(), addr, (uint8_t)value));
  }
  _writePending = true;
  _writeSentMs = now;
}

// The 41 OWN_TEI consumer slot WRITE addresses (contract section 6; ITCM slots at their run address).
// Generated/validated by tools/gen_owntei_mask_table.py; keep in sync with it.
const uint32_t LocalModem::TEI_SLOT_ADDR[LocalModem::TEI_SITES] = {
    0x217d54, 0x217ec4, 0x217f04,                                          // A MME TX header (0-2)
    0x2189a8, 0x219004, 0x2192b0,                                          // B beacon STEI (3-5)
    0x1e64,                                                                // C TX FC template, ITCM run (6)
    0x10a50, 0x10ba4, 0x12588,                                            // D MAC per-peer, ITCM run (7-9)
    0x22ce80, 0x237bc8,                                                    // E 0xA0DA reply (10-11)
    0x2400a0, 0x2406a4, 0x240a64, 0x240b10, 0x240ca4, 0x240da8,            // F PowerSave (12-17)
    0x23f0d4, 0x23f240, 0x23f434, 0x23f4d0, 0x23f540,                      // G Ethernet switch (18-22)
    0x21f1f0, 0x226c84, 0x22d678, 0x2418dc, 0x241b18, 0x241c08, 0x2456ac,  // H other compares (23-40)
    0x245b4c, 0x2562e4, 0x257018, 0x2573c0, 0x258778, 0x259a60, 0x259fa4,
    0x25a7d4, 0x25dc74, 0x25de0c, 0x25f014,
};

void LocalModem::queueMaskWrite(uint8_t site, bool follow) {
  if (site >= TEI_SITES || _queueLen >= sizeof(_queue) / sizeof(_queue[0])) {
    return;
  }
  _queue[_queueLen++] = {TEI_SLOT_ADDR[site], follow ? TEI_SLOT_FOLLOW : TEI_SLOT_REAL, 4};
}

bool LocalModem::teiMaskAllowed() const {
  int build = homeplug::snifferBuild(_tag);
  if (build >= BUILD_MIN && build <= BUILD_MAX) {
    return true;
  }
  Serial.printf("tei mask: needs sniffer build %d..%d (have %d), nothing written\n", BUILD_MIN, BUILD_MAX, build);
  return false;
}

void LocalModem::teiMaskSite(uint8_t site, bool follow) {
  if (!teiMaskAllowed()) {
    return;
  }
  if (site >= TEI_SITES) {
    Serial.printf("tei mask: site %u out of range (0..%u)\n", site, TEI_SITES - 1);
    return;
  }
  if (follow) {
    _teiMask |= (uint64_t)1 << site;
  } else {
    _teiMask &= ~((uint64_t)1 << site);
  }
  _queueLen = _queuePos = _queueTries = 0;
  queueMaskWrite(site, follow);
  Serial.printf("tei mask: site %u -> %s (mask now 0x%010llx)\n", site, follow ? "follow" : "real",
                (unsigned long long)_teiMask);
}

void LocalModem::teiMaskAll(bool follow) {
  if (!teiMaskAllowed()) {
    return;
  }
  _teiMask = follow ? (((uint64_t)1 << TEI_SITES) - 1) : 0;
  _queueLen = _queuePos = _queueTries = 0;
  for (uint8_t i = 0; i < TEI_SITES; i++) {
    queueMaskWrite(i, follow);
  }
  Serial.printf("tei mask: all 41 -> %s (queued %u writes)\n", follow ? "follow" : "real", _queueLen);
}

void LocalModem::reapplyTeiMask() {
  if (!_teiMask) {
    return;  // no override held; the baked all-real default is already in place after the restart
  }
  if (!teiMaskAllowed()) {
    return;
  }
  _queueLen = _queuePos = _queueTries = 0;
  for (uint8_t i = 0; i < TEI_SITES; i++) {
    if (_teiMask & ((uint64_t)1 << i)) {
      queueMaskWrite(i, true);
    }
  }
  Serial.printf("tei mask: re-applying %u held-follow site(s) after the restart\n", _queueLen);
}

void LocalModem::resetModem() {
  if (!_macKnown) {
    Serial.println("modemreset: modem MAC not known yet");
    return;
  }
  uint8_t frame[homeplug::MIN_ETH_FRAME_LEN];
  send(frame, homeplug::composeDeviceResetReq(frame, _mac, _eth.ownMac()));
  Serial.println("modemreset: VS_RS_DEV sent (modem reloads firmware; seq will restart)");
}

void LocalModem::teiMaskShow(Print &out) const {
  out.printf("OWN_TEI mask: 0x%010llx (bit set = held FOLLOW; 0 = all baked REAL). Firmware build %u.\n",
             (unsigned long long)_teiMask, _sbValid ? _sb.build : 0);
  static const char *grp[TEI_SITES] = {"A", "A", "A", "B", "B", "B", "C", "D", "D", "D", "E", "E",
                                       "F", "F", "F", "F", "F", "F", "G", "G", "G", "G", "G",
                                       "H", "H", "H", "H", "H", "H", "H", "H", "H", "H", "H", "H",
                                       "H", "H", "H", "H", "H", "H"};
  for (uint8_t i = 0; i < TEI_SITES; i++) {
    bool follow = _teiMask & ((uint64_t)1 << i);
    out.printf("  %2u %s 0x%06lx %s\n", i, grp[i], (unsigned long)TEI_SLOT_ADDR[i], follow ? "follow" : "real");
  }
}

void LocalModem::finishScan() {
  _scanPhase = ScanPhase::Idle;
  _versionUpdated = true;
  printVersions(Serial);
}

// Version scan state machine. Pausing needs a sniffer with a valid status block that is joined and
// knows its real TEI; otherwise the broadcast goes out without a pause.
void LocalModem::scanStep(uint32_t now) {
  uint8_t frame[homeplug::MIN_ETH_FRAME_LEN];
  switch (_scanPhase) {
    case ScanPhase::Queued: {
      if (_readPending || _writePending || _memPending) {
        return;
      }
      int build = homeplug::snifferBuild(_tag);
      bool canPause = _macKnown && _firmware == Firmware::Sniffer && build >= BUILD_MIN && build <= BUILD_MAX &&
                      _sbValid && _blockState == BlockState::Valid && _sb.assoc != 0x0f && _sb.natOwn != 0;
      if (canPause) {
        _scanPaused = true;
        _scanPhase = ScanPhase::Disarm;
        sendWrite(ADDR_ARMED, 0, now);
        Serial.println("Modem: version scan, ping-pong paused");
      } else {
        _scanPhase = ScanPhase::Collect;
        _collectStartMs = now;
        send(frame, homeplug::composeGetSwReq(frame, MAC_BROADCAST, _eth.ownMac()));
        Serial.println("Modem: version scan started (GET_SW broadcast, no pause)");
      }
      return;
    }
    case ScanPhase::Disarm:
    case ScanPhase::SetOwn:
      if (_writePending && now - _writeSentMs >= WRITE_TIMEOUT_MS) {
        _writePending = false;  // no confirmation: re-arm and stop (never leave the ping-pong paused)
        if (_mode == MODE_PASSIVE) {
          finishScan();         // passive: it stays paused on purpose
          return;
        }
        _scanPhase = ScanPhase::Rearm;
        _resumeTries = 1;
        sendWrite(ADDR_ARMED, _mode, now);   // back to the mode in use, not always ping-pong
      }
      return;
    case ScanPhase::Collect:
      if (now - _collectStartMs >= VERSION_SCAN_MS) {
        if (_scanPaused && _mode != MODE_PASSIVE) {
          _scanPhase = ScanPhase::Rearm;
          _resumeTries = 1;
          sendWrite(ADDR_ARMED, _mode, now);
        } else {
          finishScan();
        }
      }
      return;
    case ScanPhase::Rearm:
      if (_writePending && now - _writeSentMs >= WRITE_TIMEOUT_MS) {
        _writePending = false;
        if (_resumeTries < RESUME_TRIES) {
          _resumeTries++;
          sendWrite(ADDR_ARMED, _mode, now);
        } else {
          _resumeFailed = true;
          Serial.println("Modem: version scan, re-arming the ping-pong NOT confirmed");
          finishScan();
        }
      }
      return;
    default:
      return;
  }
}

void LocalModem::printVersions(Print &out) const {
  out.printf("Modem versions: %s, %u answer(s) in the last read, %u modem(s) in the list%s%s\n",
             versionScanRunning() ? "reading" : "done", _lastScanAnswers, _nVersions,
             _scanPaused ? ", ping-pong was paused" : "", _resumeFailed ? ", RE-ARM NOT CONFIRMED" : "");
  uint32_t now = millis();
  for (uint8_t i = 0; i < _nVersions; i++) {
    out.print("  ");
    printMac(out, _versions[i].mac);
    out.printf("%s %s (%lu s ago)\n", (_macKnown && memcmp(_versions[i].mac, _mac, 6) == 0) ? " (local)" : "",
               _versions[i].version, (unsigned long)((now - _versions[i].lastSeenMs) / 1000));
  }
}

const char *LocalModem::modeName(uint8_t m) {
  static const char *const N[] = {"passive", "pingpong", "car", "charger"};
  return m < 4 ? N[m] : "?";
}

int LocalModem::modeFromName(const char *name) {
  for (uint8_t m = 0; m < 4; m++) {
    if (strcmp(name, modeName(m)) == 0) {
      return m;
    }
  }
  return -1;
}

bool LocalModem::modeBreached() const {
  if (!_sbValid || _sb.natOwn == 0) {
    return false;
  }
  switch (_mode) {
    case MODE_PASSIVE: return _sb.ownTei != _sb.natOwn;
    case MODE_SELF_IS_CAR: return _sb.teiB && _sb.ownTei != _sb.teiB;
    case MODE_SELF_IS_CHARGER: return _sb.teiB && _sb.teiA && _sb.ownTei != _sb.teiA;
    default: return false;
  }
}

void LocalModem::setMode(uint8_t m) {
  if (m > MODE_SELF_IS_CHARGER) {
    return;
  }
  _mode = m;
  _modeOk = false;
  _modeWrites = 0;
  _modeTimeouts = 0;
  _lastPassiveMs = 0;  // modes 0/2/3: the next passiveStep writes at once
  if (m == MODE_PINGPONG && _macKnown && _firmware == Firmware::Sniffer && !_writePending && !_readPending &&
      !_memPending && _scanPhase == ScanPhase::Idle) {
    _holdWrite = HoldWrite::None;
    uint8_t frame[homeplug::MIN_ETH_FRAME_LEN];  // one write; the firmware makes the first flip within 100 ms
    send(frame, homeplug::composeSnifferWriteReq(frame, _mac, _eth.ownMac(), ADDR_ARMED, 1));
  }
  Serial.printf("Modem: sniffer mode %s\n", modeName(m));
}

// Modes 0/2/3: the mode byte is re-written every PASSIVE_INTERVAL_MS (the firmware re-inits it to 1 after each of
// its restarts). The firmware holds OWN_TEI per mode itself (v158).
void LocalModem::passiveStep(uint32_t now) {
  if (_holdWrite != HoldWrite::None) {
    if (now - _writeSentMs >= WRITE_TIMEOUT_MS) {
      _writePending = false;
      if (_holdWrite == HoldWrite::Queued && ++_queueTries >= RESUME_TRIES) {
        Serial.printf("Modem: queued write %u NOT confirmed, giving up\n", _queuePos);
        _queueLen = 0;
      }
      _holdWrite = HoldWrite::None;
      _modeOk = false;
      _modeTimeouts++;
    }
    return;
  }
  int build = homeplug::snifferBuild(_tag);
  if (_queuePos < _queueLen && !_readPending && !_writePending && !_memPending && _scanPhase == ScanPhase::Idle &&
      _macKnown && _firmware == Firmware::Sniffer && build >= BUILD_MIN && build <= BUILD_MAX) {
    _holdWrite = HoldWrite::Queued;
    sendWrite(_queue[_queuePos].addr, _queue[_queuePos].value, _queue[_queuePos].width, now);
    return;
  }
  if (_mode == MODE_PINGPONG || _readPending || _writePending || _memPending || _scanPhase != ScanPhase::Idle ||
      !_macKnown ||
      _firmware != Firmware::Sniffer || build < BUILD_MIN || build > BUILD_MAX ||
      now - _lastPassiveMs < PASSIVE_INTERVAL_MS) {
    return;
  }
  _lastPassiveMs = now;
  _holdWrite = HoldWrite::Armed;
  sendWrite(ADDR_ARMED, _mode, now);
}

// Confirmation of a passive or queued write; the reply carries the 16 bytes from the written address
bool LocalModem::passiveConfirm(const uint8_t *readBack) {
  HoldWrite w = _holdWrite;
  _holdWrite = HoldWrite::None;
  if (w == HoldWrite::Armed) {
    bool ok = readBack[0] == _mode;
    if (ok && !_modeOk) {
      Serial.printf("Modem: sniffer mode %s (confirmed)\n", modeName(_mode));
    }
    _modeOk = ok;
    _modeWrites++;
  } else if (w == HoldWrite::Queued) {
    Serial.printf("Modem: queued write 0x%06lx = 0x%lx w%u (read back 0x%02x)\n",
                  (unsigned long)_queue[_queuePos].addr, (unsigned long)_queue[_queuePos].value,
                  _queue[_queuePos].width, readBack[0]);
    _queueTries = 0;
    if (++_queuePos >= _queueLen) {
      Serial.println("Modem: queued writes done");
    }
  }
  return true;
}

// Raw memory access. Mapped ranges as bisected on the AR7420 844 (qca7000-transparency readme fact (z)).
bool LocalModem::memMapped(uint32_t addr, uint32_t len) {
  static const uint32_t RANGES[][2] = {{0x0, 0x20000}, {0x80000, 0xa0000}, {0x180000, 0x380000}};
  for (const auto &r : RANGES) {
    if (addr >= r[0] && len <= r[1] - r[0] && addr - r[0] <= r[1] - r[0] - len) {
      return true;
    }
  }
  return false;
}

bool LocalModem::memRead(uint32_t addr, uint16_t len) {
  uint32_t span = ((len + 15) / 16) * 16;     // RDM1 always returns 16 bytes
  if (_memActive || len == 0 || len > MEM_READ_MAX || !memMapped(addr, span)) {
    Serial.printf("rd: refused (%s); mapped: 0x0-0x1ffff, 0x80000-0x9ffff, 0x180000-0x37ffff, len 1..%u\n",
                  _memActive ? "busy" : "outside the mapped ranges or bad length", MEM_READ_MAX);
    return false;
  }
  _memActive = true; _memWrite = false; _memAddr = addr; _memLeft = len; _memTries = 0;
  return true;
}

bool LocalModem::memWrite(uint32_t addr, uint32_t value, uint8_t width) {
  if (_memActive || (width != 1 && width != 4) || !memMapped(addr, 16)) {
    Serial.printf("wr: refused (%s); width 1 or 4, mapped ranges as for rd\n",
                  _memActive ? "busy" : "outside the mapped ranges or bad width");
    return false;
  }
  _memActive = true; _memWrite = true; _memAddr = addr; _memValue = value; _memWidth = width; _memTries = 0;
  return true;
}

void LocalModem::memStep(uint32_t now) {
  if (!_memActive) {
    return;
  }
  if (_memPending) {
    if (now - _memSentMs >= WRITE_TIMEOUT_MS) {
      _memPending = false;
      if (++_memTries >= 3) {
        Serial.printf("%s 0x%06lx: no answer, stopped\n", _memWrite ? "wr" : "rd", (unsigned long)_memAddr);
        _memActive = false;
      }
    }
    return;
  }
  if (_readPending || _writePending || _scanPhase != ScanPhase::Idle || _holdWrite != HoldWrite::None ||
      !_macKnown || _firmware != Firmware::Sniffer) {
    return;  // replies carry no address: never overlap with another GET_SW request
  }
  uint8_t frame[homeplug::MIN_ETH_FRAME_LEN];
  if (!_memWrite) {
    send(frame, homeplug::composeSnifferReadReq(frame, _mac, _eth.ownMac(), _memAddr));
  } else if (_memWidth == 4) {
    send(frame, homeplug::composeSnifferWriteReq32(frame, _mac, _eth.ownMac(), _memAddr, _memValue));
  } else {
    send(frame, homeplug::composeSnifferWriteReq(frame, _mac, _eth.ownMac(), _memAddr, (uint8_t)_memValue));
  }
  _memPending = true;
  _memSentMs = now;
}

void LocalModem::memAnswer(const uint8_t *content) {
  _memPending = false;
  _memTries = 0;
  uint16_t n = _memWrite ? 16 : min<uint16_t>(_memLeft, 16);
  if (_memWrite) {
    Serial.printf("wr 0x%06lx = 0x%lx (%u byte%s), read back:", (unsigned long)_memAddr, (unsigned long)_memValue,
                  _memWidth, _memWidth == 1 ? "" : "s");
  } else {
    Serial.printf("rd 0x%06lx:", (unsigned long)_memAddr);
  }
  for (uint16_t i = 0; i < n; i++) {
    Serial.printf(" %02x", content[i]);
  }
  Serial.println();
  if (_memWrite) {
    _memActive = false;
    return;
  }
  _memAddr += 16;
  _memLeft -= n;
  if (_memLeft == 0) {
    _memActive = false;
  }
}

void LocalModem::cycle(uint32_t now) {
  if (_scanPhase != ScanPhase::Idle) {
    scanStep(now);
  }
  if (_eth.linkUp()) {
    passiveStep(now);
    memStep(now);
  }

  // Status block: its own pace, one "RDM1" request outstanding at a time
  if (_readPending && now - _readSentMs >= BLOCK_READ_TIMEOUT_MS) {
    _readPending = false;
    _blockTimeouts++;
    _blockState = BlockState::NoAnswer;
    _blockUpdated = true;
  }
  if (!_readPending && !_writePending && !_memPending && _scanPhase == ScanPhase::Idle && _eth.linkUp() &&
      _macKnown && _firmware == Firmware::Sniffer && now - _lastBlockStartMs >= BLOCK_INTERVAL_MS) {
    int build = homeplug::snifferBuild(_tag);
    if (build >= BUILD_MIN && build <= BUILD_MAX) {  // outside the contract range: read nothing
      _lastBlockStartMs = now;
      _readIndex = 0;
      if (_blockState == BlockState::Off) {
        _blockState = BlockState::Reading;
      }
      sendBlockRead();
    }
  }

  if (!_eth.linkUp() || now - _lastQueryMs < QUERY_INTERVAL_MS) {
    return;
  }
  _lastQueryMs = now;

  if (_macKnown && now - _lastAnswerMs >= FORGET_TIMEOUT_MS) {
    Serial.println("Modem: not answering, searching again");
    forget();
  }

  uint8_t frame[homeplug::MIN_ETH_FRAME_LEN];
  if (!_macKnown) {
    if (_scanPhase != ScanPhase::Idle) {
      return;  // remote modems answer the scan too: learn the local MAC only afterwards
    }
    send(frame, homeplug::composeGetSwReq(frame, homeplug::MAC_LOCAL_MANAGEMENT, _eth.ownMac()));
    return;
  }
  if (_firmware == Firmware::Unknown) {
    if (_tagRequests < TAG_REQUEST_TRIES) {
      _tagRequests++;
      _tagPending = true;
      send(frame, homeplug::composeSnifferTagReq(frame, _mac, _eth.ownMac()));
    } else {
      _tagPending = false;
      _firmware = Firmware::Stock;
      Serial.println("Modem: no answer to the sniffer tag request (stock firmware?)");
    }
  }
  send(frame, homeplug::composeVsNwInfoReq(frame, _mac, _eth.ownMac()));
}

bool LocalModem::handleFrame(const uint8_t *frame, uint16_t len, uint32_t now) {
  if (len < homeplug::MIN_ETH_FRAME_LEN || homeplug::etherType(frame) != homeplug::ETHERTYPE_HOMEPLUG ||
      memcmp(frame, _eth.ownMac(), 6) != 0) {
    return false;  // not addressed to us
  }
  // Version scan: confirmation of a "WRM1" write (pause / resume of the ping-pong)
  uint8_t wr[16];
  if (_writePending && _macKnown && memcmp(frame + 6, _mac, 6) == 0 && homeplug::parseSnifferCnf(frame, len, wr)) {
    _writePending = false;
    _lastAnswerMs = now;
    if (_holdWrite != HoldWrite::None) {
      return passiveConfirm(wr);
    }
    uint8_t frame2[homeplug::MIN_ETH_FRAME_LEN];
    if (_scanPhase == ScanPhase::Disarm) {
      _scanPhase = ScanPhase::SetOwn;
      sendWrite(ADDR_OWN_TEI, _sb.natOwn, now);
    } else if (_scanPhase == ScanPhase::SetOwn) {
      _scanPhase = ScanPhase::Collect;
      _collectStartMs = now;
      send(frame2, homeplug::composeGetSwReq(frame2, MAC_BROADCAST, _eth.ownMac()));
    } else if (_scanPhase == ScanPhase::Rearm) {
      finishScan();
    }
    return true;
  }

  // Version scan: answers from any modem in the network (they are unicast to us)
  if (_scanPhase == ScanPhase::Collect || _scanPhase == ScanPhase::Rearm) {
    homeplug::SoftwareVersion sw;
    if (homeplug::parseGetSwCnf(frame, len, sw)) {
      ModemVersion *e = nullptr;
      for (uint8_t i = 0; i < _nVersions; i++) {
        if (memcmp(_versions[i].mac, sw.mac, 6) == 0) {
          e = &_versions[i];
        }
      }
      bool isNew = false;
      if (e == nullptr && _nVersions < MAX_VERSIONS) {
        e = &_versions[_nVersions++];
        memcpy(e->mac, sw.mac, 6);
        isNew = true;
      }
      if (e != nullptr) {
        if (isNew || (int32_t)(e->lastSeenMs - _collectStartMs) < 0) {
          _lastScanAnswers++;  // first answer of this modem in this read
        }
        strlcpy(e->version, sw.version, sizeof(e->version));
        e->lastSeenMs = now;
      }
      if (_macKnown && memcmp(sw.mac, _mac, 6) == 0) {
        _lastAnswerMs = now;
      }
      return true;
    }
  }

  if (_macKnown && memcmp(frame + 6, _mac, 6) != 0) {
    return false;
  }

  uint8_t content[16];
  if (_macKnown && _memPending && homeplug::parseSnifferCnf(frame, len, content)) {
    _lastAnswerMs = now;
    memAnswer(content);
    return true;
  }
  if (_macKnown && _readPending && homeplug::parseSnifferCnf(frame, len, content)) {
    _lastAnswerMs = now;
    _readPending = false;
    memcpy(&_raw[16 * _readIndex], content, 16);
    if (++_readIndex < BLOCK_READS) {
      sendBlockRead();
    } else {
      decodeBlock();
    }
    return true;
  }

  char tag[17];
  if (_macKnown && _tagPending && homeplug::parseSnifferTagCnf(frame, len, tag)) {
    _lastAnswerMs = now;
    _tagPending = false;
    if (!_tagDumped) {
      _tagDumped = true;
      dumpFrame("tag answer", frame, len, 64);
    }
    if (homeplug::isSnifferTag(tag)) {
      _firmware = Firmware::Sniffer;
      strlcpy(_tag, tag, sizeof(_tag));
      Serial.printf("Modem: sniffer build tag %s\n", _tag);
    } else {
      _firmware = Firmware::Stock;
      Serial.printf("Modem: no sniffer tag (stock firmware?), answer \"%s\"\n", tag);
    }
    return true;
  }

  homeplug::SoftwareVersion sw;
  if (homeplug::parseGetSwCnf(frame, len, sw)) {
    _lastAnswerMs = now;
    if (!_macKnown) {
      _macKnown = true;
      memcpy(_mac, sw.mac, 6);
      strlcpy(_version, sw.version, sizeof(_version));
      Serial.print("Modem: ");
      printMac(Serial, _mac);
      Serial.printf(" version %s\n", _version);
    }
    return true;
  }

  homeplug::VsNetworkInfo info;
  if (_macKnown && homeplug::parseVsNwInfoCnf(frame, len, info)) {
    _lastAnswerMs = now;
    if (!_nwInfoDumped) {
      _nwInfoDumped = true;
      dumpFrame("VS_NW_INFO.CNF", frame, len, len);
    }
    bool wasJoined = joined();
    bool firstInfo = !_nwInfoValid;
    _nwInfo = info;
    _nwInfoValid = true;
    if (firstInfo || joined() != wasJoined) {
      if (joined()) {
        Serial.printf("Modem: joined, own TEI %u, role %u, CCo TEI %u, %u station(s)\n",
                      _nwInfo.ownTei, _nwInfo.role, _nwInfo.ccoTei, _nwInfo.numStations);
      } else {
        Serial.println("Modem: not joined");
      }
    }
    return true;
  }
  return false;
}

void LocalModem::printStatus(Print &out) const {
  uint32_t now = millis();
  if (!_macKnown) {
    out.println("Modem: unknown (no answer yet)");
    return;
  }
  out.print("Modem: ");
  printMac(out, _mac);
  out.printf(" %s, version %s, ", alive(now) ? "alive" : "NOT ANSWERING", _version);
  switch (_firmware) {
    case Firmware::Sniffer: out.printf("sniffer tag %s", _tag); break;
    case Firmware::Stock: out.print("no sniffer tag"); break;
    default: out.print("tag pending"); break;
  }
  if (!_nwInfoValid) {
    out.println(", network unknown");
  } else if (joined()) {
    out.printf(", joined, own TEI %u, CCo TEI %u", _nwInfo.ownTei, _nwInfo.ccoTei);
    for (uint8_t i = 0; i < _nwInfo.numStations; i++) {
      out.print(i == 0 ? ", stations " : " ");
      printMac(out, _nwInfo.stations[i].mac);
      out.printf("/%u", _nwInfo.stations[i].tei);
    }
    out.println();
  } else {
    out.println(", not joined");
  }
  printSniffer(out);
}

void LocalModem::printSniffer(Print &out) const {
  static const char *const STATE[] = {"off", "reading", "valid", "not refreshed yet", "unknown layout", "no answer"};
  out.printf("Sniffer status block: %s, %lu read, %lu timeouts, %lu modem restarts seen\n",
             STATE[(int)_blockState], (unsigned long)_blockReads, (unsigned long)_blockTimeouts,
             (unsigned long)_restarts);
  out.printf("  MODE %s%s, %lu re-writes, %lu timeouts%s (firmware reports %s)\n", modeName(_mode),
             _mode == MODE_PINGPONG ? "" : (_modeOk ? " (confirmed)" : " NOT confirmed"), (unsigned long)_modeWrites,
             (unsigned long)_modeTimeouts, modeBreached() ? ", OWN_TEI NOT as the mode wants right now" : "",
             _sbValid ? modeName(_sb.mode) : "-");
  if (!_sbValid) {
    return;
  }
  const SnifferStatus &b = _sb;
  out.printf("  build %u, size %u, modem uptime %lu s, %lu s since its last firmware start\n", b.build, b.size,
             (unsigned long)(b.uptimeMs / 1000), (unsigned long)(b.seq / 10));
  out.printf("  own %u, CCo %u, assoc 0x%02x, fsm %u; teiA %u teiB %u nat_own %u cands %u\n", b.ownTei, b.ccoTei,
             b.assoc, b.fsm, b.teiA, b.teiB, b.natOwn, b.cands);
  if (b.tJoin) {
    out.printf("  after join: SDP %ld ms, learned %ld ms, first response %ld ms (0 = not yet)\n",
               b.tSdp ? (long)(b.tSdp - b.tJoin) : 0L, b.tLearned ? (long)(b.tLearned - b.tJoin) : 0L,
               b.tFirstResp ? (long)(b.tFirstResp - b.tJoin) : 0L);
  }
  out.printf("  found %u miss %u retryOk %u pending %u retryMiss %u clears %u; stations %u max TEI %u\n",
             b.foundAtSdp, b.missAtSdp, b.foundByRetry, b.pending, b.retryMisses, b.clears, b.nStations, b.maxTei);
  out.printf("  frames %lu, TCP to charger %u / to car %u, SDP req %u resp %u", (unsigned long)b.frames,
             b.tcpToCharger, b.tcpToCar, b.sdpReq, b.sdpResp);
  out.printf(", rejected MMEs %u (last 0x%04X)\n", b.rejectedMme, b.lastRejectedMmtype);
  static const char *const SRC[] = {"none", "SDP request", "retry", "tick fallback"};
  out.printf("  learned by %s, SDP seen %u, candidate age %u ticks, first flips %u, disarm fixes %u, relearns %u\n",
             b.learnSrc < 4 ? SRC[b.learnSrc] : "?", b.sdpSeen, b.candAge, b.firstFlips, b.disarmFixes, b.relearns);
}

#include "session.h"

static const char *const PHASE_NAMES[Session::PH_COUNT] = {
    "SLAC", "join", "SDP", "handshake", "setup", "CableCheck", "PreCharge", "CurrentDemand", "stop"};

static constexpr uint16_t MMTYPE_SLAC_FIRST = 0x6064;  // SLAC_PARAM
static constexpr uint16_t MMTYPE_SLAC_LAST = 0x607F;   // up to SLAC_MATCH
static constexpr uint16_t MMTYPE_ATTEN_CHAR = 0x606C;
static constexpr uint16_t MMTYPE_SLAC_MATCH_CNF = 0x607D;
static constexpr uint32_t SLAC_RUN_GAP_MS = 5000;     // a SLAC_PARAM.REQ after this pause starts a new run
static constexpr uint32_t ENERGY_MAX_STEP_MS = 2000;  // longer gaps between samples are not integrated
static constexpr float CURRENT_FLOW_MIN_A = 0.5f;

static const char *sdpSecurity(uint8_t s) { return s == 0x00 ? "TLS" : s == 0x10 ? "none" : "?"; }
static const char *sdpTransport(uint8_t t) { return t == 0x00 ? "TCP" : t == 0x10 ? "UDP" : "?"; }

static uint8_t phaseOfMessage(const char *n) {
  if (strncmp(n, "SupportedAppProtocol", 20) == 0) return Session::PH_HANDSHAKE;
  if (strncmp(n, "CableCheck", 10) == 0) return Session::PH_CABLECHECK;
  if (strncmp(n, "PreCharge", 9) == 0) return Session::PH_PRECHARGE;
  if (strncmp(n, "CurrentDemand", 13) == 0) return Session::PH_CURRENTDEMAND;
  if (strncmp(n, "PowerDelivery", 13) == 0 || strncmp(n, "SessionStop", 11) == 0 ||
      strncmp(n, "WeldingDetection", 16) == 0) {
    return Session::PH_STOP;
  }
  return Session::PH_SETUP;
}

// PowerDelivery before the first CurrentDemand starts the charging, it does not stop it
static uint8_t phaseOf(const char *name, const uint32_t *phaseStart) {
  uint8_t ph = phaseOfMessage(name);
  if (ph == Session::PH_STOP && strncmp(name, "PowerDelivery", 13) == 0 &&
      phaseStart[Session::PH_CURRENTDEMAND] == 0) {
    return Session::PH_PRECHARGE;
  }
  return ph;
}

static bool endsWith(const char *s, const char *suffix) {
  size_t n = strlen(s), m = strlen(suffix);
  return n >= m && strcmp(s + n - m, suffix) == 0;
}

static void ipv6(JsonOut &j, const uint8_t *a) {
  j.raw("\"");
  for (uint8_t i = 0; i < 16; i += 2) {
    j.raw("%s%x", i ? ":" : "", (a[i] << 8) | a[i + 1]);
  }
  j.raw("\"");
}

const char *Session::bySeq(uint32_t seq) const {
  if (_ringCount == 0 || seq < oldestSeq() || seq > newestSeq()) return nullptr;
  return _ring[seq % REPLAY_LEN];
}

void Session::emit(const char *json) {
  strlcpy(_ring[_nextSeq % REPLAY_LEN], json, MESSAGE_LEN);
  _nextSeq++;
  if (_ringCount < REPLAY_LEN) _ringCount++;
  if (_sink != nullptr) _sink(json);
}

void Session::event(uint32_t now, const char *dir, const char *text) {
  char buf[MESSAGE_LEN];
  JsonOut j(buf, sizeof(buf));
  j.raw("{\"t\":\"event\",\"ms\":%lu,\"dir\":\"%s\",\"name\":", now, dir).str(text).raw("}");
  if (!j.truncated()) emit(buf);
}

void Session::begin(uint32_t now, bool late) {
  _s = Data();
  _s.id = ++_sessions;
  _s.startMs = now;
  _s.late = late;
  if (!late && _slacStartMs != 0) {
    _s.phases.start[PH_SLAC] = _slacStartMs;
    _s.phases.end[PH_SLAC] = now;
    _s.phases.current = PH_SLAC;
  }
  if (_hasPendingAtten) {
    _s.hasAtten = true;
    _s.atten = _pendingAtten;
  }
  // This SLAC run is used up: the next session measures its own
  _slacStartMs = 0;
  _hasPendingAtten = false;
  char buf[MESSAGE_LEN];
  JsonOut j(buf, sizeof(buf));
  // "slac": start of this session's SLAC run (0 = none). The SLAC messages before the match
  // belong to this session: the UI moves them over from the previous one.
  j.raw("{\"t\":\"begin\",\"ms\":%lu,\"id\":%lu,\"late\":%s,\"slac\":%lu}", now, _s.id,
        late ? "true" : "false", _s.phases.start[PH_SLAC]);
  emit(buf);
}

void Session::mark(uint8_t ph, uint32_t now) {
  if (ph >= PH_COUNT) return;
  if (_s.phases.start[ph] == 0) _s.phases.start[ph] = now;
  _s.phases.end[ph] = now;
  _s.phases.current = ph;
}

void Session::onHomeplug(const uint8_t *frame, uint16_t len, uint32_t now) {
  if (len < 17 || homeplug::etherType(frame) != homeplug::ETHERTYPE_HOMEPLUG) return;
  uint16_t mm = homeplug::mmtype(frame);
  uint16_t base = mm & ~0x0003;

  if (mm >= MMTYPE_SLAC_FIRST && mm <= MMTYPE_SLAC_LAST) {
    // The first SLAC message of a run, whatever it is: the sniffer can miss the car's first
    // SLAC_PARAM.REQ, so the run may start with a CNF (and the car's retried REQ follows)
    if (_slacStartMs == 0 || now - _slacLastMs > SLAC_RUN_GAP_MS) {
      _slacStartMs = now;
      _hasPendingAtten = false;
    }
    _slacLastMs = now;

    // REQ/IND come from the car, CNF/RSP from the charger - except ATTEN_CHAR, the other way round
    bool fromCar = (mm & 0x0003) == 0 || (mm & 0x0003) == 2;
    if (base == MMTYPE_ATTEN_CHAR) fromCar = !fromCar;
    char name[32];
    homeplug::describeMmtype(mm, name, sizeof(name));
    event(now, fromCar ? "car" : "charger", name);

    if (homeplug::parseAttenCharInd(frame, len, _pendingAtten)) {
      _hasPendingAtten = true;
      if (_s.id != 0) {
        _s.hasAtten = true;
        _s.atten = _pendingAtten;
      }
    }
    homeplug::SlacMatch match;
    if (mm == MMTYPE_SLAC_MATCH_CNF && homeplug::parseSlacMatchCnf(frame, len, match)) {
      begin(now, false);
      _s.hasMatch = true;
      _s.match = match;
    }
    return;
  }
  // Network forming after the match (key, association): the "join" phase, until SDP
  if (_s.id != 0 && !_s.late && mm < 0xA000 && _s.phases.start[PH_SDP] == 0) {
    mark(PH_JOIN, now);
  }
}

void Session::onSdpReq(uint8_t security, uint8_t transport, uint32_t now) {
  if (_s.id == 0) begin(now, true);
  _s.hasSdpReq = true;
  _s.reqSecurity = security;
  _s.reqTransport = transport;
  mark(PH_SDP, now);
  char text[40];
  snprintf(text, sizeof(text), "SDPReq %s %s", sdpSecurity(security), sdpTransport(transport));
  event(now, "car", text);
}

void Session::onSdpRes(const uint8_t ip[16], uint16_t port, uint8_t security, uint8_t transport,
                       uint32_t now) {
  if (_s.id == 0) begin(now, true);
  _s.hasSdpRes = true;
  memcpy(_s.evseIp, ip, 16);
  _s.evsePort = port;
  _s.resSecurity = security;
  _s.resTransport = transport;
  mark(PH_SDP, now);
  char text[40];
  snprintf(text, sizeof(text), "SDPRes %s %s port %u", sdpSecurity(security), sdpTransport(transport), port);
  event(now, "charger", text);
}

void Session::onV2g(const V2gValues &v, bool ok, uint32_t now) {
  bool isRes = endsWith(v.msgName, "Res");
  const char *dir = !ok ? "?" : isRes ? "charger" : "car";

  if (ok) {
    // No session yet, or a new handshake after this session got past it: we came in late
    bool newHandshake = v.appProtocolCount > 0 && _s.phases.start[PH_SETUP] != 0;
    if (_s.id == 0 || newHandshake) begin(now, true);

    mark(phaseOf(v.msgName, _s.phases.start), now);
    strlcpy(_s.lastMsg, v.msgName, sizeof(_s.lastMsg));
    _s.lastMsgMs = now;
    _s.hasRc = v.hasResponseCode;
    _s.rc = v.responseCode;
    if (v.hasTargetVoltage) { _s.targetU = v.targetVoltage; _s.targetUMs = now; }
    if (v.hasTargetCurrent) { _s.targetI = v.targetCurrent; _s.targetIMs = now; }
    if (v.hasPresentVoltage) { _s.presentU = v.presentVoltage; _s.presentUMs = now; }
    if (v.hasPresentCurrent) { _s.presentI = v.presentCurrent; _s.presentIMs = now; }
    if (v.hasSoc) { _s.soc = v.soc; _s.socMs = now; }

    if (v.appProtocolCount > 0) {
      _s.protocolCount = v.appProtocolCount;
      memcpy(_s.protocols, v.appProtocols, sizeof(_s.protocols));
    }
    if (v.hasHandshakeResult) {
      _s.hasHandshakeResult = true;
      _s.handshakeResult = v.handshakeResponseCode;
      _s.hasSchema = v.hasSelectedSchema;
      _s.schema = v.selectedSchemaId;
    }
    if (v.hasCpdReq) { _s.hasCpdReq = true; _s.cpdReq = v; }
    if (v.hasCpdRes) { _s.hasCpdRes = true; _s.cpdRes = v; }
    if (v.hasEvccid) {
      _s.hasEvccid = true;
      _s.evccidLen = v.evccidLen;
      memcpy(_s.evccid, v.evccid, v.evccidLen);
    }
    // The SessionID is all zeros in SessionSetupReq; keep the one the charger assigned
    if (v.hasSessionId && (isRes || !_s.hasSessionId)) {
      _s.hasSessionId = true;
      _s.sessionIdLen = v.sessionIdLen;
      memcpy(_s.sessionId, v.sessionId, v.sessionIdLen);
    }

    if (strcmp(v.msgName, "CurrentDemandRes") == 0 && v.hasPresentVoltage && v.hasPresentCurrent) {
      if (_s.lastSampleMs != 0 && now - _s.lastSampleMs <= ENERGY_MAX_STEP_MS) {
        float dt = (now - _s.lastSampleMs) / 1000.0f;
        float p = v.presentVoltage * v.presentCurrent;
        _s.energyWs += p * dt;
        _s.chargeAs += v.presentCurrent * dt;
        if (v.presentCurrent > CURRENT_FLOW_MIN_A) _s.flowMs += now - _s.lastSampleMs;
      }
      _s.lastSampleMs = now;
      _s.peakW = max(_s.peakW, v.presentVoltage * v.presentCurrent);
    }
  }

  char buf[MESSAGE_LEN];
  JsonOut j(buf, sizeof(buf));
  j.raw("{\"t\":\"msg\",\"ms\":%lu,\"dir\":\"%s\",\"ok\":%s,\"name\":", now, dir, ok ? "true" : "false");
  j.str(v.msgName);
  if (v.hasResponseCode) j.raw(",\"rc\":%u", v.responseCode);
  if (v.hasTargetVoltage) j.raw(",\"tU\":").num(v.targetVoltage);
  if (v.hasTargetCurrent) j.raw(",\"tI\":").num(v.targetCurrent);
  if (v.hasPresentVoltage) j.raw(",\"pU\":").num(v.presentVoltage);
  if (v.hasPresentCurrent) j.raw(",\"pI\":").num(v.presentCurrent);
  if (v.hasSoc) j.raw(",\"soc\":%d", v.soc);
  j.raw("}");
  if (!j.truncated()) emit(buf);
}

bool Session::snapshot(char *buf, size_t size, uint32_t now) const {
  JsonOut j(buf, size);
  const Data &s = _s;
  j.raw("{\"t\":\"session\",\"ms\":%lu,\"id\":%lu,\"start\":%lu,\"late\":%s", now, s.id, s.startMs,
        s.late ? "true" : "false");

  j.raw(",\"phases\":[");
  for (uint8_t i = 0; i < PH_COUNT; i++) {
    j.raw("%s{\"name\":\"%s\",\"start\":%lu,\"end\":%lu}", i ? "," : "", PHASE_NAMES[i],
          s.phases.start[i], s.phases.end[i]);
  }
  j.raw("],\"current\":%d", s.phases.current < PH_COUNT ? s.phases.current : -1);

  j.raw(",\"live\":{\"msg\":").str(s.lastMsg).raw(",\"msgMs\":%lu", s.lastMsgMs);
  if (s.hasRc) j.raw(",\"rc\":%u", s.rc);
  if (s.targetUMs) j.raw(",\"tU\":").num(s.targetU).raw(",\"tUMs\":%lu", s.targetUMs);
  if (s.targetIMs) j.raw(",\"tI\":").num(s.targetI).raw(",\"tIMs\":%lu", s.targetIMs);
  if (s.presentUMs) j.raw(",\"pU\":").num(s.presentU).raw(",\"pUMs\":%lu", s.presentUMs);
  if (s.presentIMs) j.raw(",\"pI\":").num(s.presentI).raw(",\"pIMs\":%lu", s.presentIMs);
  if (s.socMs) j.raw(",\"soc\":%d,\"socMs\":%lu", s.soc, s.socMs);
  j.raw("}");

  j.raw(",\"sdp\":{");
  if (s.hasSdpReq) {
    j.raw("\"req\":{\"sec\":\"%s\",\"tr\":\"%s\"}", sdpSecurity(s.reqSecurity), sdpTransport(s.reqTransport));
  }
  if (s.hasSdpRes) {
    j.raw("%s\"res\":{\"sec\":\"%s\",\"tr\":\"%s\",\"port\":%u,\"ip\":", s.hasSdpReq ? "," : "",
          sdpSecurity(s.resSecurity), sdpTransport(s.resTransport), s.evsePort);
    ipv6(j, s.evseIp);
    j.raw("}");
  }
  j.raw("}");

  j.raw(",\"hs\":{\"offered\":[");
  for (uint8_t i = 0; i < s.protocolCount; i++) {
    const V2gValues::AppProtocol &a = s.protocols[i];
    j.raw("%s{\"ns\":", i ? "," : "").str(a.ns);
    j.raw(",\"ver\":\"%u.%u\",\"id\":%u,\"prio\":%u}", a.versionMajor, a.versionMinor, a.schemaId, a.priority);
  }
  j.raw("]");
  if (s.hasHandshakeResult) j.raw(",\"result\":%u", s.handshakeResult);
  if (s.hasSchema) j.raw(",\"schema\":%u", s.schema);
  j.raw("}");

  j.raw(",\"cpd\":{");
  if (s.hasCpdReq) {
    const V2gValues &r = s.cpdReq;
    j.raw("\"req\":{\"mode\":%u,\"ready\":%s,\"err\":%u,\"soc\":%d", r.energyTransferMode,
          r.evReady ? "true" : "false", r.evErrorCode, r.cpdSoc);
    if (r.hasEvLimits) j.raw(",\"maxU\":").num(r.evMaxVoltage).raw(",\"maxI\":").num(r.evMaxCurrent);
    if (r.hasFullSoc) j.raw(",\"fullSoc\":%d", r.fullSoc);
    if (r.hasBulkSoc) j.raw(",\"bulkSoc\":%d", r.bulkSoc);
    j.raw("}");
  }
  if (s.hasCpdRes) {
    const V2gValues &r = s.cpdRes;
    j.raw("%s\"res\":{\"rc\":%u,\"processing\":%u", s.hasCpdReq ? "," : "", r.responseCode, r.evseProcessing);
    if (r.hasEvseLimits) {
      j.raw(",\"maxU\":").num(r.evseMaxVoltage).raw(",\"maxI\":").num(r.evseMaxCurrent);
      j.raw(",\"minU\":").num(r.evseMinVoltage).raw(",\"minI\":").num(r.evseMinCurrent);
    }
    if (r.hasEvseMaxPower) j.raw(",\"maxP\":%.0f", r.evseMaxPower);
    j.raw("}");
  }
  j.raw("}");

  j.raw(",\"ident\":{");
  bool first = true;
  if (s.hasEvccid) { j.raw("\"evccid\":").hex(s.evccid, s.evccidLen); first = false; }
  if (s.hasSessionId) { j.raw("%s\"sessionId\":", first ? "" : ",").hex(s.sessionId, s.sessionIdLen); first = false; }
  if (s.hasMatch) {
    j.raw("%s\"pevMac\":", first ? "" : ",").mac(s.match.pevMac);
    j.raw(",\"evseMac\":").mac(s.match.evseMac);
    j.raw(",\"nid\":").hex(s.match.nid, sizeof(s.match.nid));
    j.raw(",\"nmk\":").hex(s.match.nmk, sizeof(s.match.nmk));
  }
  j.raw("}");

  j.raw(",\"energy\":{\"wh\":%.2f,\"ah\":%.2f,\"peakW\":%.0f,\"flowS\":%lu}", s.energyWs / 3600.0,
        s.chargeAs / 3600.0, s.peakW, s.flowMs / 1000);

  if (s.hasAtten) {
    j.raw(",\"atten\":{\"sounds\":%u,\"groups\":[", s.atten.numSounds);
    for (uint8_t i = 0; i < s.atten.numGroups; i++) j.raw("%s%u", i ? "," : "", s.atten.attenuation[i]);
    j.raw("]}");
  }
  j.raw("}");
  return !j.truncated();
}

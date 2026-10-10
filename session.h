// The charging session as the UI shows it: phases, live values, the static data negotiated at
// the start (SDP, schemas, charge parameters, identity), energy, SLAC attenuation.
//
// The decoders feed it; it produces two kinds of WebSocket messages (docs/web-ui.md):
//   - "session": the whole current state, idempotent (sent once per second and on connect)
//   - "msg" / "event": one decoded V2G message / one SLAC, SDP or session event, sent at once.
//     The last REPLAY_LEN of them are kept, so a tablet that connects mid-session still gets
//     the recent history for its ladder and log.
// The phase model follows ccs32dave.

#pragma once

#include <Arduino.h>

#include "homeplug.h"
#include "json_out.h"
#include "v2g_exi.h"

class Session {
public:
  enum Phase : uint8_t {
    PH_SLAC, PH_JOIN, PH_SDP, PH_HANDSHAKE, PH_SETUP, PH_CABLECHECK, PH_PRECHARGE,
    PH_CURRENTDEMAND, PH_STOP, PH_COUNT
  };
  static constexpr uint8_t REPLAY_LEN = 100;
  static constexpr uint16_t MESSAGE_LEN = 224;  // longest msg/event JSON

  // Receives each new msg/event JSON (to broadcast it)
  using Sink = void (*)(const char *json);
  void onMessage(Sink sink) { _sink = sink; }

  void onHomeplug(const uint8_t *frame, uint16_t len, uint32_t now);
  void onSdpReq(uint8_t security, uint8_t transport, uint32_t now);
  void onSdpRes(const uint8_t ip[16], uint16_t port, uint8_t security, uint8_t transport, uint32_t now);
  void onV2g(const V2gValues &v, bool ok, uint32_t now);

  // The "session" message. Returns false if buf was too small.
  bool snapshot(char *buf, size_t size, uint32_t now) const;

  // Recent msg/event messages by sequence number (1, 2, ... since boot). A new viewer is fed
  // from oldestSeq() to newestSeq() at its own pace; bySeq() returns nullptr once a message was
  // overwritten in the ring. newestSeq() 0: no message yet.
  uint32_t newestSeq() const { return _nextSeq - 1; }
  uint32_t oldestSeq() const { return _nextSeq - _ringCount; }
  const char *bySeq(uint32_t seq) const;

private:
  struct Phases {
    uint32_t start[PH_COUNT] = {};  // 0 = not reached
    uint32_t end[PH_COUNT] = {};
    uint8_t current = PH_COUNT;     // PH_COUNT = nothing yet
  };

  struct Data {
    uint32_t id = 0;       // counts sessions since boot; 0 = none yet
    uint32_t startMs = 0;
    bool late = false;     // started from a V2G message: the board came in mid-session
    Phases phases;

    // Live values with the time they were last seen
    char lastMsg[28] = "";
    uint32_t lastMsgMs = 0;
    bool hasRc = false;
    uint8_t rc = 0;
    float targetU = 0, targetI = 0, presentU = 0, presentI = 0;
    uint32_t targetUMs = 0, targetIMs = 0, presentUMs = 0, presentIMs = 0;
    int8_t soc = 0;
    uint32_t socMs = 0;

    // SDP
    bool hasSdpReq = false, hasSdpRes = false;
    uint8_t reqSecurity = 0, reqTransport = 0, resSecurity = 0, resTransport = 0;
    uint8_t evseIp[16] = {};
    uint16_t evsePort = 0;

    // App handshake
    uint8_t protocolCount = 0;
    V2gValues::AppProtocol protocols[V2gValues::MAX_APP_PROTOCOLS];
    bool hasHandshakeResult = false;
    uint8_t handshakeResult = 0;
    bool hasSchema = false;
    uint8_t schema = 0;

    // ChargeParameterDiscovery (the last one of each direction)
    bool hasCpdReq = false, hasCpdRes = false;
    V2gValues cpdReq, cpdRes;

    // Identity
    bool hasEvccid = false;
    uint8_t evccid[6] = {};
    uint8_t evccidLen = 0;
    bool hasSessionId = false;
    uint8_t sessionId[8] = {};
    uint8_t sessionIdLen = 0;
    bool hasMatch = false;
    homeplug::SlacMatch match;

    // Energy, integrated over the present values of CurrentDemandRes
    double energyWs = 0, chargeAs = 0;
    float peakW = 0;
    uint32_t flowMs = 0;        // time with current flowing (> 0.5 A)
    uint32_t lastSampleMs = 0;

    bool hasAtten = false;
    homeplug::AttenProfile atten;
  };

  void begin(uint32_t now, bool late);
  void mark(uint8_t ph, uint32_t now);
  void emit(const char *json);
  void event(uint32_t now, const char *dir, const char *text);

  Data _s;
  uint32_t _sessions = 0;

  // SLAC happens before the match that opens a session: kept aside and copied in by begin()
  uint32_t _slacStartMs = 0, _slacLastMs = 0;
  bool _hasPendingAtten = false;
  homeplug::AttenProfile _pendingAtten;

  Sink _sink = nullptr;
  char _ring[REPLAY_LEN][MESSAGE_LEN];  // message with sequence number s is at s % REPLAY_LEN
  uint32_t _nextSeq = 1;
  uint8_t _ringCount = 0;
};

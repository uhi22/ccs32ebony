// Passive TCP reassembly + V2GTP framing, for the two IPv6/TCP peers of one V2G session
// (ported from github.com/uhi22/ccs32dave). No TCP stack: this only reconstructs the byte stream well enough to find
// V2GTP messages (ISO 15118 / DIN 70121 transport: 8-byte header + EXI payload) in each
// direction, using the sequence number to detect duplicates/retransmits and a resync on gaps.
//
// Up to MAX_PEERS source MACs are tracked at once (normally 2: the PEV host and the EVSE
// host). Each peer gets its own reassembly buffer and expected-sequence-number state,
// independent of the others - so this doesn't need to know in advance which MAC is which.
//
// A gap (missing segment - ping-pong or the ESP32's own poll loop can drop frames) can't be
// recovered: the byte stream has a hole. Instead of guessing, this drops the partial message
// and resyncs by scanning forward for the next V2GTP header magic 01 FE (see resync()).
#pragma once

#include <Arduino.h>

class V2gtpReassembler {
public:
  static constexpr uint8_t MAX_PEERS = 4;
  static constexpr uint16_t BUF_LEN = 2048;  // largest DIN message is well under this

  // Called for each TCP segment carrying `payloadLen` bytes of `payload` (may be 0), with
  // srcMac (6 bytes) and the segment's starting sequence number. Returns true and fills
  // `out`/`outLen` if a complete V2GTP message (header + EXI payload) is now available -
  // `out` points into an internal buffer valid until the next call for the same peer.
  bool feed(const uint8_t srcMac[6], uint32_t seq, const uint8_t *payload, uint16_t payloadLen,
            const uint8_t **out, uint16_t *outLen);

  // Diagnostics, reset when read
  uint32_t gaps() const { return _gaps; }
  uint32_t resyncs() const { return _resyncs; }

private:
  struct Peer {
    bool used = false;
    uint8_t mac[6] = {0};
    bool haveSeq = false;
    uint32_t expectedSeq = 0;
    uint16_t haveBytes = 0;      // bytes currently in buf (header once >=8, then payload)
    uint32_t wantLen = 0;        // total message length once the header is parsed (8 + declared)
    uint8_t buf[BUF_LEN];
  };

  Peer _peers[MAX_PEERS];
  uint32_t _gaps = 0;
  uint32_t _resyncs = 0;

  Peer *findOrAlloc(const uint8_t mac[6]);
  static bool tryParseHeader(const uint8_t *buf, uint16_t haveBytes, uint32_t *wantLen);
  // Scans buf[0..haveBytes) for a plausible V2GTP header start (01 FE) and compacts the
  // buffer to start there. Returns the number of bytes dropped.
  static uint16_t resyncBuffer(uint8_t *buf, uint16_t haveBytes);
};

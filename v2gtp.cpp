#include "v2gtp.h"

V2gtpReassembler::Peer *V2gtpReassembler::findOrAlloc(const uint8_t mac[6]) {
  Peer *free = nullptr;
  for (auto &p : _peers) {
    if (p.used && memcmp(p.mac, mac, 6) == 0) {
      return &p;
    }
    if (!p.used && !free) {
      free = &p;
    }
  }
  if (free) {
    free->used = true;
    memcpy(free->mac, mac, 6);
    free->haveSeq = false;
    free->haveBytes = 0;
    free->wantLen = 0;
  }
  return free;  // nullptr if the table is full - caller just stops tracking that peer
}

bool V2gtpReassembler::tryParseHeader(const uint8_t *buf, uint16_t haveBytes, uint32_t *wantLen) {
  if (haveBytes < 8) {
    return false;
  }
  if (buf[0] != 0x01 || buf[1] != 0xFE) {
    return false;
  }
  uint32_t payloadLen = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                        ((uint32_t)buf[6] << 8) | buf[7];
  *wantLen = 8 + payloadLen;
  return true;
}

uint16_t V2gtpReassembler::resyncBuffer(uint8_t *buf, uint16_t haveBytes) {
  for (uint16_t i = 0; i + 1 < haveBytes; i++) {
    if (buf[i] == 0x01 && buf[i + 1] == 0xFE) {
      uint16_t remaining = haveBytes - i;
      if (i > 0) {
        memmove(buf, buf + i, remaining);
      }
      return remaining;  // bytes now at the front of buf, starting at the header candidate
    }
  }
  // No candidate header start anywhere in the buffer: discard it all, except a trailing lone
  // 0x01 that could be the first byte of a header split across this segment and the next.
  if (haveBytes > 0 && buf[haveBytes - 1] == 0x01) {
    buf[0] = buf[haveBytes - 1];
    return 1;
  }
  return 0;
}

bool V2gtpReassembler::feed(const uint8_t srcMac[6], uint32_t seq, const uint8_t *payload,
                           uint16_t payloadLen, const uint8_t **out, uint16_t *outLen) {
  if (payloadLen == 0) {
    return false;  // bare ACK: nothing to reassemble
  }
  Peer *p = findOrAlloc(srcMac);
  if (!p) {
    return false;  // peer table full (shouldn't happen with 2 real peers + margin)
  }

  if (!p->haveSeq) {
    p->expectedSeq = seq;
    p->haveSeq = true;
  }
  if (seq != p->expectedSeq) {
    // Gap (seq ahead) or a retransmit/overlap (seq behind): either way the running
    // reassembly can't be trusted. Drop it and resync on the next header we can find,
    // including in the bytes we just received.
    _gaps++;
    p->haveBytes = 0;
    p->wantLen = 0;
    p->expectedSeq = seq;  // resume tracking from what we actually received
  }
  p->expectedSeq = seq + payloadLen;

  uint16_t room = BUF_LEN - p->haveBytes;
  uint16_t take = payloadLen < room ? payloadLen : room;
  memcpy(p->buf + p->haveBytes, payload, take);
  p->haveBytes += take;
  if (take < payloadLen) {
    // Buffer overrun (implausibly large message): give up on this one, resync.
    p->haveBytes = resyncBuffer(p->buf, p->haveBytes);
    _resyncs++;
    return false;
  }

  if (p->wantLen == 0) {
    if (!tryParseHeader(p->buf, p->haveBytes, &p->wantLen)) {
      if (p->haveBytes >= 2) {
        uint16_t before = p->haveBytes;
        p->haveBytes = resyncBuffer(p->buf, p->haveBytes);
        if (p->haveBytes != before) {
          _resyncs++;
        }
        if (p->haveBytes > BUF_LEN - 8) {
          p->haveBytes = 0;  // pathological: no header anywhere in a full buffer
        }
      }
      return false;
    }
    if (p->wantLen > BUF_LEN) {
      // Declared length larger than we can buffer - not a real DIN/appHand message on this
      // link (or we're still misaligned). Drop and resync past the bogus header.
      p->haveBytes = resyncBuffer(p->buf + 1, p->haveBytes - 1) + 1;
      p->wantLen = 0;
      _resyncs++;
      return false;
    }
  }

  if (p->haveBytes < p->wantLen) {
    return false;  // message still incomplete
  }

  *out = p->buf;
  *outLen = (uint16_t)p->wantLen;
  // In every session observed so far, one TCP segment carries exactly one V2GTP message
  // (matches "pl == v2g header + payload" in the serial log), so coalescing is not handled:
  // any leftover bytes (would-be second message in the same segment) are dropped. `*out`
  // stays valid - and must be consumed - only until the next feed() for this same peer.
  p->haveBytes = 0;
  p->wantLen = 0;
  return true;
}

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

void LocalModem::retag() {
  _firmware = Firmware::Unknown;
  _tagPending = false;
  _tagRequests = 0;
  _tag[0] = '\0';
  _tagDumped = false;
}

void LocalModem::forget() {
  _macKnown = false;
  _version[0] = '\0';
  _firmware = Firmware::Unknown;
  _tagPending = false;
  _tagRequests = 0;
  _tag[0] = '\0';
  _nwInfoValid = false;
}

void LocalModem::cycle(uint32_t now) {
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
  if (_macKnown && memcmp(frame + 6, _mac, 6) != 0) {
    return false;
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
}

// State of the local powerline modem (the sniffer on our Ethernet port), learned by queries that
// only this modem answers:
//   1. GET_SW.REQ to the local management address -> the modem's MAC and version string
//   2. GET_SW.REQ "GST1" to that MAC             -> sniffer build tag, or none (stock firmware)
//   3. VS_NW_INFO.REQ to that MAC, every second    -> alive, joined / not joined
// Nothing is broadcast, so the queries never reach the powerline session.

#pragma once

#include <Arduino.h>

#include "eth_sniff.h"
#include "homeplug.h"

class LocalModem {
public:
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

private:
  static constexpr uint32_t QUERY_INTERVAL_MS = 1000;
  static constexpr uint32_t ALIVE_TIMEOUT_MS = 3500;
  static constexpr uint32_t FORGET_TIMEOUT_MS = 10000;  // re-learn the MAC (modem swapped/reset)
  static constexpr uint8_t TAG_REQUEST_TRIES = 5;

  void send(const uint8_t *frame, uint16_t len);
  void forget();

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
};

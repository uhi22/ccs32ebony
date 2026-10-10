// Decodes one complete V2GTP-EXI payload (DIN 70121, plus the app-handshake that precedes it)
// into the fields the UI shows. Ported from github.com/uhi22/ccs32dave. Wraps the OpenV2G decoder
// in src/exi/ (ported from github.com/uhi22/ccs32berta, decoder-only - see that project's
// GNU LGPL-licensed source for the codec itself).
#pragma once

#include <Arduino.h>

struct V2gValues {
  char msgName[28] = "";  // e.g. "CurrentDemandReq", or an error tag on failure

  bool hasTargetVoltage = false, hasTargetCurrent = false;
  float targetVoltage = 0, targetCurrent = 0;  // from CurrentDemandReq (EVTarget*)

  bool hasPresentVoltage = false, hasPresentCurrent = false;
  float presentVoltage = 0, presentCurrent = 0;  // from CurrentDemandRes (EVSEPresent*)

  bool hasSoc = false;
  int8_t soc = 0;  // DC_EVStatus.EVRESSSOC, percent - reported by the EV in its DC requests

  bool hasResponseCode = false;
  uint8_t responseCode = 0;  // dinresponseCodeType - 0 = OK, see dinEXIDatatypes.h

  // ChargeParameterDiscovery. Req carries the limits the car asks for,
  // Res the ones the charger offers. DC only - the DIN AC parameter sets aren't decoded here.
  bool hasCpdReq = false;           // this was a ChargeParameterDiscoveryReq
  uint8_t energyTransferMode = 0;   // dinEVRequestedEnergyTransferType, e.g. DC_extended
  bool hasEvLimits = false;         // its DC_EVChargeParameter was present (DC session)
  float evMaxVoltage = 0, evMaxCurrent = 0;  // EVMaximum*Limit, mandatory inside it
  bool hasFullSoc = false, hasBulkSoc = false;  // both optional in DIN, often omitted
  int8_t fullSoc = 0, bulkSoc = 0;
  bool evReady = false;             // DC_EVStatus of the request
  uint8_t evErrorCode = 0;          // dinDC_EVErrorCodeType - 0 = NO_ERROR
  int8_t cpdSoc = 0;                // DC_EVStatus.EVRESSSOC at discovery time

  bool hasCpdRes = false;           // this was a ChargeParameterDiscoveryRes
  uint8_t evseProcessing = 0;       // dinEVSEProcessingType - 0 = Finished, 1 = Ongoing
  bool hasEvseLimits = false;       // its DC_EVSEChargeParameter was present (left out while
                                    // the charger is still "Ongoing")
  float evseMaxVoltage = 0, evseMaxCurrent = 0;
  float evseMinVoltage = 0, evseMinCurrent = 0;
  bool hasEvseMaxPower = false;     // EVSEMaximumPowerLimit is optional in DIN
  float evseMaxPower = 0;           // W

  // Session identity. The SessionID comes from the message header of
  // every DIN message - all zeroes in SessionSetupReq, assigned by the charger afterwards.
  bool hasSessionId = false;
  uint8_t sessionId[8] = {};
  uint8_t sessionIdLen = 0;
  bool hasEvccid = false;        // SessionSetupReq - the car's MAC
  uint8_t evccid[6] = {};
  uint8_t evccidLen = 0;

  // App handshake. The decoder keeps at most 5 offered protocols.
  struct AppProtocol {
    char ns[48];  // e.g. "urn:din:70121:2012:MsgDef" (truncated if longer)
    uint8_t versionMajor, versionMinor, schemaId, priority;
  };
  static constexpr uint8_t MAX_APP_PROTOCOLS = 5;
  uint8_t appProtocolCount = 0;  // > 0: this was a supportedAppProtocolReq
  AppProtocol appProtocols[MAX_APP_PROTOCOLS];
  bool hasHandshakeResult = false;  // this was a supportedAppProtocolRes
  uint8_t handshakeResponseCode = 0;  // 0 OK, 1 OK with minor deviation, 2 failed
  bool hasSelectedSchema = false;
  uint8_t selectedSchemaId = 0;
};

// `data`/`len` is the EXI payload only (the V2GTP message minus its 8-byte header). Returns
// true and fills `out` for a recognized DIN body message or the app-handshake; false (with
// out.msgName set to a short error tag, e.g. "DIN err -110") otherwise - a wrong guess at the
// message boundary (see V2gtpReassembler) typically shows up here as a decode error.
bool decodeV2gExiPayload(const uint8_t *data, uint16_t len, V2gValues &out);

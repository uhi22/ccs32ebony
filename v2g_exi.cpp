#include "v2g_exi.h"
#include <math.h>

#include "src/exi/EXITypes.h"
#include "src/exi/dinEXIDatatypesDecoder.h"
#include "src/exi/appHandEXIDatatypesDecoder.h"

// Single shared decode targets (matches the upstream OpenV2G pattern: the generated decoder
// is not reentrant - one document in flight at a time, which is exactly the passive-listener
// case here). Static, not stack: dinEXIDocument alone is ~28 KB (measured via host gcc
// sizeof), trivial against the ESP32-S3's several hundred KB of free SRAM but too much to put
// on a task stack.
static struct dinEXIDocument s_dinDoc;
static struct appHandEXIDocument s_aphsDoc;

// The decoder calls this on a handful of "shouldn't happen" internal branches (upstream:
// src/exi/projectExiConnector.c in ccs32berta, not copied here since it's otherwise
// encoder-heavy) - just a debug hook, no-op is what upstream itself does by default.
extern "C" void debugAddStringAndInt(char *s, int i) {
  (void)s;
  (void)i;
}

static float physicalValue(const struct dinPhysicalValueType &v) {
  return (float)v.Value * powf(10.0f, (float)v.Multiplier);
}

// One `if (body.NAME_isUsed) { ... return true; }` per DIN body message, in declaration order
// of struct dinBodyType (dinEXIDatatypes.h). Most just set the message name; CurrentDemandReq/
// Res additionally pull the fields the UI shows.
#define NAMED(NAME)                                                     \
  if (body.NAME##_isUsed) {                                            \
    strlcpy(out.msgName, #NAME, sizeof(out.msgName));                  \
    return true;                                                       \
  }

static bool extractDinBody(const struct dinBodyType &body, V2gValues &out) {
  if (body.SessionSetupReq_isUsed) {
    strlcpy(out.msgName, "SessionSetupReq", sizeof(out.msgName));
    // The EVCCID is the car's MAC - the only place the session names the car.
    const auto &id = body.SessionSetupReq.EVCCID;
    out.evccidLen = id.bytesLen > sizeof(out.evccid) ? sizeof(out.evccid) : (uint8_t)id.bytesLen;
    memcpy(out.evccid, id.bytes, out.evccidLen);
    out.hasEvccid = out.evccidLen > 0;
    return true;
  }
  if (body.SessionSetupRes_isUsed) {
    strlcpy(out.msgName, "SessionSetupRes", sizeof(out.msgName));
    out.hasResponseCode = true;
    out.responseCode = (uint8_t)body.SessionSetupRes.ResponseCode;
    return true;
  }
  NAMED(ServiceDiscoveryReq)
  NAMED(ServiceDiscoveryRes)
  NAMED(ServiceDetailReq)
  NAMED(ServiceDetailRes)
  NAMED(ServicePaymentSelectionReq)
  NAMED(ServicePaymentSelectionRes)
  NAMED(PaymentDetailsReq)
  NAMED(PaymentDetailsRes)
  NAMED(ContractAuthenticationReq)
  NAMED(ContractAuthenticationRes)
  if (body.ChargeParameterDiscoveryReq_isUsed) {
    // The car's own limits.
    strlcpy(out.msgName, "ChargeParameterDiscoveryReq", sizeof(out.msgName));
    const struct dinChargeParameterDiscoveryReqType &r = body.ChargeParameterDiscoveryReq;
    out.hasCpdReq = true;
    out.energyTransferMode = (uint8_t)r.EVRequestedEnergyTransferType;
    if (r.DC_EVChargeParameter_isUsed) {
      const struct dinDC_EVChargeParameterType &p = r.DC_EVChargeParameter;
      out.hasEvLimits = true;
      out.evMaxVoltage = physicalValue(p.EVMaximumVoltageLimit);
      out.evMaxCurrent = physicalValue(p.EVMaximumCurrentLimit);
      out.hasFullSoc = p.FullSOC_isUsed;
      out.fullSoc = p.FullSOC;
      out.hasBulkSoc = p.BulkSOC_isUsed;
      out.bulkSoc = p.BulkSOC;
      out.evReady = p.DC_EVStatus.EVReady != 0;
      out.evErrorCode = (uint8_t)p.DC_EVStatus.EVErrorCode;
      out.cpdSoc = p.DC_EVStatus.EVRESSSOC;
      out.hasSoc = true;  // the main page's SoC is fed by every DC message that carries one
      out.soc = p.DC_EVStatus.EVRESSSOC;
    }
    return true;
  }
  if (body.ChargeParameterDiscoveryRes_isUsed) {
    // The charger's limits. While EVSEProcessing is "Ongoing" the charge
    // parameter block may be missing entirely - then only the processing state is shown.
    strlcpy(out.msgName, "ChargeParameterDiscoveryRes", sizeof(out.msgName));
    const struct dinChargeParameterDiscoveryResType &r = body.ChargeParameterDiscoveryRes;
    out.hasResponseCode = true;
    out.responseCode = (uint8_t)r.ResponseCode;
    out.hasCpdRes = true;
    out.evseProcessing = (uint8_t)r.EVSEProcessing;
    if (r.DC_EVSEChargeParameter_isUsed) {
      const struct dinDC_EVSEChargeParameterType &p = r.DC_EVSEChargeParameter;
      out.hasEvseLimits = true;
      out.evseMaxVoltage = physicalValue(p.EVSEMaximumVoltageLimit);
      out.evseMaxCurrent = physicalValue(p.EVSEMaximumCurrentLimit);
      out.evseMinVoltage = physicalValue(p.EVSEMinimumVoltageLimit);
      out.evseMinCurrent = physicalValue(p.EVSEMinimumCurrentLimit);
      out.hasEvseMaxPower = p.EVSEMaximumPowerLimit_isUsed;
      if (p.EVSEMaximumPowerLimit_isUsed) {
        out.evseMaxPower = physicalValue(p.EVSEMaximumPowerLimit);
      }
    }
    return true;
  }
  if (body.PowerDeliveryReq_isUsed) {
    strlcpy(out.msgName, "PowerDeliveryReq", sizeof(out.msgName));
    return true;
  }
  if (body.PowerDeliveryRes_isUsed) {
    strlcpy(out.msgName, "PowerDeliveryRes", sizeof(out.msgName));
    out.hasResponseCode = true;
    out.responseCode = (uint8_t)body.PowerDeliveryRes.ResponseCode;
    return true;
  }
  NAMED(ChargingStatusReq)
  NAMED(ChargingStatusRes)
  NAMED(MeteringReceiptReq)
  NAMED(MeteringReceiptRes)
  NAMED(SessionStopReq)
  NAMED(SessionStopRes)
  NAMED(CertificateUpdateReq)
  NAMED(CertificateUpdateRes)
  NAMED(CertificateInstallationReq)
  NAMED(CertificateInstallationRes)
  if (body.CableCheckReq_isUsed) {
    strlcpy(out.msgName, "CableCheckReq", sizeof(out.msgName));
    out.hasSoc = true;
    out.soc = body.CableCheckReq.DC_EVStatus.EVRESSSOC;
    return true;
  }
  if (body.CableCheckRes_isUsed) {
    strlcpy(out.msgName, "CableCheckRes", sizeof(out.msgName));
    out.hasResponseCode = true;
    out.responseCode = (uint8_t)body.CableCheckRes.ResponseCode;
    return true;
  }
  if (body.PreChargeReq_isUsed) {
    strlcpy(out.msgName, "PreChargeReq", sizeof(out.msgName));
    out.hasSoc = true;
    out.soc = body.PreChargeReq.DC_EVStatus.EVRESSSOC;
    out.hasTargetVoltage = true;
    out.targetVoltage = physicalValue(body.PreChargeReq.EVTargetVoltage);
    return true;
  }
  if (body.PreChargeRes_isUsed) {
    strlcpy(out.msgName, "PreChargeRes", sizeof(out.msgName));
    out.hasResponseCode = true;
    out.responseCode = (uint8_t)body.PreChargeRes.ResponseCode;
    out.hasPresentVoltage = true;
    out.presentVoltage = physicalValue(body.PreChargeRes.EVSEPresentVoltage);
    return true;
  }
  if (body.CurrentDemandReq_isUsed) {
    strlcpy(out.msgName, "CurrentDemandReq", sizeof(out.msgName));
    const struct dinCurrentDemandReqType &r = body.CurrentDemandReq;
    out.hasSoc = true;
    out.soc = r.DC_EVStatus.EVRESSSOC;
    out.hasTargetVoltage = true;
    out.targetVoltage = physicalValue(r.EVTargetVoltage);
    out.hasTargetCurrent = true;
    out.targetCurrent = physicalValue(r.EVTargetCurrent);
    return true;
  }
  if (body.CurrentDemandRes_isUsed) {
    strlcpy(out.msgName, "CurrentDemandRes", sizeof(out.msgName));
    const struct dinCurrentDemandResType &r = body.CurrentDemandRes;
    out.hasResponseCode = true;
    out.responseCode = (uint8_t)r.ResponseCode;
    out.hasPresentVoltage = true;
    out.presentVoltage = physicalValue(r.EVSEPresentVoltage);
    out.hasPresentCurrent = true;
    out.presentCurrent = physicalValue(r.EVSEPresentCurrent);
    return true;
  }
  NAMED(WeldingDetectionReq)
  NAMED(WeldingDetectionRes)
  if (body.BodyElement_isUsed) {
    strlcpy(out.msgName, "BodyElement?", sizeof(out.msgName));
    return true;
  }
  return false;  // decoded OK but no body variant flagged - shouldn't happen
}
#undef NAMED

static bool decodeDin(const uint8_t *data, uint16_t len, V2gValues &out) {
  bitstream_t stream;
  size_t pos = 0;
  stream.size = len;
  stream.data = const_cast<uint8_t *>(data);
  stream.pos = &pos;
  stream.buffer = 0;
  stream.capacity = 0;

  int errn = decode_dinExiDocument(&stream, &s_dinDoc);
  if (errn != 0) {
    snprintf(out.msgName, sizeof(out.msgName), "DIN err %d", errn);
    return false;
  }
  if (!s_dinDoc.V2G_Message_isUsed) {
    strlcpy(out.msgName, "DIN (top-level?)", sizeof(out.msgName));
    return false;
  }
  if (!extractDinBody(s_dinDoc.V2G_Message.Body, out)) {
    strlcpy(out.msgName, "DIN (empty body)", sizeof(out.msgName));
    return false;
  }
  // The header rides on every message, so it is taken after the body decoded cleanly.
  const auto &sid = s_dinDoc.V2G_Message.Header.SessionID;
  out.sessionIdLen = sid.bytesLen > sizeof(out.sessionId) ? sizeof(out.sessionId)
                                                          : (uint8_t)sid.bytesLen;
  memcpy(out.sessionId, sid.bytes, out.sessionIdLen);
  out.hasSessionId = out.sessionIdLen > 0;
  return true;
}

static bool decodeAppHand(const uint8_t *data, uint16_t len, V2gValues &out) {
  bitstream_t stream;
  size_t pos = 0;
  stream.size = len;
  stream.data = const_cast<uint8_t *>(data);
  stream.pos = &pos;
  stream.buffer = 0;
  stream.capacity = 0;

  int errn = decode_appHandExiDocument(&stream, &s_aphsDoc);
  if (errn != 0) {
    snprintf(out.msgName, sizeof(out.msgName), "appHand err %d", errn);
    return false;
  }
  if (s_aphsDoc.supportedAppProtocolReq_isUsed) {
    strlcpy(out.msgName, "SupportedAppProtocolReq", sizeof(out.msgName));
    const auto &list = s_aphsDoc.supportedAppProtocolReq.AppProtocol;
    uint8_t n = list.arrayLen < V2gValues::MAX_APP_PROTOCOLS ? list.arrayLen
                                                               : V2gValues::MAX_APP_PROTOCOLS;
    for (uint8_t i = 0; i < n; i++) {
      const struct appHandAppProtocolType &src = list.array[i];
      V2gValues::AppProtocol &dst = out.appProtocols[i];
      uint16_t len = src.ProtocolNamespace.charactersLen;
      if (len > sizeof(dst.ns) - 1) len = sizeof(dst.ns) - 1;
      for (uint16_t c = 0; c < len; c++) {
        char ch = (char)src.ProtocolNamespace.characters[c];  // char or uint32_t, per EXI config
        dst.ns[c] = (ch < 0x20 || ch > 0x7E) ? '?' : ch;
      }
      dst.ns[len] = '\0';
      dst.versionMajor = (uint8_t)src.VersionNumberMajor;
      dst.versionMinor = (uint8_t)src.VersionNumberMinor;
      dst.schemaId = src.SchemaID;
      dst.priority = src.Priority;
    }
    out.appProtocolCount = n;
    return true;
  }
  if (s_aphsDoc.supportedAppProtocolRes_isUsed) {
    strlcpy(out.msgName, "SupportedAppProtocolRes", sizeof(out.msgName));
    const auto &res = s_aphsDoc.supportedAppProtocolRes;
    out.hasHandshakeResult = true;
    out.handshakeResponseCode = (uint8_t)res.ResponseCode;
    out.hasSelectedSchema = res.SchemaID_isUsed;
    out.selectedSchemaId = res.SchemaID;
    return true;
  }
  strlcpy(out.msgName, "appHand?", sizeof(out.msgName));
  return false;
}

bool decodeV2gExiPayload(const uint8_t *data, uint16_t len, V2gValues &out) {
  out = V2gValues();
  if (len == 0) {
    strlcpy(out.msgName, "(empty)", sizeof(out.msgName));
    return false;
  }
  // DIN is the common case once a session is under way (the app-handshake happens once, at
  // the very start). Trying it first avoids two failed decodes for most messages.
  if (decodeDin(data, len, out)) {
    return true;
  }
  V2gValues dinFail = out;
  if (decodeAppHand(data, len, out)) {
    return true;
  }
  out = dinFail;  // report the DIN error - the more likely schema once joined
  return false;
}

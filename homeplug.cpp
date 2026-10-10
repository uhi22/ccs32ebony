#include "homeplug.h"

namespace homeplug {

const uint8_t MAC_LOCAL_MANAGEMENT[6] = {0x00, 0xB0, 0x52, 0x00, 0x00, 0x01};

static constexpr uint16_t MMTYPE_GET_SW = 0xA000;
static constexpr uint16_t MMTYPE_VS_NW_INFO = 0xA038;

static constexpr uint16_t MMTYPE_REQ = 0x0000;
static constexpr uint16_t MMTYPE_CNF = 0x0001;
static constexpr uint16_t MMTYPE_IND = 0x0002;

static const uint8_t QUALCOMM_OUI[3] = {0x00, 0xB0, 0x52};

// Offsets in a HomePlug AV management frame
static constexpr uint8_t OFS_MMV = 14;
static constexpr uint8_t OFS_MMTYPE = 15;         // little endian
static constexpr uint8_t OFS_OUI = 17;            // vendor MMEs (MMV 0)
static constexpr uint8_t OFS_VS_PAYLOAD = 20;     // after the OUI
static constexpr uint8_t OFS_SW_VERSION_LEN = 22; // GET_SW.CNF
static constexpr uint8_t OFS_SW_VERSION = 23;     // GET_SW.CNF

// MMV 1 (HomePlug AV 1.1) has a 2 byte fragmentation header (FMI) after the MMTYPE
static constexpr uint8_t MMV_AV10 = 0x00;
static constexpr uint8_t MMV_AV11 = 0x01;

struct MmtypeName {
  uint16_t base;
  const char *name;
};

static const MmtypeName MMTYPE_NAMES[] = {
    {0x0030, "CC_ASSOC"},       {0x0038, "CC_SET_TEI_MAP"},
    {0x6000, "UNASSOCIATED_STA"}, {0x6004, "ENCRYPTED_PAYLOAD"},
    {0x6008, "SET_KEY"},        {0x600C, "GET_KEY"},
    {0x6038, "NW_INFO"},        {0x6044, "MME_ERROR"},
    {0x6048, "NW_STATS"},       {0x6064, "SLAC_PARAM"},
    {0x6068, "START_ATTEN_CHAR"}, {0x606C, "ATTEN_CHAR"},
    {0x6074, "MNBC_SOUND"},     {0x6078, "VALIDATE"},
    {0x607C, "SLAC_MATCH"},     {0x6084, "ATTEN_PROFILE"},
    {0xA000, "GET_SW"},         {0xA038, "VS_NW_INFO"},
};

uint16_t etherType(const uint8_t *frame) {
  return (frame[12] << 8) | frame[13];
}

uint16_t mmtype(const uint8_t *frame) {
  return frame[OFS_MMTYPE] | (frame[OFS_MMTYPE + 1] << 8);
}

void describeMmtype(uint16_t mm, char *buf, size_t bufLen) {
  static const char *const SUFFIX[4] = {"REQ", "CNF", "IND", "RSP"};
  uint16_t base = mm & ~0x0003;
  for (const MmtypeName &entry : MMTYPE_NAMES) {
    if (entry.base == base) {
      snprintf(buf, bufLen, "%s.%s", entry.name, SUFFIX[mm & 0x0003]);
      return;
    }
  }
  snprintf(buf, bufLen, "MME %04X.%s", base, SUFFIX[mm & 0x0003]);
}

// Header up to and including the MMTYPE; returns the offset of the payload
static uint8_t composeHeader(uint8_t *frame, const uint8_t dst[6], const uint8_t src[6],
                             uint8_t mmv, uint16_t mm) {
  memset(frame, 0, MIN_ETH_FRAME_LEN);
  memcpy(&frame[0], dst, 6);
  memcpy(&frame[6], src, 6);
  frame[12] = ETHERTYPE_HOMEPLUG >> 8;
  frame[13] = ETHERTYPE_HOMEPLUG & 0xFF;
  frame[OFS_MMV] = mmv;
  frame[OFS_MMTYPE] = mm & 0xFF;
  frame[OFS_MMTYPE + 1] = mm >> 8;
  return (mmv == MMV_AV10) ? 17 : 19;  // FMI bytes stay 0
}

// Offset of the payload in a received MME, depending on its MMV
static uint8_t payloadOffset(const uint8_t *frame) {
  return (frame[OFS_MMV] == MMV_AV10) ? 17 : 19;
}

// Vendor MME header (MMV 0 + OUI) to dst; returns the payload offset
static uint8_t composeVendorHeader(uint8_t *frame, const uint8_t dst[6],
                                   const uint8_t src[6], uint16_t mm) {
  composeHeader(frame, dst, src, MMV_AV10, mm);
  memcpy(&frame[OFS_OUI], QUALCOMM_OUI, 3);
  return OFS_VS_PAYLOAD;
}

static bool isVendorCnf(const uint8_t *frame, uint16_t len, uint16_t mm, uint16_t minLen) {
  return len >= minLen && etherType(frame) == ETHERTYPE_HOMEPLUG &&
         mmtype(frame) == (mm | MMTYPE_CNF) &&
         memcmp(&frame[OFS_OUI], QUALCOMM_OUI, 3) == 0;
}

uint16_t composeGetSwReq(uint8_t *frame, const uint8_t dst[6], const uint8_t src[6]) {
  composeVendorHeader(frame, dst, src, MMTYPE_GET_SW | MMTYPE_REQ);
  return MIN_ETH_FRAME_LEN;
}

uint16_t composeSnifferTagReq(uint8_t *frame, const uint8_t dst[6], const uint8_t src[6]) {
  uint8_t ofs = composeVendorHeader(frame, dst, src, MMTYPE_GET_SW | MMTYPE_REQ);
  memcpy(&frame[ofs], "GST1", 4);
  return MIN_ETH_FRAME_LEN;
}

bool parseGetSwCnf(const uint8_t *frame, uint16_t len, SoftwareVersion &out) {
  if (!isVendorCnf(frame, len, MMTYPE_GET_SW, OFS_SW_VERSION)) {
    return false;
  }
  uint8_t versionLen = frame[OFS_SW_VERSION_LEN];
  if (versionLen == 0 || versionLen > VERSION_MAX_LEN ||
      OFS_SW_VERSION + versionLen > len) {
    return false;
  }

  memcpy(out.mac, &frame[6], 6);
  for (uint8_t i = 0; i < versionLen; i++) {
    char c = frame[OFS_SW_VERSION + i];
    out.version[i] = (c < 0x20 || c > 0x7E) ? ' ' : c;  // unprintable -> space
  }
  // The string is zero-padded; drop the padding
  while (versionLen > 0 && out.version[versionLen - 1] == ' ') {
    versionLen--;
  }
  out.version[versionLen] = '\0';
  return true;
}

bool parseSnifferTagCnf(const uint8_t *frame, uint16_t len, char tag[17]) {
  // The sniffer's tag answer has zeros where the OUI and the length byte would be, so only the
  // MMTYPE is checked (seen on a TL-PA4010P with build 261008-V142-0844)
  if (len < OFS_SW_VERSION + 16 || etherType(frame) != ETHERTYPE_HOMEPLUG ||
      mmtype(frame) != (MMTYPE_GET_SW | MMTYPE_CNF)) {
    return false;
  }
  for (uint8_t i = 0; i < 16; i++) {
    char c = frame[OFS_SW_VERSION + i];
    tag[i] = (c < 0x20 || c > 0x7E) ? '.' : c;
  }
  tag[16] = '\0';
  return true;
}

bool isSnifferTag(const char *v) {
  // YYMMDD-Vnnn-xxxx
  if (strlen(v) < 16) {
    return false;
  }
  for (uint8_t i = 0; i < 6; i++) {
    if (!isdigit((unsigned char)v[i])) {
      return false;
    }
  }
  return v[6] == '-' && v[7] == 'V' && v[11] == '-';
}

uint16_t composeVsNwInfoReq(uint8_t *frame, const uint8_t dst[6], const uint8_t src[6]) {
  composeVendorHeader(frame, dst, src, MMTYPE_VS_NW_INFO | MMTYPE_REQ);
  return MIN_ETH_FRAME_LEN;
}

bool parseVsNwInfoCnf(const uint8_t *frame, uint16_t len, VsNetworkInfo &out) {
  // NUMAVLNs at 0x14 (wire offset; the programmer's guide says 0x18), then
  // NID(7) SNID TEI ROLE CCO_MAC(6) CCO_TEI NUMSTAS, then 15 bytes per station
  if (!isVendorCnf(frame, len, MMTYPE_VS_NW_INFO, 0x15)) {
    return false;
  }
  memset(&out, 0, sizeof(out));
  memcpy(out.mac, &frame[6], 6);
  out.numAvlns = frame[0x14];
  if (out.numAvlns == 0) {
    return true;
  }
  static constexpr uint16_t OFS_AVLN = 0x15;
  if (OFS_AVLN + 18 > len) {
    return false;
  }
  const uint8_t *a = &frame[OFS_AVLN];
  out.ownTei = a[8];
  out.role = a[9];
  memcpy(out.ccoMac, &a[10], 6);
  out.ccoTei = a[16];
  uint8_t stations = a[17];
  uint16_t pos = OFS_AVLN + 18;
  for (uint8_t i = 0; i < stations && out.numStations < VsNetworkInfo::MAX_STATIONS &&
                      pos + 15 <= len;
       i++, pos += 15) {
    memcpy(out.stations[out.numStations].mac, &frame[pos], 6);
    out.stations[out.numStations].tei = frame[pos + 6];
    out.numStations++;
  }
  return true;
}

// SLAC payload parsers. Both messages travel between PEV and EVSE and reach us through the
// sniffer - no request of ours is involved.
static constexpr uint16_t MMTYPE_ATTEN_CHAR = 0x606C;
static constexpr uint16_t MMTYPE_SLAC_MATCH = 0x607C;

bool parseAttenCharInd(const uint8_t *frame, uint16_t len, AttenProfile &out) {
  if (len < 24 || etherType(frame) != ETHERTYPE_HOMEPLUG ||
      mmtype(frame) != (MMTYPE_ATTEN_CHAR | MMTYPE_IND)) {
    return false;
  }
  uint8_t ofs = payloadOffset(frame);
  const uint16_t groupsOfs = ofs + 1 + 1 + 6 + 8 + 17 + 17 + 1 + 1;  // see the header comment
  if (groupsOfs > len) {
    return false;
  }
  out = AttenProfile();
  memcpy(out.pevMac, &frame[ofs + 2], 6);
  out.numSounds = frame[groupsOfs - 2];
  uint8_t groups = frame[groupsOfs - 1];
  if (groups > ATTEN_MAX_GROUPS) groups = ATTEN_MAX_GROUPS;
  if (groupsOfs + groups > len) {
    groups = (uint8_t)(len - groupsOfs);  // truncated frame: keep what is there
  }
  out.numGroups = groups;
  memcpy(out.attenuation, &frame[groupsOfs], groups);
  return groups > 0;
}

bool parseSlacMatchCnf(const uint8_t *frame, uint16_t len, SlacMatch &out) {
  if (etherType(frame) != ETHERTYPE_HOMEPLUG ||
      mmtype(frame) != (MMTYPE_SLAC_MATCH | MMTYPE_CNF)) {
    return false;
  }
  uint8_t ofs = payloadOffset(frame);
  const uint16_t pevMacOfs = ofs + 1 + 1 + 2 + 17;
  const uint16_t evseMacOfs = pevMacOfs + 6 + 17;
  const uint16_t nidOfs = evseMacOfs + 6 + 8 + 8;
  const uint16_t nmkOfs = nidOfs + 7 + 1;
  if (nmkOfs + 16 > len) {
    return false;
  }
  out = SlacMatch();
  memcpy(out.pevMac, &frame[pevMacOfs], 6);
  memcpy(out.evseMac, &frame[evseMacOfs], 6);
  memcpy(out.nid, &frame[nidOfs], 7);
  memcpy(out.nmk, &frame[nmkOfs], 16);
  return true;
}

}  // namespace homeplug

// HomePlug AV management messages (MMEs).
// Ported from github.com/uhi22/ccs32dave (homeplug.h/.cpp), which was ported from ccs32berta.
// Requests are always addressed to the local modem (never broadcast), so nothing reaches the
// powerline session.

#pragma once

#include <Arduino.h>

namespace homeplug {

constexpr uint16_t ETHERTYPE_HOMEPLUG = 0x88E1;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
constexpr uint16_t MIN_ETH_FRAME_LEN = 60;
constexpr uint8_t VERSION_MAX_LEN = 64;

// Qualcomm "local management" address: only the modem attached to this Ethernet port answers,
// the frame is not forwarded onto the powerline
extern const uint8_t MAC_LOCAL_MANAGEMENT[6];

struct SoftwareVersion {
  uint8_t mac[6];                        // MAC of the answering modem
  char version[VERSION_MAX_LEN + 1];     // e.g. "MAC-7420-v1.1.0-01-X-FINAL"
};

// Content of VS_NW_INFO.CNF (Qualcomm vendor MME): the networks the answering station is member of
struct VsNetworkInfo {
  static constexpr uint8_t MAX_STATIONS = 8;
  uint8_t mac[6];       // answering modem
  uint8_t numAvlns;     // 0 = not joined
  uint8_t ownTei;
  uint8_t role;         // 0 = STA, 1 = PCo, 2 = CCo
  uint8_t ccoTei;
  uint8_t ccoMac[6];
  uint8_t numStations;  // stations stored (<= MAX_STATIONS)
  struct Station {
    uint8_t mac[6];
    uint8_t tei;
  } stations[MAX_STATIONS];
};

uint16_t etherType(const uint8_t *frame);

// MMTYPE of a HomePlug frame (base type + REQ/CNF/IND/RSP in the low 2 bits)
uint16_t mmtype(const uint8_t *frame);

// Writes a readable MMTYPE, e.g. "SLAC_PARAM.REQ" or "MME 6044.CNF", into buf
void describeMmtype(uint16_t mmtype, char *buf, size_t bufLen);

// GET_SW.REQ (Qualcomm vendor MME) to dst; frame must hold MIN_ETH_FRAME_LEN bytes.
// Returns the frame length.
uint16_t composeGetSwReq(uint8_t *frame, const uint8_t dst[6], const uint8_t src[6]);

// GET_SW.REQ with the "GST1" pattern: the pyPLC AR7420 sniffer firmware then answers with its
// build tag (e.g. "YYMMDD-Vnnn-0844") in the version field; stock firmware ignores the pattern
// and answers with its normal version string
uint16_t composeSnifferTagReq(uint8_t *frame, const uint8_t dst[6], const uint8_t src[6]);

// Returns true and fills out if frame is a valid GET_SW.CNF
bool parseGetSwCnf(const uint8_t *frame, uint16_t len, SoftwareVersion &out);

// Answer to composeSnifferTagReq(): a GET_SW.CNF whose 16 bytes at the version position are
// read as the tag. The OUI and the length byte are not checked (the sniffer leaves them 0), as
// in the published identify script.
// Returns true and fills tag (17 bytes incl. terminator) if frame is a GET_SW.CNF.
bool parseSnifferTagCnf(const uint8_t *frame, uint16_t len, char tag[17]);

// True if a version string has the sniffer build tag format "YYMMDD-Vnnn-xxxx"
bool isSnifferTag(const char *version);

// Build number nnn of a sniffer tag "YYMMDD-Vnnn-xxxx", or -1
int snifferBuild(const char *tag);

// GET_SW.REQ with the "RDM1" pattern: the sniffer firmware answers with the 16 bytes at addr.
// The answer does not repeat the address, so only one such request may be outstanding at a time.
uint16_t composeSnifferReadReq(uint8_t *frame, const uint8_t dst[6], const uint8_t src[6], uint32_t addr);

// GET_SW.REQ with the "WRM1" pattern: the sniffer firmware writes one byte at addr and answers with the
// 16 bytes there, read back after the write (same answer shape as "RDM1"). Only for the addresses the
// sniffer contract allows (see local_modem.h).
uint16_t composeSnifferWriteReq(uint8_t *frame, const uint8_t dst[6], const uint8_t src[6], uint32_t addr,
                                uint8_t value);

// GET_SW.REQ with the "WRM1" pattern, width 4: writes the 32-bit `value` (little endian) at addr and answers
// with the 16 bytes there. Used for the OWN_TEI consumer mask (contract section 6), whose slots are 4-byte words.
uint16_t composeSnifferWriteReq32(uint8_t *frame, const uint8_t dst[6], const uint8_t src[6], uint32_t addr,
                                  uint32_t value);

// VS_RS_DEV (0xA01C): a vendor device soft reset. The modem reloads its firmware (seq restarts); used to test the
// mask re-apply on the bench without a charging session. Harmless; the modem is back in a few seconds.
uint16_t composeDeviceResetReq(uint8_t *frame, const uint8_t dst[6], const uint8_t src[6]);

// The 16 content bytes (offset 23) of a sniffer GET_SW.CNF (answer to "GST1" or "RDM1").
// Only the MMTYPE is checked, as for the tag. Returns true if frame is a GET_SW.CNF.
bool parseSnifferCnf(const uint8_t *frame, uint16_t len, uint8_t out[16]);

// VS_NW_INFO.REQ (0xA038) to dst. Returns the frame length.
uint16_t composeVsNwInfoReq(uint8_t *frame, const uint8_t dst[6], const uint8_t src[6]);

// VS_NW_INFO.CNF (0xA039)
bool parseVsNwInfoCnf(const uint8_t *frame, uint16_t len, VsNetworkInfo &out);

// CM_ATTEN_CHAR.IND (0x606C): the attenuation the EVSE measured over the PEV's CM_MNBC_SOUND
// bursts, per OFDM carrier group, in dB. Wire layout after the MME header:
// APPLICATION_TYPE(1) SECURITY_TYPE(1) SOURCE_ADDRESS(6) RUN_ID(8) SOURCE_ID(17) RESP_ID(17)
// NUM_SOUNDS(1) NUM_GROUPS(1) then NUM_GROUPS attenuation bytes.
constexpr uint8_t ATTEN_MAX_GROUPS = 64;
struct AttenProfile {
  uint8_t pevMac[6] = {};   // SOURCE_ADDRESS: the PEV whose sounds were measured
  uint8_t numSounds = 0;    // sounds the EVSE actually received (10 expected)
  uint8_t numGroups = 0;
  uint8_t attenuation[ATTEN_MAX_GROUPS] = {};  // dB per group, higher = weaker coupling
};
bool parseAttenCharInd(const uint8_t *frame, uint16_t len, AttenProfile &out);

// CM_SLAC_MATCH.CNF (0x607D): names both sides and hands over the key material.
// After the MME header: APPLICATION_TYPE(1) SECURITY_TYPE(1) MVFLength(2) PEV_ID(17) PEV_MAC(6)
// EVSE_ID(17) EVSE_MAC(6) RunID(8) RSVD(8) NID(7) RSVD(1) NMK(16)
struct SlacMatch {
  uint8_t pevMac[6] = {};
  uint8_t evseMac[6] = {};
  uint8_t nid[7] = {};
  uint8_t nmk[16] = {};
};
bool parseSlacMatchCnf(const uint8_t *frame, uint16_t len, SlacMatch &out);

}  // namespace homeplug

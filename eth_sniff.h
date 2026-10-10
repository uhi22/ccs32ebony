// Raw Ethernet receiver for the WT32-ETH01 (ESP32 EMAC + LAN8720 PHY).
//
// The sniffer modem forwards the car's and the charger's frames with their original MAC addresses,
// so the EMAC runs in promiscuous mode and every frame is taken directly from the driver. No IP
// stack is attached to the Ethernet port: the board sends nothing on its own (no DHCP, ARP, IPv6).
//
// Frames are queued by the driver's RX task and handed to the caller in poll(), i.e. in loop()
// context, like Qca7000::poll() in ccs32dave.

#pragma once

#include <Arduino.h>
#include <esp_eth.h>

class EthSniffer {
public:
  static constexpr uint16_t MAX_ETH_FRAME_LEN = 1522;
  static constexpr uint8_t RX_QUEUE_LEN = 64;

  // Called for each received Ethernet frame (without FCS)
  using FrameHandler = void (*)(const uint8_t *frame, uint16_t len);

  // WT32-ETH01: LAN8720 at PHY address 1, MDC 23, MDIO 18, GPIO16 = PHY/oscillator enable,
  // RMII clock input on GPIO0 from the board's 50 MHz oscillator.
  bool begin(int phyAddr = 1, int pinMdc = 23, int pinMdio = 18, int pinPower = 16);

  // Hands all queued frames to handler. Returns the number of frames handled.
  uint16_t poll(FrameHandler handler);

  // Sends one Ethernet frame (without FCS). Not used by the passive sniffer yet.
  bool sendEthFrame(const uint8_t *frame, uint16_t len);

  bool linkUp() const { return _linkUp; }
  uint32_t linkSpeedMbps() const { return _speedMbps; }
  bool fullDuplex() const { return _fullDuplex; }
  const uint8_t *ownMac() const { return _ownMac; }

  uint32_t rxFrames() const { return _rxFrames; }    // received by the driver
  uint32_t rxDropped() const { return _rxDropped; }  // queue full, frame lost
  uint32_t txFrames() const { return _txFrames; }
  uint32_t errors() const { return _errors; }

private:
  struct QueuedFrame {
    uint8_t *data;  // allocated by the driver, freed after the handler ran
    uint16_t len;
  };

  static esp_err_t onRx(esp_eth_handle_t hdl, uint8_t *buffer, uint32_t length, void *priv);
  static void onEvent(void *arg, esp_event_base_t base, int32_t id, void *data);

  esp_eth_handle_t _handle = nullptr;
  QueueHandle_t _queue = nullptr;
  uint8_t _ownMac[6] = {};

  volatile bool _linkUp = false;
  volatile uint32_t _speedMbps = 0;
  volatile bool _fullDuplex = false;

  volatile uint32_t _rxFrames = 0;
  volatile uint32_t _rxDropped = 0;
  uint32_t _txFrames = 0;
  uint32_t _errors = 0;
};

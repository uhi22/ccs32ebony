#include "eth_sniff.h"

#include <Network.h>
#include <esp_mac.h>

bool EthSniffer::begin(int phyAddr, int pinMdc, int pinMdio, int pinPower) {
  // Default event loop and esp_netif (the Wi-Fi AP needs them too). Ethernet gets no netif.
  Network.begin();

  _queue = xQueueCreate(RX_QUEUE_LEN, sizeof(QueuedFrame));
  if (_queue == nullptr) {
    log_e("RX queue allocation failed");
    return false;
  }

  eth_esp32_emac_config_t emacConfig = ETH_ESP32_EMAC_DEFAULT_CONFIG();
  emacConfig.smi_mdc_gpio_num = pinMdc;
  emacConfig.smi_mdio_gpio_num = pinMdio;
  emacConfig.clock_config.rmii.clock_mode = EMAC_CLK_EXT_IN;  // 50 MHz oscillator into GPIO0
  emacConfig.clock_config.rmii.clock_gpio = EMAC_CLK_IN_GPIO;

  eth_mac_config_t macConfig = ETH_MAC_DEFAULT_CONFIG();
  macConfig.sw_reset_timeout_ms = 1000;
  esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&emacConfig, &macConfig);
  if (mac == nullptr) {
    log_e("esp_eth_mac_new_esp32 failed");
    return false;
  }

  // The power pin enables the oscillator; the PHY driver pulses it like a reset (as ETH.begin() does)
  eth_phy_config_t phyConfig = ETH_PHY_DEFAULT_CONFIG();
  phyConfig.phy_addr = phyAddr;
  phyConfig.reset_gpio_num = pinPower;
  esp_eth_phy_t *phy = esp_eth_phy_new_lan87xx(&phyConfig);
  if (phy == nullptr) {
    log_e("esp_eth_phy_new_lan87xx failed");
    return false;
  }

  esp_eth_config_t ethConfig = ETH_DEFAULT_CONFIG(mac, phy);
  esp_err_t err = esp_eth_driver_install(&ethConfig, &_handle);
  if (err != ESP_OK || _handle == nullptr) {
    log_e("esp_eth_driver_install failed: %d", err);
    return false;
  }

  esp_read_mac(_ownMac, ESP_MAC_ETH);
  esp_eth_ioctl(_handle, ETH_CMD_S_MAC_ADDR, _ownMac);

  err = esp_eth_update_input_path(_handle, onRx, this);
  if (err != ESP_OK) {
    log_e("esp_eth_update_input_path failed: %d", err);
    return false;
  }

  bool promiscuous = true;
  err = esp_eth_ioctl(_handle, ETH_CMD_S_PROMISCUOUS, &promiscuous);
  if (err != ESP_OK) {
    log_e("promiscuous mode failed: %d", err);
    return false;
  }

  esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, onEvent, this);

  err = esp_eth_start(_handle);
  if (err != ESP_OK) {
    log_e("esp_eth_start failed: %d", err);
    return false;
  }
  return true;
}

// Runs in the EMAC RX task: only queue the frame, never block.
esp_err_t EthSniffer::onRx(esp_eth_handle_t hdl, uint8_t *buffer, uint32_t length, void *priv) {
  EthSniffer *self = static_cast<EthSniffer *>(priv);
  self->_rxFrames++;
  QueuedFrame f = {buffer, (uint16_t)length};
  if (length > MAX_ETH_FRAME_LEN || xQueueSend(self->_queue, &f, 0) != pdTRUE) {
    self->_rxDropped++;
    free(buffer);
  }
  return ESP_OK;
}

void EthSniffer::onEvent(void *arg, esp_event_base_t base, int32_t id, void *data) {
  EthSniffer *self = static_cast<EthSniffer *>(arg);
  switch (id) {
    case ETHERNET_EVENT_CONNECTED: {
      eth_speed_t speed;
      eth_duplex_t duplex;
      esp_eth_ioctl(self->_handle, ETH_CMD_G_SPEED, &speed);
      esp_eth_ioctl(self->_handle, ETH_CMD_G_DUPLEX_MODE, &duplex);
      self->_speedMbps = (speed == ETH_SPEED_100M) ? 100 : 10;
      self->_fullDuplex = (duplex == ETH_DUPLEX_FULL);
      self->_linkUp = true;
      break;
    }
    case ETHERNET_EVENT_DISCONNECTED:
      self->_linkUp = false;
      break;
    default:
      break;
  }
}

uint16_t EthSniffer::poll(FrameHandler handler) {
  uint16_t count = 0;
  QueuedFrame f;
  while (_queue != nullptr && xQueueReceive(_queue, &f, 0) == pdTRUE) {
    handler(f.data, f.len);
    free(f.data);
    count++;
  }
  return count;
}

bool EthSniffer::sendEthFrame(const uint8_t *frame, uint16_t len) {
  if (_handle == nullptr || len > MAX_ETH_FRAME_LEN) {
    _errors++;
    return false;
  }
  if (esp_eth_transmit(_handle, (void *)frame, len) != ESP_OK) {
    _errors++;
    return false;
  }
  _txFrames++;
  return true;
}

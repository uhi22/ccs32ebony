// Wi-Fi access point with a minimal HTTP + WebSocket server for the tablet UI.
//
// - SoftAP (WPA2) at 192.168.4.1, DNS answers every name with that address (captive portal)
// - GET /       -> the single-page app (gzip-compressed, embedded in flash: webui_assets.h)
// - GET /ws     -> WebSocket; the sketch pushes JSON text messages to all clients
// - other paths -> redirect to /, so the tablet's "sign in to network" check opens the UI
//
// Everything runs in loop() context and never blocks for long: each WebSocket client has an
// output queue that is flushed non-blocking; a client whose queue overflows is disconnected
// (its browser reconnects).

#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <DNSServer.h>

class WebUi {
public:
  static constexpr uint8_t MAX_CONNECTIONS = 6;  // HTTP and WebSocket together
  static constexpr uint8_t MAX_AP_CLIENTS = 4;   // Wi-Fi stations
  static constexpr uint16_t TX_QUEUE_LEN = 4096;  // per WebSocket client, allocated on upgrade

  // Called when a WebSocket client connected (id = connection slot), e.g. to send a snapshot
  using ConnectHandler = void (*)(uint8_t id);
  // Called for each text message received from a WebSocket client
  using TextHandler = void (*)(uint8_t id, const char *text);

  // Returns false if the password is too short for WPA2 (< 8 characters) or the AP fails.
  // captivePortal false: the OS connectivity checks are answered as "internet OK", so tablets
  // join without a sign-in sheet and the UI is opened in the browser (http://192.168.4.1/).
  // true: they are redirected to the UI, which then pops up by itself - but iOS shows it in a
  // sign-in sheet that cannot be confirmed, only cancelled (which leaves the network).
  bool begin(const char *ssid, const char *password, bool captivePortal = false);
  void loop();

  void onConnect(ConnectHandler h) { _onConnect = h; }
  void onText(TextHandler h) { _onText = h; }

  // Queues a text message for all WebSocket clients, or for one. False (one client): not a
  // WebSocket client, or its queue overflowed and it was disconnected.
  void broadcast(const char *text);
  bool sendTo(uint8_t id, const char *text);

  bool isWebSocket(uint8_t id) const { return id < MAX_CONNECTIONS && _conn[id].state == State::WebSocket; }
  // Free space in a client's output queue (0 if not a WebSocket client)
  size_t txFree(uint8_t id) const;

  uint8_t wsClients() const;
  uint8_t apStations() const { return WiFi.softAPgetStationNum(); }
  uint32_t wsDropped() const { return _wsDropped; }  // clients closed: queue overflow or socket error
  IPAddress ip() const { return WiFi.softAPIP(); }

private:
  enum class State : uint8_t { Free, Http, WebSocket };

  struct Connection {
    NetworkClient client;
    State state = State::Free;
    uint32_t lastRxMs = 0;
    uint16_t len = 0;
    char buf[1024];  // HTTP request header, later the WebSocket receive buffer
    uint8_t *tx = nullptr;  // WebSocket output queue (TX_QUEUE_LEN bytes)
    uint16_t txLen = 0;
  };

  void accept();
  void handleHttp(uint8_t id);
  void handleWebSocket(uint8_t id);
  void serveIndex(Connection &c);
  bool answerConnectivityCheck(Connection &c, const char *path);
  void upgrade(uint8_t id, const char *key);
  bool sendFrame(Connection &c, uint8_t opcode, const uint8_t *data, size_t len);
  bool flush(Connection &c);
  void close(Connection &c);

  DNSServer _dns;
  NetworkServer _server{80};
  Connection _conn[MAX_CONNECTIONS];
  ConnectHandler _onConnect = nullptr;
  TextHandler _onText = nullptr;
  uint32_t _wsDropped = 0;
  bool _running = false;
  bool _captivePortal = false;
};

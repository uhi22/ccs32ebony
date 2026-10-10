#include "webui.h"

#include <errno.h>
#include <lwip/sockets.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha1.h>

#include "webui_assets.h"

static constexpr uint32_t HTTP_TIMEOUT_MS = 5000;   // request header must be complete by then
static constexpr uint32_t WS_IDLE_TIMEOUT_MS = 30000;  // the UI pings every 10 s
static constexpr uint16_t WS_MAX_TEXT_LEN = 255;     // longest message accepted from a client

static constexpr uint8_t WS_OP_TEXT = 0x1;
static constexpr uint8_t WS_OP_CLOSE = 0x8;
static constexpr uint8_t WS_OP_PING = 0x9;
static constexpr uint8_t WS_OP_PONG = 0xA;

static const char WS_GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// Value of header `name` (case-insensitive) in the request, or false
static bool findHeader(const char *req, const char *name, char *out, size_t outLen) {
  size_t nameLen = strlen(name);
  for (const char *line = strstr(req, "\r\n"); line != nullptr; line = strstr(line, "\r\n")) {
    line += 2;
    if (strncasecmp(line, name, nameLen) == 0 && line[nameLen] == ':') {
      const char *v = line + nameLen + 1;
      while (*v == ' ') v++;
      size_t n = 0;
      while (v[n] != '\r' && v[n] != '\0' && n + 1 < outLen) {
        out[n] = v[n];
        n++;
      }
      out[n] = '\0';
      return true;
    }
  }
  return false;
}

bool WebUi::begin(const char *ssid, const char *password, bool captivePortal) {
  _captivePortal = captivePortal;
  if (password == nullptr || strlen(password) < 8) {
    log_e("Wi-Fi AP password too short (WPA2 needs at least 8 characters)");
    return false;
  }
  WiFi.mode(WIFI_AP);
  if (!WiFi.softAP(ssid, password, 1, 0, MAX_AP_CLIENTS)) {
    log_e("softAP failed");
    return false;
  }
  _dns.setErrorReplyCode(DNSReplyCode::NoError);
  _dns.start(53, "*", WiFi.softAPIP());
  _server.begin();
  _server.setNoDelay(true);
  _running = true;
  return true;
}

void WebUi::loop() {
  if (!_running) {
    return;
  }
  _dns.processNextRequest();
  accept();
  for (uint8_t id = 0; id < MAX_CONNECTIONS; id++) {
    switch (_conn[id].state) {
      case State::Http: handleHttp(id); break;
      case State::WebSocket:
        handleWebSocket(id);
        if (_conn[id].state == State::WebSocket && !flush(_conn[id])) {
          _wsDropped++;
          close(_conn[id]);
        }
        break;
      default: break;
    }
  }
}

void WebUi::accept() {
  NetworkClient client = _server.accept();
  if (!client) {
    return;
  }
  for (Connection &c : _conn) {
    if (c.state == State::Free) {
      c.client = client;
      c.client.setNoDelay(true);
      c.state = State::Http;
      c.len = 0;
      c.lastRxMs = millis();
      return;
    }
  }
  client.stop();  // all slots busy
}

void WebUi::close(Connection &c) {
  c.client.stop();
  c.state = State::Free;
  c.len = 0;
  free(c.tx);
  c.tx = nullptr;
  c.txLen = 0;
}

void WebUi::handleHttp(uint8_t id) {
  Connection &c = _conn[id];
  if (!c.client.connected()) {
    close(c);
    return;
  }
  while (c.client.available() > 0 && c.len < sizeof(c.buf) - 1) {
    int n = c.client.read((uint8_t *)c.buf + c.len, sizeof(c.buf) - 1 - c.len);
    if (n <= 0) break;
    c.len += n;
    c.lastRxMs = millis();
  }
  c.buf[c.len] = '\0';

  if (strstr(c.buf, "\r\n\r\n") == nullptr) {
    if (c.len >= sizeof(c.buf) - 1) {
      c.client.print("HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n");
      close(c);
    } else if (millis() - c.lastRxMs > HTTP_TIMEOUT_MS) {
      close(c);
    }
    return;
  }

  // "GET /path HTTP/1.1"
  char path[64] = "";
  if (strncmp(c.buf, "GET ", 4) == 0) {
    size_t n = 0;
    for (const char *p = c.buf + 4; *p != ' ' && *p != '?' && *p != '\0' && n + 1 < sizeof(path); p++) {
      path[n++] = *p;
    }
    path[n] = '\0';
  }

  char value[64];
  if (strcmp(path, "/ws") == 0 && findHeader(c.buf, "Upgrade", value, sizeof(value)) &&
      strcasecmp(value, "websocket") == 0 &&
      findHeader(c.buf, "Sec-WebSocket-Key", value, sizeof(value))) {
    upgrade(id, value);
  } else if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
    serveIndex(c);
    close(c);
  } else if (!_captivePortal && answerConnectivityCheck(c, path)) {
    close(c);
  } else if (path[0] != '\0') {
    // Captive portal: everything else (OS connectivity checks, typed URLs) leads to the UI
    c.client.printf("HTTP/1.1 302 Found\r\nLocation: http://%s/\r\nContent-Length: 0\r\n"
                    "Connection: close\r\n\r\n",
                    WiFi.softAPIP().toString().c_str());
    close(c);
  } else {
    c.client.print("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    close(c);
  }
}

// The operating systems' "is there internet?" probes, answered as if there were. Otherwise the
// device treats the AP as a captive portal: iOS then opens a sign-in sheet that can only be
// cancelled (which leaves the network), Android shows a "sign in" notification.
bool WebUi::answerConnectivityCheck(Connection &c, const char *path) {
  struct Probe {
    const char *path;
    const char *status;
    const char *type;
    const char *body;
  };
  static const Probe PROBES[] = {
      // Apple (iOS, iPadOS, macOS)
      {"/hotspot-detect.html", "200 OK", "text/html",
       "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"},
      {"/library/test/success.html", "200 OK", "text/html",
       "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"},
      // Android, ChromeOS
      {"/generate_204", "204 No Content", nullptr, nullptr},
      {"/gen_204", "204 No Content", nullptr, nullptr},
      // Windows
      {"/connecttest.txt", "200 OK", "text/plain", "Microsoft Connect Test"},
      {"/ncsi.txt", "200 OK", "text/plain", "Microsoft NCSI"},
      // Firefox
      {"/success.txt", "200 OK", "text/plain", "success\n"},
  };
  for (const Probe &p : PROBES) {
    if (strcmp(path, p.path) == 0) {
      if (p.body == nullptr) {
        c.client.printf("HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", p.status);
      } else {
        c.client.printf("HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %u\r\nCache-Control: no-cache\r\n"
                        "Connection: close\r\n\r\n%s",
                        p.status, p.type, (unsigned)strlen(p.body), p.body);
      }
      return true;
    }
  }
  return false;
}

void WebUi::serveIndex(Connection &c) {
  // Blocking write: a one-time download of a few kB, done before any WebSocket traffic
  c.client.printf("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                  "Content-Encoding: gzip\r\nContent-Length: %u\r\nCache-Control: no-cache\r\n"
                  "Connection: close\r\n\r\n",
                  (unsigned)INDEX_HTML_GZ_LEN);
  c.client.write(INDEX_HTML_GZ, INDEX_HTML_GZ_LEN);
}

void WebUi::upgrade(uint8_t id, const char *key) {
  Connection &c = _conn[id];
  // Sec-WebSocket-Accept = base64(sha1(key + GUID))
  char input[96];
  snprintf(input, sizeof(input), "%s%s", key, WS_GUID);
  uint8_t hash[20];
  mbedtls_sha1((const uint8_t *)input, strlen(input), hash);
  uint8_t accept[32];
  size_t acceptLen = 0;
  mbedtls_base64_encode(accept, sizeof(accept) - 1, &acceptLen, hash, sizeof(hash));
  accept[acceptLen] = '\0';

  c.tx = (uint8_t *)malloc(TX_QUEUE_LEN);
  if (c.tx == nullptr) {
    c.client.print("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    close(c);
    return;
  }
  c.txLen = 0;
  c.client.printf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  "Sec-WebSocket-Accept: %s\r\n\r\n",
                  (const char *)accept);
  c.state = State::WebSocket;
  c.len = 0;
  c.lastRxMs = millis();
  if (_onConnect != nullptr) {
    _onConnect(id);
  }
}

void WebUi::handleWebSocket(uint8_t id) {
  Connection &c = _conn[id];
  if (!c.client.connected() || millis() - c.lastRxMs > WS_IDLE_TIMEOUT_MS) {
    close(c);
    return;
  }
  while (c.client.available() > 0 && c.len < sizeof(c.buf)) {
    int n = c.client.read((uint8_t *)c.buf + c.len, sizeof(c.buf) - c.len);
    if (n <= 0) break;
    c.len += n;
    c.lastRxMs = millis();
  }

  // Client frames are always masked: b0 = FIN|opcode, b1 = MASK|len, [ext len], mask[4], payload
  uint8_t *b = (uint8_t *)c.buf;
  while (c.len >= 2) {
    uint8_t opcode = b[0] & 0x0F;
    uint16_t payloadLen = b[1] & 0x7F;
    uint16_t hdr = 2;
    if (payloadLen == 126) {
      if (c.len < 4) return;
      payloadLen = (b[2] << 8) | b[3];
      hdr = 4;
    } else if (payloadLen == 127 || (b[1] & 0x80) == 0) {
      close(c);  // 64-bit length or unmasked: not from a browser
      return;
    }
    const uint8_t *mask = b + hdr;
    hdr += 4;
    if (hdr + payloadLen > sizeof(c.buf)) {
      close(c);
      return;
    }
    if (c.len < hdr + payloadLen) {
      return;  // wait for the rest
    }
    uint8_t *payload = b + hdr;
    for (uint16_t i = 0; i < payloadLen; i++) {
      payload[i] ^= mask[i % 4];
    }

    if (opcode == WS_OP_TEXT && payloadLen <= WS_MAX_TEXT_LEN) {
      char text[WS_MAX_TEXT_LEN + 1];
      memcpy(text, payload, payloadLen);
      text[payloadLen] = '\0';
      if (_onText != nullptr) {
        _onText(id, text);
      }
    } else if (opcode == WS_OP_PING) {
      sendFrame(c, WS_OP_PONG, payload, payloadLen);
    } else if (opcode == WS_OP_CLOSE) {
      sendFrame(c, WS_OP_CLOSE, nullptr, 0);
      close(c);
      return;
    }
    // Pong, binary and oversized text messages are ignored

    uint16_t frameLen = hdr + payloadLen;
    memmove(b, b + frameLen, c.len - frameLen);
    c.len -= frameLen;
  }
}

bool WebUi::sendFrame(Connection &c, uint8_t opcode, const uint8_t *data, size_t len) {
  uint8_t hdr[4];
  size_t hdrLen = 2;
  hdr[0] = 0x80 | opcode;  // FIN
  if (len < 126) {
    hdr[1] = len;
  } else if (len <= 0xFFFF) {
    hdr[1] = 126;
    hdr[2] = len >> 8;
    hdr[3] = len & 0xFF;
    hdrLen = 4;
  } else {
    return false;
  }
  if (c.tx == nullptr || c.txLen + hdrLen + len > TX_QUEUE_LEN) {
    // Queue full: the client cannot keep up. A dropped frame would break the stream, so close.
    _wsDropped++;
    close(c);
    return false;
  }
  memcpy(c.tx + c.txLen, hdr, hdrLen);
  if (len > 0) memcpy(c.tx + c.txLen + hdrLen, data, len);
  c.txLen += hdrLen + len;
  if (!flush(c)) {
    _wsDropped++;
    close(c);
    return false;
  }
  return true;
}

// Sends as much of the queue as the socket takes without blocking. False on a socket error.
bool WebUi::flush(Connection &c) {
  if (c.txLen == 0) return true;
  int fd = c.client.fd();
  if (fd < 0) return false;
  int n = send(fd, c.tx, c.txLen, MSG_DONTWAIT);
  if (n < 0) {
    return errno == EAGAIN || errno == EWOULDBLOCK;  // send buffer full: try again next loop
  }
  memmove(c.tx, c.tx + n, c.txLen - n);
  c.txLen -= n;
  return true;
}

size_t WebUi::txFree(uint8_t id) const {
  if (!isWebSocket(id) || _conn[id].tx == nullptr) return 0;
  return TX_QUEUE_LEN - _conn[id].txLen;
}

bool WebUi::sendTo(uint8_t id, const char *text) {
  if (id >= MAX_CONNECTIONS || _conn[id].state != State::WebSocket) {
    return false;
  }
  return sendFrame(_conn[id], WS_OP_TEXT, (const uint8_t *)text, strlen(text));
}

void WebUi::broadcast(const char *text) {
  for (uint8_t id = 0; id < MAX_CONNECTIONS; id++) {
    sendTo(id, text);
  }
}

uint8_t WebUi::wsClients() const {
  uint8_t n = 0;
  for (const Connection &c : _conn) {
    if (c.state == State::WebSocket) n++;
  }
  return n;
}

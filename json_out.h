// Minimal JSON writer into a fixed buffer (no heap). Writes past the end are dropped and
// flagged, so a too-small buffer gives a truncated (and detectable) message, never an overflow.

#pragma once

#include <Arduino.h>
#include <stdarg.h>

class JsonOut {
public:
  JsonOut(char *buf, size_t size) : _buf(buf), _size(size) { _buf[0] = '\0'; }

  // printf-style raw text
  JsonOut &raw(const char *fmt, ...) __attribute__((format(printf, 2, 3))) {
    if (_pos >= _size) return *this;
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(_buf + _pos, _size - _pos, fmt, args);
    va_end(args);
    if (n < 0 || _pos + n >= _size) {
      _pos = _size;
      _buf[_size - 1] = '\0';
    } else {
      _pos += n;
    }
    return *this;
  }

  // A JSON string: quotes and backslashes escaped, control characters dropped
  JsonOut &str(const char *s) {
    put('"');
    for (; *s != '\0'; s++) {
      if (*s == '"' || *s == '\\') put('\\');
      if ((uint8_t)*s >= 0x20) put(*s);
    }
    put('"');
    return *this;
  }

  JsonOut &mac(const uint8_t *m) {
    return raw("\"%02x:%02x:%02x:%02x:%02x:%02x\"", m[0], m[1], m[2], m[3], m[4], m[5]);
  }

  JsonOut &hex(const uint8_t *d, size_t n) {
    put('"');
    for (size_t i = 0; i < n; i++) raw("%02x", d[i]);
    put('"');
    return *this;
  }

  // A number with one decimal (voltage, current), e.g. 230.5
  JsonOut &num(float v) { return raw("%.1f", v); }

  JsonOut &boolean(bool b) { return raw(b ? "true" : "false"); }

  bool truncated() const { return _pos >= _size; }
  size_t length() const { return _pos; }
  const char *c_str() const { return _buf; }

private:
  void put(char c) {
    if (_pos + 1 < _size) {
      _buf[_pos++] = c;
      _buf[_pos] = '\0';
    } else {
      _pos = _size;
    }
  }

  char *_buf;
  size_t _size;
  size_t _pos = 0;
};

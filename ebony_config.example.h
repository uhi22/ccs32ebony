// ccs32ebony configuration template.
//
// Copy this file to ebony_config.h and adapt it. ebony_config.h is not committed (.gitignore), so local
// settings and passwords stay private. Without an ebony_config.h, the sketch builds with these defaults.

#pragma once

// Serial log
#define SERIAL_BAUD 115200

// Wi-Fi access point. WPA2 needs a password of at least 8 characters; a shorter or empty one is
// refused at runtime (no access point). Set your own in ebony_config.h.
#define WIFI_AP_SSID     "ccs32ebony"
#define WIFI_AP_PASSWORD ""

// 0: answer the tablets' "is there internet?" checks positively. The tablet joins without a
//    sign-in sheet; open http://192.168.4.1/ in the browser (or as a home-screen icon).
// 1: captive portal - the UI pops up after joining, but iOS shows it in a sign-in sheet that
//    can only be cancelled, which leaves the network.
#define WIFI_CAPTIVE_PORTAL 0

// Sniffer passive test mode at start (diagnostic, LocalModem::setPassive): 1 = the sniffer's ping-pong is held
// disarmed from power-on - it joins but catches no V2G. Only for diagnostic runs (qca7000-transparency
// plans/plan-alpitronic-abort.md, matrix item 3). 0 = normal sniffing (default); the Sniffer tab can switch it.
#define SNIFFER_PASSIVE_DEFAULT 0

# TLS JA4 Gatekeeper

A C++ TLS ClientHello fingerprinting and rule-based traffic analysis tool that parses real TLS handshake traffic, generates JA4-style fingerprints, and applies policy decisions such as `ALLOW`, `BLOCK`, and `RATE_LIMIT`.

This project focuses on **early-stage encrypted traffic identification** by analyzing the TLS **ClientHello** message before application-layer data is available. It supports offline pcap analysis, structured JSON/CSV export, and an experimental live capture mode.

---

## Project Overview

Modern WAF, anti-bot, and zero-trust traffic filtering systems increasingly rely on **TLS fingerprinting** to identify clients early in the connection lifecycle. Even when attackers rotate IPs or spoof HTTP headers, many tools and automated clients still expose recognizable patterns in their TLS handshake behavior.

This project implements a lightweight prototype of that idea in C++.

Given a pcap file or live traffic source, the tool:

1. detects TLS ClientHello packets
2. extracts key handshake metadata
3. generates a **JA4-style fingerprint**
4. compares the fingerprint against a rule file
5. outputs a decision, reason, and risk level

---

## Features

- Parse real TLS ClientHello packets from offline `.pcap` traffic
- Extract:
  - TLS version
  - SNI
  - ALPN
  - cipher suites
  - extensions
  - signature algorithms
- Generate **JA4-style TLS fingerprints**
- Apply rule-based decisions with:
  - action
  - reason
  - risk level
- Human-readable terminal output
- JSON export
- CSV export
- IPv4 and IPv6 support
- Experimental live capture mode using libpcap

---

## Why This Project Matters

This project is inspired by the same general detection direction used in modern:

- bot mitigation systems
- WAF platforms
- DDoS / abuse prevention systems
- zero-trust traffic inspection pipelines

Instead of waiting for full application-layer behavior, the system attempts to classify traffic **at the TLS handshake stage**, which is useful for early filtering and policy evaluation.

---

## Architecture

```text
Traffic Source
   |
   +--> Offline pcap file
   |       |
   |       v
   |   Packet parsing
   |
   +--> Live interface capture
           |
           v
      Packet parsing
           |
           v
   Ethernet / IPv4 / IPv6 / TCP
           |
           v
      TLS ClientHello detection
           |
           v
   Handshake field extraction
           |
           v
   JA4-style fingerprint generation
           |
           v
      Rule engine lookup
           |
           v
   Action + Reason + Risk Level
           |
           +--> Text output
           +--> JSON output
           +--> CSV export
```

## Current Rule Model

Rules are stored in `rules/fingerprints.txt`.

Supported format:

```text
ACTION FINGERPRINT REASON RISK_LEVEL
```

## Example:

```text
BLOCK t13d4907h2_0d8feac7bc37_c301dbdb3ef2 Known_blocked_browser_fingerprint High
ALLOW t13d0506h2_c96ac5133cd7_7e881129b111 Known_safe_test_fingerprint Low
RATE_LIMIT t13d9999h2_aaaaaaaaaaaa_bbbbbbbbbbbb Suspicious_automation_pattern Medium
```
If a fingerprint does not match any rule, the default decision is:
- ALLOW
- reason: No matching rule
- risk level: Low

## JA4-Style Fingerprint Format

This implementation produces a JA4-style fingerprint string in the form:

```a_b_c```

Example:
```text
t13d4907h2_0d8feac7bc37_c301dbdb3ef2
```

Interpretation:
- t = TLS over TCP
- 13 = TLS 1.3
- d = SNI present
- 49 = cipher count
- 07 = extension count
- h2 = ALPN indicates HTTP/2
- second part = hash of normalized cipher list
- third part = hash of normalized extension/signature algorithm data

This is a JA4-style educational / prototype implementation, not a complete production JA4 library.

## Project Structure
```text
tls_ja4_gatekeeper/
├── build/
├── include/
│   ├── ja4.h
│   ├── rules.h
│   └── tls_parser.h
├── rules/
│   └── fingerprints.txt
├── samples/
│   ├── real_tls.pcap
│   └── test.pcap
├── src/
│   ├── ja4.cpp
│   ├── main.cpp
│   ├── rules.cpp
│   └── tls_parser.cpp
├── demo_output.json
├── demo_text_output.txt
├── results.csv
├── live_capture_success_example.txt
└── CMakeLists.txt
```
## Build Requirements
- macOS or Linux
- CMake
- C++17 compiler
- libpcap
- OpenSSL

## macOS (Homebrew)
```text
brew update
brew install cmake pkg-config libpcap openssl
```
## Build Instructions
```text
mkdir build
cd build
cmake ..
make
```

If build succeeds, the executable will be:
```text
./tls_gatekeeper
```

## Usage
### 1. Human-readable offline analysis
```./build/tls_gatekeeper samples/real_tls.pcap```

Example output:
```text
Connection #1
-------------
Src IP: 2603:8000:bc01:ba82:58d9:e938:39ed:d529
Src Port: 63384
Dst IP: 2606:4700::6812:1a78
Dst Port: 443
TLS Version: 13
SNI Present: Yes
Server Name: example.com
ALPN: h2
Cipher Count: 49
Extension Count: 7
Signature Algorithm Count: 11
JA4: t13d4907h2_0d8feac7bc37_c301dbdb3ef2
Decision: BLOCK
Rule Reason: Known_blocked_browser_fingerprint
Risk Level: High
```

### 2. JSON output
```./build/tls_gatekeeper --json samples/real_tls.pcap```

Example output:
```text
[
  {
    "src_ip": "2603:8000:bc01:ba82:58d9:e938:39ed:d529",
    "src_port": 63384,
    "dst_ip": "2606:4700::6812:1a78",
    "dst_port": 443,
    "tls_version": "13",
    "has_sni": true,
    "server_name": "example.com",
    "alpn": "h2",
    "cipher_count": 49,
    "extension_count": 7,
    "signature_algorithm_count": 11,
    "ja4": "t13d4907h2_0d8feac7bc37_c301dbdb3ef2",
    "decision": "BLOCK",
    "rule_reason": "Known_blocked_browser_fingerprint",
    "risk_level": "High"
  }
]
```

### 3. CSV export
```./build/tls_gatekeeper samples/real_tls.pcap --csv results.csv```

Example CSV content:
```text
src_ip,src_port,dst_ip,dst_port,tls_version,has_sni,server_name,alpn,cipher_count,extension_count,signature_algorithm_count,ja4,decision,rule_reason,risk_level
2603:8000:bc01:ba82:58d9:e938:39ed:d529,63384,2606:4700::6812:1a78,443,13,true,example.com,h2,49,7,11,t13d4907h2_0d8feac7bc37_c301dbdb3ef2,BLOCK,Known_blocked_browser_fingerprint,High
```
### 4. Experimental live capture
```sudo ./build/tls_gatekeeper --live en0```

or:

```sudo ./build/tls_gatekeeper --live any```

A successful live capture may look like:

```text
[+] Live capture started on interface: en0
[+] Waiting for TLS ClientHello packets...
[+] ClientHello captured in live mode.

Connection #1
-------------
Src IP: 2603:8000:bc01:ba82:58d9:e938:39ed:d529
Src Port: 64020
Dst IP: 2620:1ec:46::69
Dst Port: 443
TLS Version: 13
SNI Present: Yes
Server Name: update.code.visualstudio.com
ALPN: h2
Cipher Count: 16
Extension Count: 19
Signature Algorithm Count: 8
JA4: t13d1517h2_8daaf6152771_9f57a497f507
Decision: ALLOW
Rule Reason: No matching rule
Risk Level: Low
```

To reliably trigger a fresh TLS handshake during live testing:
```text
openssl s_client -connect example.com:443 -servername example.com </dev/null
```
## Demo Files

The project includes stable demo artifacts generated from real traffic:
- demo_text_output.txt
- demo_output.json
- results.csv

These demonstrate the same parsed connection from multiple output formats.

## Implementation Notes
### Offline parsing

The parser currently processes Ethernet + TCP traffic and supports both:
- IPv4
- IPv6

It extracts ClientHello metadata from TLS handshake records and then computes a JA4-style fingerprint.

### Rule engine
The rule engine maps fingerprints to:

- action
- reason
- risk level

### Live capture
The live mode uses libpcap and is intended as an experimental real-time demonstration feature.

## Limitations

This project is a prototype and has several important limitations:

- It does not implement full TCP stream reassembly
- It may miss ClientHello messages that span multiple TCP segments
- Live capture mode is best-effort and not guaranteed to catch every handshake
- It focuses on detection and decisioning, not kernel-level blocking
- JA4 generation is JA4-style, not a complete production-grade JA4 implementation
- IPv6 extension header handling is basic, not exhaustive
- It does not yet support QUIC / HTTP/3 fingerprinting

## Future Work

Planned or possible next steps:

- full TCP stream reassembly
- more robust live capture correlation
- QUIC / HTTP/3 support
- richer rule format with tags and categories
- active enforcement mode
    - proxy-based blocking
    - firewall integration
- batch processing of multiple pcap files
- improved reporting and analytics dashboards

## Resume-Style Summary

Built a C++ TLS traffic analysis tool that parses ClientHello packets from offline pcap and experimental live traffic, generates JA4-style fingerprints, and applies rule-based security decisions with IPv4/IPv6 support and text, JSON, and CSV output modes.

## Status
- Offline pcap analysis: stable
- JSON / CSV export: stable
- Rule-based action / reason / severity output: stable
- Live capture mode: experimental
# 🔍 DPI Engine — Deep Packet Inspection in Java

![Java](https://img.shields.io/badge/Java-21+-orange?style=flat-square&logo=openjdk)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Threads](https://img.shields.io/badge/Multi--threaded-Pipeline-green?style=flat-square)
![Protocol](https://img.shields.io/badge/Protocol-TLS%20%7C%20HTTP%20%7C%20DNS-purple?style=flat-square)

A multi-threaded network traffic analyzer that reads `.pcap` capture files, **identifies which apps generated the traffic** (YouTube, TikTok, Netflix, etc.), and can block traffic by app, domain, or IP — all without any external libraries.

The core insight: even though HTTPS is encrypted, the destination domain leaks in **plaintext** during the TLS handshake inside a field called the **SNI (Server Name Indication)**. This engine extracts that field from every packet using byte-level protocol parsing.

> This is how real ISP firewalls, parental controls, and enterprise network filters actually work.

---

## Demo

```
╔══════════════════════════════════════════════════════════════╗
║          DPI ENGINE v2.0  —  Java Multi-threaded             ║
║  Load Balancers: 2      Fast Paths: 4      Total FPs: 8      ║
╚══════════════════════════════════════════════════════════════╝

[BLOCKED] 192.168.1.100  →  142.250.185.110   YouTube   (www.youtube.com)

╔══════════════════════════════════════════════════════════════╗
║                    APPLICATION BREAKDOWN                      ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS              39   50.6% ############                   ║
║ Unknown            16   20.8% #####                          ║
║ DNS                 4    5.2% #                              ║
║ YouTube             1    1.3%  [BLOCKED]                     ║
║ Netflix             1    1.3%                                ║
║ TikTok              1    1.3%                                ║
║ Facebook            1    1.3%                                ║
╠══════════════════════════════════════════════════════════════╣
║                   DETECTED DOMAINS / SNIs                    ║
╠══════════════════════════════════════════════════════════════╣
║  www.youtube.com               →  YouTube                    ║
║  www.netflix.com               →  Netflix                    ║
║  www.tiktok.com                →  TikTok                     ║
║  www.facebook.com              →  Facebook                   ║
║  github.com                    →  GitHub                     ║
║  discord.com                   →  Discord                    ║
║  open.spotify.com              →  Spotify                    ║
╚══════════════════════════════════════════════════════════════╝

Completed in 0.33 seconds.
```

---

## How It Works

When your browser connects to `https://www.youtube.com`, the very first message it sends contains the domain name in **plaintext** — before any encryption begins:

```
TLS Client Hello packet:
  Byte 0:      0x16        → Content Type: Handshake
  Bytes 1-2:   0x0303      → TLS Version 1.2
  Byte 5:      0x01        → Handshake Type: Client Hello
  ...
  Extension:   type=0x0000 → SNI Extension
  Value:       "www.youtube.com"   ← extracted here, plaintext
```

`SniExtractor.java` navigates these raw bytes manually and pulls out the domain name. No libraries. Pure byte arithmetic.

---

## Architecture

Multi-threaded pipeline — packets flow through stages in parallel:

```
                   ┌─────────────────┐
                   │  Reader Thread  │  reads PCAP, parses headers
                   └────────┬────────┘
                            │
             ┌──────────────┴──────────────┐
             ▼                             ▼
   ┌──────────────────┐         ┌──────────────────┐
   │   LoadBalancer 0 │         │   LoadBalancer 1 │   consistent hash
   └────────┬─────────┘         └─────────┬────────┘   on 5-tuple
            │                             │
     ┌──────┴──────┐               ┌──────┴──────┐
     ▼             ▼               ▼             ▼
 ┌────────┐  ┌────────┐       ┌────────┐  ┌────────┐
 │  FP 0  │  │  FP 1  │       │  FP 2  │  │  FP 3  │  DPI + blocking
 └────┬───┘  └────┬───┘       └────┬───┘  └────┬───┘
      └───────────┴───────┬────────┘────────────┘
                          ▼
              ┌───────────────────────┐
              │   Output Writer       │  writes filtered PCAP
              └───────────────────────┘
```

**Why consistent hashing?** All packets from the same TCP connection must go to the same FastPath thread so flow state (SNI, app type, blocked?) stays consistent. The hash is computed on the 5-tuple: `src_ip + dst_ip + src_port + dst_port + protocol`.

### Key design decisions

| Concept | Implementation |
|---|---|
| Consistent hashing | Same 5-tuple → same FastPath thread, no flow table locking needed |
| Thread-safe queues | `ArrayBlockingQueue` wrapped in `BoundedQueue<T>` with backpressure |
| Lock-free counters | `AtomicLong` for all per-packet stats |
| Rule engine | `ReadWriteLock` — many threads read rules, writes get exclusive access |
| Flow table | `ConcurrentHashMap<FiveTuple, FlowEntry>` — one per FP thread |
| SNI extraction | Manual byte-level TLS Client Hello parsing, zero dependencies |

---

## Project Structure

```
src/main/java/com/dpi/
│
├── Main.java                     ← CLI entry point
│
├── model/                        ← Data classes
│   ├── AppType.java              ← Enum: YouTube, TikTok, Netflix ...
│   ├── FiveTuple.java            ← Connection identity (5 fields)
│   ├── FlowEntry.java            ← Per-connection state
│   ├── PacketJob.java            ← Packet passed between threads
│   ├── ParsedPacket.java         ← Decoded protocol fields
│   └── RawPacket.java            ← Raw bytes from PCAP
│
├── parser/                       ← Protocol parsing (no libraries)
│   ├── PcapReader.java           ← PCAP file format parser
│   ├── PacketParser.java         ← Ethernet → IP → TCP/UDP
│   ├── SniExtractor.java         ← TLS Client Hello → domain name
│   ├── HttpHostExtractor.java    ← HTTP Host header extraction
│   └── DnsExtractor.java         ← DNS query extraction
│
├── engine/                       ← Threading pipeline
│   ├── DpiEngine.java            ← Orchestrator
│   ├── FastPath.java             ← Core DPI worker thread
│   ├── LoadBalancer.java         ← Packet distributor thread
│   └── OutputWriter.java         ← PCAP writer thread
│
├── rules/
│   └── RuleEngine.java           ← Thread-safe blocking rules
│
├── stats/
│   └── DpiStats.java             ← Thread-safe statistics
│
└── util/
    └── BoundedQueue.java         ← Bounded blocking queue
```

---

## Getting Started

### Requirements
- Java 21 or higher ([download here](https://adoptium.net))
- No other dependencies

### Build

**Windows:**
```cmd
.\build-and-run.bat
```

**Linux / macOS:**
```bash
mkdir -p out
find src -name "*.java" | xargs javac -d out
java -cp out com.dpi.Main test_dpi.pcap output.pcap
```

### Run

**Windows (after building once):**
```cmd
.\run.bat input.pcap output.pcap [options]
```

**Linux / macOS:**
```bash
java -cp out com.dpi.Main input.pcap output.pcap [options]
```

---

## Usage Examples

```cmd
# Analyze traffic — no blocking
.\run.bat capture.pcap output.pcap

# Block YouTube
.\run.bat capture.pcap output.pcap --block-app YouTube

# Block multiple apps
.\run.bat capture.pcap output.pcap --block-app YouTube --block-app TikTok --block-app Facebook

# Block by source IP address
.\run.bat capture.pcap output.pcap --block-ip 192.168.1.50

# Block any domain containing a keyword
.\run.bat capture.pcap output.pcap --block-domain instagram

# High performance mode (more threads)
.\run.bat capture.pcap output.pcap --lbs 4 --fps 8
```

### All supported apps

`YouTube` `Facebook` `Instagram` `WhatsApp` `Twitter` `Netflix` `Amazon`
`Microsoft` `Apple` `Telegram` `TikTok` `Spotify` `Zoom` `Discord`
`GitHub` `Cloudflare` `Google`

---

## Capture Your Own Traffic

To run the engine on real traffic instead of the test file:

1. Install [Wireshark](https://www.wireshark.org/download.html)
2. Open Wireshark → select **Wi-Fi**
3. Click the blue **▶ Start** button
4. Browse any websites for 30 seconds
5. Click the red **■ Stop** button
6. **File → Save As** → format: `Wireshark/tcpdump - pcap` → save as `my_capture.pcap`
7. Run:
```cmd
.\run.bat my_capture.pcap output.pcap
```

The engine will show every domain extracted from your own encrypted traffic.

---

## What the Output Files Mean

| File | Description |
|---|---|
| `output.pcap` | Filtered traffic — only packets that passed your rules. Open in Wireshark. |
| Terminal report | Application breakdown, thread statistics, detected domains |

To inspect `output.pcap` in Wireshark: type `tls` in the filter bar → click any packet → expand **Transport Layer Security** → find the SNI field.

---

## Concepts Used

| Concept | Where |
|---|---|
| Network protocols (Ethernet, IP, TCP, TLS) | `PacketParser.java`, `SniExtractor.java` |
| Multi-threading & concurrent data structures | `DpiEngine.java`, `FastPath.java`, `BoundedQueue.java` |
| Producer-consumer pattern | All queue handoffs between threads |
| Consistent hashing | `LoadBalancer.java` |
| Atomic operations & memory visibility | `DpiStats.java`, `FlowEntry.java` |
| Binary file I/O | `PcapReader.java`, `OutputWriter.java` |

---

## License

MIT — free to use, modify, and distribute.
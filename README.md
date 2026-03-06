# DPI Engine — Java

A **Java Deep Packet Inspection (DPI) system** that reads PCAP network capture
files, identifies which applications generated the traffic (YouTube, TikTok,
Facebook, etc.), applies blocking rules, and writes filtered output PCAP files.

---

## What is DPI?

Deep Packet Inspection looks *inside* network packets — not just at the headers
(source/destination IP), but at the payload. The key insight: even though HTTPS
is encrypted, the **target domain name leaks in plaintext** during the TLS
handshake in a field called the **SNI (Server Name Indication)**.

```
Browser → "I want to connect to www.youtube.com" (PLAINTEXT, in TLS Client Hello)
Server  → [sends certificate for youtube.com]
Browser → [encrypted session begins]
```

Our DPI engine captures that `www.youtube.com` before encryption starts.

---

## Architecture

Multi-threaded pipeline for high-throughput processing:

```
                   ┌─────────────────┐
                   │  Reader Thread  │  Reads PCAP, parses headers
                   └────────┬────────┘
                            │ PacketJob
             ┌──────────────┴──────────────┐
             │      hash(5-tuple) % numLBs  │
             ▼                             ▼
   ┌─────────────────┐           ┌─────────────────┐
   │  LB0 Thread     │           │  LB1 Thread     │  Load Balancers:
   │ (Load Balancer) │           │ (Load Balancer) │  distribute packets
   └────────┬────────┘           └────────┬────────┘  to FastPath workers
            │                             │
     ┌──────┴──────┐               ┌──────┴──────┐
     ▼             ▼               ▼             ▼
┌─────────┐ ┌─────────┐     ┌─────────┐ ┌─────────┐
│  FP0    │ │  FP1    │     │  FP2    │ │  FP3    │  FastPaths:
│ Thread  │ │ Thread  │     │ Thread  │ │ Thread  │  DPI + blocking
└────┬────┘ └────┬────┘     └────┬────┘ └────┬────┘
     └──────────────┬────────────┘────────────┘
                    ▼
        ┌───────────────────────┐
        │  Output Writer Thread │  Writes filtered PCAP to disk
        └───────────────────────┘
```

### Key Design Decisions

| Concept | How it's done in Java |
|---|---|
| Consistent hashing | Same 5-tuple → same FastPath thread (no flow table locking) |
| Thread-safe queues | `ArrayBlockingQueue` via `BoundedQueue<T>` wrapper |
| Atomic counters | `AtomicLong` for lock-free packet/byte counting |
| Rule engine | `ReadWriteLock` for concurrent reads, exclusive writes |
| Flow table | `ConcurrentHashMap<FiveTuple, FlowEntry>` per FP thread |
| SNI extraction | Byte-level TLS Client Hello parsing (no external libraries) |

---

## File Structure

```
src/main/java/com/dpi/
├── Main.java                    ← Entry point, CLI arg parsing
│
├── model/
│   ├── AppType.java             ← Enum: YouTube, TikTok, Netflix, etc.
│   ├── FiveTuple.java           ← Connection identifier (src/dst IP+port+proto)
│   ├── FlowEntry.java           ← Per-connection state (SNI, app, blocked?)
│   ├── PacketJob.java           ← Self-contained packet passed between threads
│   ├── ParsedPacket.java        ← Decoded Ethernet/IP/TCP/UDP fields
│   └── RawPacket.java           ← Raw bytes + PCAP metadata
│
├── parser/
│   ├── PcapReader.java          ← Reads PCAP files (handles byte-order)
│   ├── PacketParser.java        ← Decodes Ethernet → IP → TCP/UDP headers
│   ├── SniExtractor.java        ← Extracts SNI from TLS Client Hello
│   ├── HttpHostExtractor.java   ← Extracts Host: header from HTTP requests
│   └── DnsExtractor.java        ← Extracts queried domain from DNS packets
│
├── engine/
│   ├── DpiEngine.java           ← Orchestrator: wires all threads together
│   ├── FastPath.java            ← Core DPI worker (classify + block + forward)
│   ├── LoadBalancer.java        ← Distributes packets to FastPath workers
│   └── OutputWriter.java        ← Writes allowed packets to output PCAP
│
├── rules/
│   └── RuleEngine.java          ← Thread-safe: IP / app / domain blocking rules
│
├── stats/
│   └── DpiStats.java            ← Thread-safe stats (AtomicLong, ConcurrentHashMap)
│
├── util/
│   └── BoundedQueue.java        ← Bounded blocking queue (wraps ArrayBlockingQueue)
│
└── cli/
    └── ReportPrinter.java       ← ASCII box-drawing report printer
```

---

## Building

**Requirements:** Java 21+, Maven 3.8+

```bash
# Compile and package
mvn package

# Run
java -jar target/dpi-engine.jar <input.pcap> <output.pcap> [options]
```

**Or compile manually without Maven:**
```bash
# Create output directory
mkdir -p out

# Compile all sources
find src -name "*.java" | xargs javac --release 21 -d out

# Run directly
java -cp out com.dpi.Main input.pcap output.pcap
```

---

## Usage

```bash
# Basic — just classify, no blocking
java -jar dpi-engine.jar capture.pcap output.pcap

# Block YouTube and TikTok
java -jar dpi-engine.jar capture.pcap output.pcap \
  --block-app YouTube \
  --block-app TikTok

# Block by source IP
java -jar dpi-engine.jar capture.pcap output.pcap \
  --block-ip 192.168.1.50

# Block by domain substring (matches any SNI containing "facebook")
java -jar dpi-engine.jar capture.pcap output.pcap \
  --block-domain facebook

# High performance: 4 LBs × 8 FastPath threads
java -jar dpi-engine.jar large.pcap output.pcap --lbs 4 --fps 8
```

### Supported `--block-app` values
`YouTube` `Facebook` `Instagram` `WhatsApp` `Twitter` `Netflix`
`Amazon` `Microsoft` `Apple` `Telegram` `TikTok` `Spotify` `Zoom`
`Discord` `GitHub` `Cloudflare` `Google`

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║          DPI ENGINE v2.0  —  Java Multi-threaded             ║
║  Load Balancers: 2     Fast Paths: 4     Total FPs: 8        ║
╚══════════════════════════════════════════════════════════════╝

[BLOCKED] 192.168.1.100   → 172.217.14.206  YouTube      (www.youtube.com)
[BLOCKED] 192.168.1.100   → 31.13.72.36     Facebook     (www.facebook.com)

╔══════════════════════════════════════════════════════════════╗
║         DPI ENGINE v2.0 (Java Multi-threaded)                ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:                            2                 ║
║ Fast Path Workers:                         4                 ║
║ Total Threads:                             8                 ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                            77                 ║
║ Total Bytes:                            5738                 ║
║ TCP Packets:                              73                 ║
║ UDP Packets:                               4                 ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                                61                 ║
║ Dropped:                                  16                 ║
║ Drop Rate:                             20.8%                 ║
╠══════════════════════════════════════════════════════════════╣
║               APPLICATION BREAKDOWN                          ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS            39  50.6% ##########                        ║
║ Unknown          16  20.8% ####                              ║
║ YouTube           4   5.2% # (BLOCKED)                       ║
║ DNS               4   5.2% #                                 ║
║ Facebook          3   3.9%                                   ║
╠══════════════════════════════════════════════════════════════╣
║               DETECTED DOMAINS / SNIs                        ║
╠══════════════════════════════════════════════════════════════╣
║ github.com                         → GitHub                  ║
║ www.facebook.com                   → Facebook                ║
║ www.google.com                     → Google                  ║
║ www.youtube.com                    → YouTube                 ║
╚══════════════════════════════════════════════════════════════╝

Completed in 0.18 seconds.
Output written to: output.pcap
```

---

## How SNI Extraction Works

When you visit `https://www.youtube.com`, your browser sends a **TLS Client Hello**:

```
Byte 0:     0x16  (Content Type: Handshake)
Bytes 1-2:  0x0303 (TLS 1.2)
Byte 5:     0x01  (Handshake Type: Client Hello)
...
Extensions:
  Type: 0x0000 (SNI)
  Value: "www.youtube.com"  ← plaintext, before encryption
```

`SniExtractor.java` navigates these bytes manually — no libraries, pure Java.
The same technique is used by real ISP firewalls and parental controls.

---

## Differences from the C++ Original

| Aspect | C++ Original | Java Version |
|---|---|---|
| Unsigned types | `uint8_t`, `uint32_t` | `& 0xFF`, `& 0xFFFFFFFFL` masking |
| Thread queues | Custom `TSQueue<T>` | `ArrayBlockingQueue` wrapper |
| Build | `g++` / CMake | Maven |
| Memory | Manual control | JVM / GC managed |
| Performance | Faster (no JVM overhead) | Slightly slower, easier to deploy |
| Portability | Linux/macOS | Any JVM platform |

The core algorithms (byte parsing, SNI extraction, consistent hashing,
flow tracking) are identical in logic.

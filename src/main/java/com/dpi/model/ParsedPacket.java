package com.dpi.model;

/**
 * A packet after protocol header parsing.
 * Contains decoded fields from Ethernet, IP, TCP/UDP headers.
 */
public class ParsedPacket {

    // Timing
    public long tsSec;
    public long tsUsec;

    // Ethernet
    public String srcMac;
    public String dstMac;
    public int    etherType;  // 0x0800 = IPv4

    // IP
    public boolean hasIp;
    public int     ipVersion;
    public int     ttl;
    public int     protocol;   // 6=TCP, 17=UDP, 1=ICMP
    public long    srcIp;      // Unsigned 32-bit stored as long
    public long    dstIp;
    public String  srcIpStr;
    public String  dstIpStr;

    // TCP
    public boolean hasTcp;
    public int     srcPort;
    public int     dstPort;
    public long    seqNumber;
    public long    ackNumber;
    public int     tcpFlags;

    // UDP
    public boolean hasUdp;
    // srcPort/dstPort reused

    // Payload
    public int payloadOffset;  // Byte offset into raw.data where payload starts
    public int payloadLength;

    public boolean isTcp() { return hasTcp; }
    public boolean isUdp() { return hasUdp; }

    /** Build a FiveTuple from this parsed packet. */
    public FiveTuple toFiveTuple() {
        return new FiveTuple(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    public String tcpFlagsString() {
        if (!hasTcp) return "";
        StringBuilder sb = new StringBuilder();
        if ((tcpFlags & 0x02) != 0) sb.append("SYN ");
        if ((tcpFlags & 0x10) != 0) sb.append("ACK ");
        if ((tcpFlags & 0x01) != 0) sb.append("FIN ");
        if ((tcpFlags & 0x04) != 0) sb.append("RST ");
        if ((tcpFlags & 0x08) != 0) sb.append("PSH ");
        if ((tcpFlags & 0x20) != 0) sb.append("URG ");
        return sb.toString().trim();
    }
}

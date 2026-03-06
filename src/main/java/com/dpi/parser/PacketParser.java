package com.dpi.parser;

import com.dpi.model.ParsedPacket;
import com.dpi.model.RawPacket;

/**
 * Parses raw Ethernet frame bytes into a {@link ParsedPacket}.
 *
 * Packet structure (nested headers):
 * ┌──────────────────────────────────────────────────────────────────┐
 * │ Ethernet Header (14 bytes)                                       │
 * │ ┌──────────────────────────────────────────────────────────────┐ │
 * │ │ IP Header (20+ bytes)                                        │ │
 * │ │ ┌──────────────────────────────────────────────────────────┐ │ │
 * │ │ │ TCP/UDP Header                                           │ │ │
 * │ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
 * │ │ │ │ Payload (TLS Client Hello, HTTP request, DNS, etc.)  │ │ │ │
 * │ │ │ └──────────────────────────────────────────────────────┘ │ │ │
 * │ │ └──────────────────────────────────────────────────────────┘ │ │
 * │ └──────────────────────────────────────────────────────────────┘ │
 * └──────────────────────────────────────────────────────────────────┘
 *
 * All multi-byte fields in network packets are big-endian.
 * Java bytes are signed (-128..127); use & 0xFF to get 0..255.
 */
public class PacketParser {

    // EtherType values
    private static final int ETHER_TYPE_IPV4 = 0x0800;

    // IP protocol numbers
    private static final int PROTO_ICMP = 1;
    private static final int PROTO_TCP  = 6;
    private static final int PROTO_UDP  = 17;

    // Header sizes
    private static final int ETH_HEADER_LEN     = 14;
    private static final int MIN_IP_HEADER_LEN  = 20;
    private static final int MIN_TCP_HEADER_LEN = 20;
    private static final int UDP_HEADER_LEN      = 8;

    /**
     * Parse a raw packet into its protocol fields.
     *
     * @return null if the packet cannot be parsed (too short, unsupported type)
     */
    public static ParsedPacket parse(RawPacket raw) {
        byte[] data = raw.data;
        if (data == null || data.length < ETH_HEADER_LEN) return null;

        ParsedPacket pkt = new ParsedPacket();
        pkt.tsSec  = raw.tsSec;
        pkt.tsUsec = raw.tsUsec;

        int offset = 0;

        // ── Ethernet header ──────────────────────────────────────────────────
        pkt.dstMac    = macToString(data, 0);
        pkt.srcMac    = macToString(data, 6);
        pkt.etherType = readUint16(data, 12);
        offset = ETH_HEADER_LEN;

        if (pkt.etherType != ETHER_TYPE_IPV4) return null; // Only IPv4 supported

        // ── IPv4 header ──────────────────────────────────────────────────────
        if (data.length < offset + MIN_IP_HEADER_LEN) return null;

        int versionIhl   = data[offset] & 0xFF;
        pkt.ipVersion    = (versionIhl >> 4) & 0x0F;
        int ihl          = versionIhl & 0x0F;          // Header length in 32-bit words
        int ipHeaderLen  = ihl * 4;

        if (pkt.ipVersion != 4) return null;
        if (ipHeaderLen < MIN_IP_HEADER_LEN) return null;
        if (data.length < offset + ipHeaderLen) return null;

        pkt.ttl      = data[offset + 8]  & 0xFF;
        pkt.protocol = data[offset + 9]  & 0xFF;

        // Source IP (4 bytes at offset+12), big-endian → unsigned long
        pkt.srcIp    = readUint32(data, offset + 12);
        pkt.dstIp    = readUint32(data, offset + 16);
        pkt.srcIpStr = ipToString(pkt.srcIp);
        pkt.dstIpStr = ipToString(pkt.dstIp);
        pkt.hasIp    = true;
        offset      += ipHeaderLen;

        // ── TCP header ────────────────────────────────────────────────────────
        if (pkt.protocol == PROTO_TCP) {
            if (data.length < offset + MIN_TCP_HEADER_LEN) return null;

            pkt.srcPort   = readUint16(data, offset);
            pkt.dstPort   = readUint16(data, offset + 2);
            pkt.seqNumber = readUint32(data, offset + 4);
            pkt.ackNumber = readUint32(data, offset + 8);

            int dataOffset  = (data[offset + 12] & 0xFF) >> 4;   // upper 4 bits
            int tcpHdrLen   = dataOffset * 4;

            pkt.tcpFlags = data[offset + 13] & 0xFF;

            if (tcpHdrLen < MIN_TCP_HEADER_LEN || data.length < offset + tcpHdrLen) return null;

            pkt.hasTcp        = true;
            offset           += tcpHdrLen;

        // ── UDP header ────────────────────────────────────────────────────────
        } else if (pkt.protocol == PROTO_UDP) {
            if (data.length < offset + UDP_HEADER_LEN) return null;

            pkt.srcPort = readUint16(data, offset);
            pkt.dstPort = readUint16(data, offset + 2);

            pkt.hasUdp  = true;
            offset     += UDP_HEADER_LEN;
        }

        pkt.payloadOffset = offset;
        pkt.payloadLength = data.length - offset;

        return pkt;
    }

    // ── Byte-reading helpers ──────────────────────────────────────────────────

    /** Read a big-endian unsigned 16-bit value from buf[offset..offset+1]. */
    public static int readUint16(byte[] buf, int offset) {
        return ((buf[offset] & 0xFF) << 8) | (buf[offset + 1] & 0xFF);
    }

    /** Read a big-endian unsigned 24-bit value from buf[offset..offset+2]. */
    public static int readUint24(byte[] buf, int offset) {
        return ((buf[offset]     & 0xFF) << 16) |
               ((buf[offset + 1] & 0xFF) <<  8) |
                (buf[offset + 2] & 0xFF);
    }

    /** Read a big-endian unsigned 32-bit value, returned as long to avoid sign issues. */
    public static long readUint32(byte[] buf, int offset) {
        return (((long)(buf[offset]     & 0xFF)) << 24) |
               (((long)(buf[offset + 1] & 0xFF)) << 16) |
               (((long)(buf[offset + 2] & 0xFF)) <<  8) |
                ((long)(buf[offset + 3] & 0xFF));
    }

    // ── Formatting helpers ────────────────────────────────────────────────────

    private static String macToString(byte[] data, int offset) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
            data[offset]     & 0xFF, data[offset + 1] & 0xFF,
            data[offset + 2] & 0xFF, data[offset + 3] & 0xFF,
            data[offset + 4] & 0xFF, data[offset + 5] & 0xFF);
    }

    public static String ipToString(long ip) {
        return ((ip >> 24) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "." +
               ((ip >>  8) & 0xFF) + "." +  (ip        & 0xFF);
    }
}

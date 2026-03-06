package com.dpi.model;

import java.util.Objects;

/**
 * A network flow's unique 5-tuple identifier.
 * All packets sharing the same 5-tuple belong to the same connection.
 *
 * Fields are stored as Java ints/longs using unsigned interpretation.
 * Use Integer.toUnsignedLong() when comparing or formatting.
 */
public final class FiveTuple {

    public final long srcIp;   // stored as unsigned 32-bit (use long)
    public final long dstIp;
    public final int  srcPort; // 0–65535
    public final int  dstPort;
    public final int  protocol; // 6=TCP, 17=UDP

    public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp    = srcIp;
        this.dstIp    = dstIp;
        this.srcPort  = srcPort;
        this.dstPort  = dstPort;
        this.protocol = protocol;
    }

    public String srcIpString() { return ipToString(srcIp); }
    public String dstIpString() { return ipToString(dstIp); }

    public static String ipToString(long ip) {
        return ((ip >> 24) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >>  8) & 0xFF) + "." +
               ( ip        & 0xFF);
    }

    public String protocolString() {
        return switch (protocol) {
            case 6  -> "TCP";
            case 17 -> "UDP";
            case 1  -> "ICMP";
            default -> "PROTO(" + protocol + ")";
        };
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple t)) return false;
        return srcIp == t.srcIp && dstIp == t.dstIp &&
               srcPort == t.srcPort && dstPort == t.dstPort &&
               protocol == t.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        return srcIpString() + ":" + srcPort + " -> " +
               dstIpString()  + ":" + dstPort + " (" + protocolString() + ")";
    }
}

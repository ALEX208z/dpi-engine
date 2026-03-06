package com.dpi.model;

/**
 * A self-contained packet job passed between pipeline threads.
 *
 * Carries both the raw bytes (needed to write to output) and the parsed
 * fields (needed for DPI processing). Using a value object avoids shared
 * mutable state between threads.
 */
public class PacketJob {

    public final int    id;
    public final long   tsSec;
    public final long   tsUsec;
    public final byte[] data;        // Full raw Ethernet frame
    public final int    originalLen;

    // Parsed fields (populated by PacketParser before queuing)
    public final FiveTuple tuple;
    public final int        payloadOffset;
    public final int        payloadLength;
    public final int        protocol;   // 6=TCP, 17=UDP

    public PacketJob(int id, RawPacket raw, ParsedPacket parsed) {
        this.id            = id;
        this.tsSec         = raw.tsSec;
        this.tsUsec        = raw.tsUsec;
        this.data          = raw.data;
        this.originalLen   = raw.originalLen;
        this.tuple         = parsed.toFiveTuple();
        this.payloadOffset = parsed.payloadOffset;
        this.payloadLength = parsed.payloadLength;
        this.protocol      = parsed.protocol;
    }
}

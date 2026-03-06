package com.dpi.model;

/**
 * A raw packet as read directly from a PCAP file.
 * Contains the original byte array and PCAP metadata.
 */
public class RawPacket {
    public long tsSec;      // Timestamp seconds
    public long tsUsec;     // Timestamp microseconds
    public byte[] data;     // Raw packet bytes (Ethernet frame)
    public int originalLen; // Original length before snaplen truncation

    public RawPacket(long tsSec, long tsUsec, byte[] data, int originalLen) {
        this.tsSec       = tsSec;
        this.tsUsec      = tsUsec;
        this.data        = data;
        this.originalLen = originalLen;
    }
}

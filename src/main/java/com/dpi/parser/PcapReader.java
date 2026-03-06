package com.dpi.parser;

import com.dpi.model.RawPacket;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Reads packets from a PCAP (libpcap) capture file.
 *
 * Supports both native and byte-swapped byte orders (little/big endian PCAP).
 *
 * PCAP file format:
 * ┌────────────────────────────┐
 * │ Global Header (24 bytes)   │  magic, version, snaplen, link type
 * ├────────────────────────────┤
 * │ Packet Header (16 bytes)   │  timestamp, incl_len, orig_len
 * │ Packet Data (incl_len)     │
 * ├────────────────────────────┤
 * │ Packet Header + Data ...   │
 * └────────────────────────────┘
 */
public class PcapReader implements Closeable {

    private static final int PCAP_MAGIC_NATIVE  = 0xa1b2c3d4;
    private static final int PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;

    private static final int GLOBAL_HEADER_SIZE = 24;
    private static final int PACKET_HEADER_SIZE = 16;
    private static final int MAX_PACKET_LEN     = 65535;

    private DataInputStream stream;
    private ByteOrder       fileByteOrder;
    private int             snaplen;
    private int             linkType;
    private int             versionMajor;
    private int             versionMinor;

    /**
     * Open a PCAP file and read the global header.
     *
     * @param path path to the .pcap file
     * @throws IOException if file is missing, unreadable, or not a valid PCAP
     */
    public void open(String path) throws IOException {
        stream = new DataInputStream(new BufferedInputStream(new FileInputStream(path), 64 * 1024));

        // Read the 24-byte global header as raw bytes first, then interpret
        byte[] headerBytes = stream.readNBytes(GLOBAL_HEADER_SIZE);
        if (headerBytes.length < GLOBAL_HEADER_SIZE) {
            throw new IOException("File too small to be a PCAP: " + path);
        }

        // Detect byte order from magic number (big-endian read first)
        int magicBE = ByteBuffer.wrap(headerBytes, 0, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        if (magicBE == PCAP_MAGIC_NATIVE) {
            fileByteOrder = ByteOrder.BIG_ENDIAN;
        } else if (magicBE == PCAP_MAGIC_SWAPPED) {
            fileByteOrder = ByteOrder.LITTLE_ENDIAN;
        } else {
            // Try little-endian magic
            int magicLE = ByteBuffer.wrap(headerBytes, 0, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            if (magicLE == PCAP_MAGIC_NATIVE) {
                fileByteOrder = ByteOrder.LITTLE_ENDIAN;
            } else {
                throw new IOException(String.format(
                    "Invalid PCAP magic: 0x%08X (not a PCAP file?)", magicBE));
            }
        }

        ByteBuffer header = ByteBuffer.wrap(headerBytes).order(fileByteOrder);
        header.getInt();                          // skip magic
        versionMajor = header.getShort() & 0xFFFF;
        versionMinor = header.getShort() & 0xFFFF;
        header.getInt();                          // timezone (unused)
        header.getInt();                          // timestamp accuracy (unused)
        snaplen  = header.getInt();
        linkType = header.getInt();

        System.out.printf("Opened PCAP: %s%n", path);
        System.out.printf("  Version  : %d.%d%n", versionMajor, versionMinor);
        System.out.printf("  Snaplen  : %d bytes%n", snaplen);
        System.out.printf("  Link type: %d%s%n", linkType, linkType == 1 ? " (Ethernet)" : "");
    }

    /**
     * Read the next packet from the file.
     *
     * @return a RawPacket, or null at end-of-file
     * @throws IOException on read error
     */
    public RawPacket readNextPacket() throws IOException {
        byte[] pktHeader = new byte[PACKET_HEADER_SIZE];
        int read = stream.readNBytes(pktHeader, 0, PACKET_HEADER_SIZE);
        if (read == 0) return null;  // EOF
        if (read < PACKET_HEADER_SIZE) throw new IOException("Truncated packet header");

        ByteBuffer hdr = ByteBuffer.wrap(pktHeader).order(fileByteOrder);
        long tsSec    = hdr.getInt() & 0xFFFFFFFFL;
        long tsUsec   = hdr.getInt() & 0xFFFFFFFFL;
        int  inclLen  = hdr.getInt();
        int  origLen  = hdr.getInt();

        if (inclLen < 0 || inclLen > MAX_PACKET_LEN) {
            throw new IOException("Invalid packet incl_len: " + inclLen);
        }

        byte[] data = stream.readNBytes(inclLen);
        if (data.length < inclLen) throw new IOException("Truncated packet data");

        return new RawPacket(tsSec, tsUsec, data, origLen);
    }

    /** Write a PCAP global header to an output stream (for writing filtered output). */
    public void writeGlobalHeaderTo(DataOutputStream out) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(GLOBAL_HEADER_SIZE).order(fileByteOrder);
        buf.putInt(fileByteOrder == ByteOrder.BIG_ENDIAN ? PCAP_MAGIC_NATIVE : PCAP_MAGIC_NATIVE);
        buf.putShort((short) versionMajor);
        buf.putShort((short) versionMinor);
        buf.putInt(0);       // timezone
        buf.putInt(0);       // timestamp accuracy
        buf.putInt(snaplen);
        buf.putInt(linkType);
        out.write(buf.array());
    }

    /** Write a single packet (header + data) to an output stream. */
    public static void writePacketTo(DataOutputStream out, RawPacket pkt) throws IOException {
        // Always write in little-endian (standard pcap format for most tools)
        ByteBuffer hdr = ByteBuffer.allocate(PACKET_HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        hdr.putInt((int) pkt.tsSec);
        hdr.putInt((int) pkt.tsUsec);
        hdr.putInt(pkt.data.length);
        hdr.putInt(pkt.originalLen);
        out.write(hdr.array());
        out.write(pkt.data);
    }

    @Override
    public void close() throws IOException {
        if (stream != null) stream.close();
    }

    public int getLinkType()     { return linkType; }
    public int getSnaplen()      { return snaplen; }
    public int getVersionMajor() { return versionMajor; }
    public int getVersionMinor() { return versionMinor; }
}

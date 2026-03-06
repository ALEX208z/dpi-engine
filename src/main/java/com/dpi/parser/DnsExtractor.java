package com.dpi.parser;

import static com.dpi.parser.PacketParser.readUint16;

/**
 * Extracts the queried domain name from DNS packets.
 *
 * DNS Header (12 bytes):
 *   ID (2), Flags (2), QDCOUNT (2), ANCOUNT (2), NSCOUNT (2), ARCOUNT (2)
 *
 * DNS Question:
 *   QNAME  – variable-length encoded domain (labels terminated by 0x00)
 *   QTYPE  – 2 bytes (1=A, 28=AAAA, 15=MX, etc.)
 *   QCLASS – 2 bytes (1=IN)
 *
 * Domain encoding example for "www.google.com":
 *   03 77 77 77    →  "www"
 *   06 67 6f 6f 67 6c 65  →  "google"
 *   03 63 6f 6d    →  "com"
 *   00             →  end
 */
public class DnsExtractor {

    private static final int DNS_HEADER_LEN = 12;
    private static final int QR_FLAG_MASK   = 0x80; // bit 7 of flags byte = 1 → response

    /**
     * Extract the first queried domain from a DNS payload.
     *
     * @return the domain name string, or null if not a valid DNS query
     */
    public static String extractQuery(byte[] payload, int offset, int length) {
        if (payload == null || length < DNS_HEADER_LEN) return null;

        // Flags byte 2: QR bit — must be 0 for a query
        int flags = payload[offset + 2] & 0xFF;
        if ((flags & QR_FLAG_MASK) != 0) return null; // this is a response

        // QDCOUNT must be > 0
        int qdcount = readUint16(payload, offset + 4);
        if (qdcount == 0) return null;

        // Parse the QNAME starting at offset+12
        int pos = offset + DNS_HEADER_LEN;
        StringBuilder domain = new StringBuilder();

        while (pos < offset + length) {
            int labelLen = payload[pos] & 0xFF;

            if (labelLen == 0) break;            // End of name
            if ((labelLen & 0xC0) == 0xC0) break; // Compression pointer — stop
            if (labelLen > 63) break;            // Invalid label

            pos++;
            if (pos + labelLen > offset + length) break;

            if (domain.length() > 0) domain.append('.');
            domain.append(new String(payload, pos, labelLen));
            pos += labelLen;
        }

        return domain.length() > 0 ? domain.toString() : null;
    }
}

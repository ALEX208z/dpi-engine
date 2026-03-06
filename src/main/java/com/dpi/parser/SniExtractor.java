package com.dpi.parser;

import static com.dpi.parser.PacketParser.*;

/**
 * Extracts the Server Name Indication (SNI) from TLS Client Hello packets.
 *
 * Even though HTTPS traffic is encrypted, the TARGET DOMAIN leaks in plaintext
 * during the TLS handshake. This is the core insight that makes DPI possible
 * for HTTPS traffic.
 *
 * TLS Client Hello structure (simplified):
 * ┌─────────────────────────────────────────────────────────────────┐
 * │ TLS Record Header (5 bytes)                                     │
 * │   Byte 0:   Content Type = 0x16 (Handshake)                    │
 * │   Bytes 1-2: Version (0x0301 = TLS 1.0, 0x0303 = TLS 1.2)     │
 * │   Bytes 3-4: Record Length                                      │
 * ├─────────────────────────────────────────────────────────────────┤
 * │ Handshake Header (4 bytes)                                      │
 * │   Byte 0:   Handshake Type = 0x01 (Client Hello)               │
 * │   Bytes 1-3: Handshake Length (24-bit)                         │
 * ├─────────────────────────────────────────────────────────────────┤
 * │ Client Hello Body                                               │
 * │   Version (2), Random (32), SessionID (variable),              │
 * │   CipherSuites (variable), Compression (variable)              │
 * ├─────────────────────────────────────────────────────────────────┤
 * │ Extensions                                                      │
 * │   ...                                                           │
 * │   SNI Extension (type 0x0000):                                  │
 * │     Extension Type:   0x0000 (2 bytes)                         │
 * │     Extension Length: N      (2 bytes)                         │
 * │     SNI List Length:  M      (2 bytes)                         │
 * │     SNI Type:         0x00   (1 byte, hostname)                │
 * │     SNI Length:       L      (2 bytes)                         │
 * │     SNI Value:        "www.youtube.com"  ← We extract THIS     │
 * └─────────────────────────────────────────────────────────────────┘
 */
public class SniExtractor {

    // TLS constants
    private static final int CONTENT_TYPE_HANDSHAKE  = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO  = 0x01;
    private static final int EXTENSION_SNI           = 0x0000;
    private static final int SNI_TYPE_HOSTNAME       = 0x00;

    // Minimum TLS version (SSL 3.0) and maximum (TLS 1.3)
    private static final int TLS_MIN_VERSION = 0x0300;
    private static final int TLS_MAX_VERSION = 0x0304;

    /**
     * Attempt to extract the SNI hostname from a TLS Client Hello payload.
     *
     * @param payload raw bytes starting at the TLS record header
     * @param offset  start offset within payload
     * @param length  number of bytes available
     * @return the SNI hostname string, or null if not found / not a Client Hello
     */
    public static String extract(byte[] payload, int offset, int length) {
        if (payload == null || length < 9) return null;

        // ── TLS Record Header (5 bytes) ───────────────────────────────────────
        if ((payload[offset] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return null;

        int version = readUint16(payload, offset + 1);
        if (version < TLS_MIN_VERSION || version > TLS_MAX_VERSION) return null;

        int recordLength = readUint16(payload, offset + 3);
        if (recordLength > length - 5) return null; // truncated

        // ── Handshake Header (4 bytes, starts at offset+5) ───────────────────
        if ((payload[offset + 5] & 0xFF) != HANDSHAKE_CLIENT_HELLO) return null;
        // handshake_length is 24-bit, starting at offset+6 — we don't need it

        int pos = offset + 5 + 4; // skip handshake header

        // ── Client Hello Body ─────────────────────────────────────────────────
        pos += 2;  // Client version (2 bytes)
        pos += 32; // Random (32 bytes)

        // Session ID (1-byte length + data)
        if (pos >= offset + length) return null;
        int sessionIdLen = payload[pos] & 0xFF;
        pos += 1 + sessionIdLen;

        // Cipher Suites (2-byte length + data)
        if (pos + 2 > offset + length) return null;
        int cipherSuitesLen = readUint16(payload, pos);
        pos += 2 + cipherSuitesLen;

        // Compression Methods (1-byte length + data)
        if (pos >= offset + length) return null;
        int compressionLen = payload[pos] & 0xFF;
        pos += 1 + compressionLen;

        // ── Extensions ────────────────────────────────────────────────────────
        if (pos + 2 > offset + length) return null;
        int extensionsLen = readUint16(payload, pos);
        pos += 2;

        int extensionsEnd = Math.min(pos + extensionsLen, offset + length);

        while (pos + 4 <= extensionsEnd) {
            int extType = readUint16(payload, pos);
            int extLen  = readUint16(payload, pos + 2);
            pos += 4;

            if (pos + extLen > extensionsEnd) break;

            if (extType == EXTENSION_SNI) {
                // SNI extension found — parse the SNI list
                // SNI List Length (2) + SNI Type (1) + SNI Length (2) + SNI Value
                if (extLen < 5) break;

                // sniListLength = readUint16(payload, pos);  // not needed
                int sniType   = payload[pos + 2] & 0xFF;
                int sniLen    = readUint16(payload, pos + 3);

                if (sniType != SNI_TYPE_HOSTNAME) break;
                if (sniLen > extLen - 5) break;
                if (pos + 5 + sniLen > extensionsEnd) break;

                return new String(payload, pos + 5, sniLen);
            }

            pos += extLen;
        }

        return null; // SNI not found
    }
}

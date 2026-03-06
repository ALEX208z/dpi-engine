package com.dpi.parser;

/**
 * Extracts the Host header from plain HTTP (port 80) requests.
 *
 * For unencrypted HTTP traffic, the target domain appears in the
 * "Host:" request header — no TLS parsing needed.
 *
 * Example HTTP request:
 *   GET /index.html HTTP/1.1\r\n
 *   Host: www.example.com\r\n     ← We extract THIS
 *   Accept: text/html\r\n
 *   ...
 */
public class HttpHostExtractor {

    private static final byte[][] HTTP_METHODS = {
        "GET ".getBytes(), "POST".getBytes(), "PUT ".getBytes(),
        "HEAD".getBytes(), "DELE".getBytes(), "PATC".getBytes(), "OPTI".getBytes()
    };

    /**
     * Extract the HTTP Host header value from a payload.
     *
     * @return the hostname (without port), or null if not an HTTP request
     */
    public static String extract(byte[] payload, int offset, int length) {
        if (payload == null || length < 16) return null;
        if (!isHttpRequest(payload, offset)) return null;

        // Search for "Host:" header (case-insensitive)
        for (int i = offset; i + 6 < offset + length; i++) {
            if (isHostHeader(payload, i)) {
                // Skip "Host:" and any whitespace
                int start = i + 5;
                while (start < offset + length &&
                       (payload[start] == ' ' || payload[start] == '\t')) {
                    start++;
                }

                // Find end of line (\r\n or \n)
                int end = start;
                while (end < offset + length &&
                       payload[end] != '\r' && payload[end] != '\n') {
                    end++;
                }

                if (end > start) {
                    String host = new String(payload, start, end - start).trim();
                    // Strip port number if present (e.g., "example.com:8080" → "example.com")
                    int colonIdx = host.lastIndexOf(':');
                    if (colonIdx > 0) host = host.substring(0, colonIdx);
                    return host;
                }
            }
        }
        return null;
    }

    private static boolean isHttpRequest(byte[] payload, int offset) {
        if (payload.length < offset + 4) return false;
        for (byte[] method : HTTP_METHODS) {
            boolean match = true;
            for (int i = 0; i < 4 && i < method.length; i++) {
                if (payload[offset + i] != method[i]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }

    /** Check if bytes at position i are "Host:" (case-insensitive). */
    private static boolean isHostHeader(byte[] payload, int i) {
        if (i + 5 >= payload.length) return false;
        return Character.toUpperCase(payload[i]    & 0xFF) == 'H' &&
               Character.toUpperCase(payload[i+1]  & 0xFF) == 'O' &&
               Character.toUpperCase(payload[i+2]  & 0xFF) == 'S' &&
               Character.toUpperCase(payload[i+3]  & 0xFF) == 'T' &&
               payload[i+4] == ':';
    }
}

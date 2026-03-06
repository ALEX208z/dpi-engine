package com.dpi.rules;

import com.dpi.model.AppType;

import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Thread-safe blocking rules engine.
 *
 * Supports three rule types:
 *  1. IP blacklist     – block all traffic from a specific source IP
 *  2. App blacklist    – block all traffic classified as a specific app
 *  3. Domain blacklist – block traffic whose SNI contains a substring
 *
 * Uses a ReadWriteLock so multiple threads can check rules concurrently,
 * while rule updates get exclusive access.
 *
 * Blocking logic (checked in order):
 *   Source IP blocked? → DROP
 *   App type blocked?  → DROP
 *   SNI matches domain rule? → DROP
 *   Otherwise          → FORWARD
 */
public class RuleEngine {

    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private final Set<Long>     blockedIps      = new HashSet<>();
    private final Set<AppType>  blockedApps     = new HashSet<>();
    private final List<String>  blockedDomains  = new ArrayList<>();

    // ── Rule registration ─────────────────────────────────────────────────────

    public void blockIp(String ip) {
        long addr = parseIp(ip);
        lock.writeLock().lock();
        try {
            blockedIps.add(addr);
        } finally {
            lock.writeLock().unlock();
        }
        System.out.printf("[Rules] Blocked IP     : %s%n", ip);
    }

    public void blockApp(String appName) {
        AppType found = null;
        for (AppType t : AppType.values()) {
            if (t.getDisplayName().equalsIgnoreCase(appName) ||
                t.name().equalsIgnoreCase(appName)) {
                found = t;
                break;
            }
        }
        if (found == null) {
            System.err.printf("[Rules] Unknown app: %s%n", appName);
            return;
        }
        lock.writeLock().lock();
        try {
            blockedApps.add(found);
        } finally {
            lock.writeLock().unlock();
        }
        System.out.printf("[Rules] Blocked App    : %s%n", found.getDisplayName());
    }

    public void blockDomain(String domain) {
        lock.writeLock().lock();
        try {
            blockedDomains.add(domain.toLowerCase());
        } finally {
            lock.writeLock().unlock();
        }
        System.out.printf("[Rules] Blocked Domain : %s (substring match)%n", domain);
    }

    // ── Rule evaluation ───────────────────────────────────────────────────────

    /**
     * Check whether a packet/flow should be blocked.
     *
     * @param srcIp  source IP as unsigned long
     * @param app    classified application type
     * @param sni    SNI hostname (may be empty string)
     * @return true if the packet should be dropped
     */
    public boolean isBlocked(long srcIp, AppType app, String sni) {
        lock.readLock().lock();
        try {
            if (blockedIps.contains(srcIp))  return true;
            if (blockedApps.contains(app))   return true;
            if (!sni.isEmpty()) {
                String lower = sni.toLowerCase();
                for (String domain : blockedDomains) {
                    if (lower.contains(domain)) return true;
                }
            }
            return false;
        } finally {
            lock.readLock().unlock();
        }
    }

    public boolean hasAnyRules() {
        lock.readLock().lock();
        try {
            return !blockedIps.isEmpty() || !blockedApps.isEmpty() || !blockedDomains.isEmpty();
        } finally {
            lock.readLock().unlock();
        }
    }

    // ── IP parsing ────────────────────────────────────────────────────────────

    /**
     * Parse a dotted-decimal IP string into an unsigned 32-bit long.
     * Throws IllegalArgumentException on invalid format.
     */
    public static long parseIp(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Invalid IP: " + ip);
        long result = 0;
        for (int i = 0; i < 4; i++) {
            int octet = Integer.parseInt(parts[i].trim());
            if (octet < 0 || octet > 255) throw new IllegalArgumentException("Invalid octet in IP: " + ip);
            result = (result << 8) | octet;
        }
        return result;
    }
}

package com.dpi.stats;

import com.dpi.model.AppType;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe statistics collector for the DPI pipeline.
 *
 * Uses atomic counters for high-frequency per-packet stats,
 * and ConcurrentHashMap for per-app and per-SNI tracking.
 */
public class DpiStats {

    // Per-packet counters (lock-free atomics)
    public final AtomicLong totalPackets  = new AtomicLong(0);
    public final AtomicLong totalBytes    = new AtomicLong(0);
    public final AtomicLong forwarded     = new AtomicLong(0);
    public final AtomicLong dropped       = new AtomicLong(0);
    public final AtomicLong tcpPackets    = new AtomicLong(0);
    public final AtomicLong udpPackets    = new AtomicLong(0);

    // Per-thread dispatcher counters (indexed by thread id)
    private final AtomicLong[] lbCounts;
    private final AtomicLong[] fpCounts;

    // Per-app traffic breakdown
    private final ConcurrentHashMap<AppType, AtomicLong> appCounts   = new ConcurrentHashMap<>();

    // Unique detected SNIs and their app types
    private final ConcurrentHashMap<String, AppType>     detectedSnis = new ConcurrentHashMap<>();

    public DpiStats(int numLbs, int numFps) {
        lbCounts = new AtomicLong[numLbs];
        fpCounts = new AtomicLong[numFps];
        for (int i = 0; i < numLbs; i++) lbCounts[i] = new AtomicLong(0);
        for (int i = 0; i < numFps; i++) fpCounts[i] = new AtomicLong(0);
    }

    public void recordApp(AppType app, String sni) {
        appCounts.computeIfAbsent(app, k -> new AtomicLong(0)).incrementAndGet();
        if (sni != null && !sni.isEmpty()) {
            detectedSnis.putIfAbsent(sni, app);
        }
    }

    public void recordLbDispatch(int lbId)    { if (lbId < lbCounts.length) lbCounts[lbId].incrementAndGet(); }
    public void recordFpProcess(int fpId)     { if (fpId < fpCounts.length) fpCounts[fpId].incrementAndGet(); }

    public Map<AppType, Long> getAppCounts() {
        Map<AppType, Long> result = new LinkedHashMap<>();
        appCounts.forEach((k, v) -> result.put(k, v.get()));
        return result;
    }

    public Map<String, AppType> getDetectedSnis() {
        return Collections.unmodifiableMap(detectedSnis);
    }

    public long getLbCount(int i) { return i < lbCounts.length ? lbCounts[i].get() : 0; }
    public long getFpCount(int i) { return i < fpCounts.length ? fpCounts[i].get() : 0; }
    public int  getNumLbs()       { return lbCounts.length; }
    public int  getNumFps()       { return fpCounts.length; }
}

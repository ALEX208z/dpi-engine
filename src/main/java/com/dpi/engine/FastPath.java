package com.dpi.engine;

import com.dpi.model.*;
import com.dpi.parser.DnsExtractor;
import com.dpi.parser.HttpHostExtractor;
import com.dpi.parser.SniExtractor;
import com.dpi.rules.RuleEngine;
import com.dpi.stats.DpiStats;
import com.dpi.util.BoundedQueue;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Fast Path (FP) worker thread — the core DPI processing unit.
 *
 * Each FP thread owns its own flow table. Consistent hashing in the
 * LoadBalancer ensures that all packets belonging to the same connection
 * (same 5-tuple) always arrive at the same FP thread. This eliminates
 * locking on the flow table entirely.
 *
 * Per packet, the FP thread:
 *  1. Looks up (or creates) the flow entry
 *  2. Attempts to classify the flow via SNI / HTTP Host / DNS
 *  3. Checks blocking rules
 *  4. Forwards allowed packets to the output queue
 *  5. Records statistics
 */
public class FastPath implements Runnable {

    private final int                         id;
    private final BoundedQueue<PacketJob>     inputQueue;
    private final BoundedQueue<PacketJob>     outputQueue;
    private final RuleEngine                  rules;
    private final DpiStats                    stats;

    // Each FP has its own flow table — no locking needed
    private final ConcurrentHashMap<FiveTuple, FlowEntry> flows = new ConcurrentHashMap<>();

    private volatile boolean running = true;

    public FastPath(int id,
                    BoundedQueue<PacketJob> inputQueue,
                    BoundedQueue<PacketJob> outputQueue,
                    RuleEngine rules,
                    DpiStats stats) {
        this.id          = id;
        this.inputQueue  = inputQueue;
        this.outputQueue = outputQueue;
        this.rules       = rules;
        this.stats       = stats;
    }

    @Override
    public void run() {
        while (running || !inputQueue.isEmpty()) {
            PacketJob job = inputQueue.poll();
            if (job == null) continue;

            stats.recordFpProcess(id);
            processPacket(job);
        }
    }

    private void processPacket(PacketJob job) {
        // ── Flow lookup / creation ────────────────────────────────────────────
        FlowEntry flow = flows.computeIfAbsent(job.tuple, FlowEntry::new);
        flow.packets.incrementAndGet();
        flow.bytes.addAndGet(job.data.length);

        // ── Classification (only if not yet done) ─────────────────────────────
        if (!flow.classified) {
            classify(job, flow);
        }

        // ── Blocking check ────────────────────────────────────────────────────
        if (!flow.blocked) {
            flow.blocked = rules.isBlocked(job.tuple.srcIp, flow.appType, flow.sni);
            if (flow.blocked) {
                System.out.printf("[BLOCKED] %-15s → %-15s  %-12s  %s%n",
                    job.tuple.srcIpString(),
                    job.tuple.dstIpString(),
                    flow.appType.getDisplayName(),
                    flow.sni.isEmpty() ? "" : "(" + flow.sni + ")");
            }
        }

        // ── Statistics recording ──────────────────────────────────────────────
        stats.recordApp(flow.appType, flow.sni);

        // ── Forward or drop ───────────────────────────────────────────────────
        if (flow.blocked) {
            stats.dropped.incrementAndGet();
        } else {
            stats.forwarded.incrementAndGet();
            outputQueue.offer(job);
        }
    }

    /**
     * Attempt to classify the flow using DPI techniques.
     * Sets flow.sni, flow.appType, and flow.classified when successful.
     */
    private void classify(PacketJob job, FlowEntry flow) {
        byte[] data      = job.data;
        int    pOff      = job.payloadOffset;
        int    pLen      = job.payloadLength;
        int    dstPort   = job.tuple.dstPort;
        int    srcPort   = job.tuple.srcPort;
        int    protocol  = job.protocol;

        if (pLen <= 0) {
            fallbackClassify(flow, dstPort, protocol);
            return;
        }

        // ── TLS/HTTPS: port 443 → attempt SNI extraction ──────────────────────
        if (dstPort == 443 && pLen > 9) {
            String sni = SniExtractor.extract(data, pOff, pLen);
            if (sni != null && !sni.isEmpty()) {
                flow.sni        = sni;
                flow.appType    = AppType.fromSni(sni);
                flow.classified = true;
                return;
            }
            flow.appType = AppType.HTTPS;
        }

        // ── HTTP: port 80 → extract Host header ───────────────────────────────
        if (dstPort == 80 && pLen > 16) {
            String host = HttpHostExtractor.extract(data, pOff, pLen);
            if (host != null && !host.isEmpty()) {
                flow.sni        = host;
                flow.appType    = AppType.fromSni(host);
                flow.classified = true;
                return;
            }
            flow.appType = AppType.HTTP;
        }

        // ── DNS: port 53 → extract query domain ───────────────────────────────
        if (dstPort == 53 || srcPort == 53) {
            String domain = DnsExtractor.extractQuery(data, pOff, pLen);
            if (domain != null) {
                flow.sni        = domain;
                flow.appType    = AppType.DNS;
                flow.classified = true;
                return;
            }
            flow.appType = AppType.DNS;
        }

        fallbackClassify(flow, dstPort, protocol);
    }

    /** Port-based classification fallback when payload inspection fails. */
    private void fallbackClassify(FlowEntry flow, int dstPort, int protocol) {
        if (flow.appType == AppType.UNKNOWN) {
            flow.appType = switch (dstPort) {
                case 443  -> AppType.HTTPS;
                case 80   -> AppType.HTTP;
                case 53   -> AppType.DNS;
                default   -> AppType.UNKNOWN;
            };
        }
    }

    public void stop()                    { running = false; }
    public int  getId()                   { return id; }
    public int  getFlowCount()            { return flows.size(); }
    public ConcurrentHashMap<FiveTuple, FlowEntry> getFlows() { return flows; }
}

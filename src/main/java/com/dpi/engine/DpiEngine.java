package com.dpi.engine;

import com.dpi.model.*;
import com.dpi.parser.PacketParser;
import com.dpi.parser.PcapReader;
import com.dpi.rules.RuleEngine;
import com.dpi.stats.DpiStats;
import com.dpi.util.BoundedQueue;

import java.io.IOException;
import java.util.*;

/**
 * DPI Engine Orchestrator — wires all pipeline components together.
 *
 * Multi-threaded architecture:
 *
 *                    ┌─────────────────┐
 *                    │  Reader Thread  │
 *                    │  (reads PCAP)   │
 *                    └────────┬────────┘
 *                             │ PacketJob
 *              ┌──────────────┴──────────────┐
 *              │      hash(5-tuple) % numLBs  │
 *              ▼                             ▼
 *    ┌─────────────────┐           ┌─────────────────┐
 *    │  LB0 Thread     │           │  LB1 Thread     │
 *    └────────┬────────┘           └────────┬────────┘
 *             │                             │
 *      ┌──────┴──────┐               ┌──────┴──────┐
 *      ▼             ▼               ▼             ▼
 * ┌─────────┐ ┌─────────┐     ┌─────────┐ ┌─────────┐
 * │  FP0    │ │  FP1    │     │  FP2    │ │  FP3    │
 * │ Thread  │ │ Thread  │     │ Thread  │ │ Thread  │
 * └────┬────┘ └────┬────┘     └────┬────┘ └────┬────┘
 *      └──────────────┬────────────┘───────────┘
 *                     ▼
 *         ┌───────────────────────┐
 *         │  Output Writer Thread │
 *         │  (writes PCAP)        │
 *         └───────────────────────┘
 */
public class DpiEngine {

    private static final int QUEUE_CAPACITY = 10_000;

    private final String     inputPath;
    private final String     outputPath;
    private final int        numLbs;
    private final int        numFps;
    private final RuleEngine rules;

    public DpiEngine(String inputPath, String outputPath,
                     int numLbs, int numFps, RuleEngine rules) {
        this.inputPath  = inputPath;
        this.outputPath = outputPath;
        this.numLbs     = numLbs;
        this.numFps     = numFps;
        this.rules      = rules;
    }

    /**
     * Run the full DPI pipeline.
     *
     * @return the collected statistics after processing completes
     */
    @SuppressWarnings("unchecked")
    public DpiStats run() throws IOException, InterruptedException {
        DpiStats stats = new DpiStats(numLbs, numFps);

        // ── Create queues ─────────────────────────────────────────────────────
        // One input queue per LB (Reader dispatches to LBs)
        BoundedQueue<PacketJob>[] lbQueues = new BoundedQueue[numLbs];
        for (int i = 0; i < numLbs; i++) lbQueues[i] = new BoundedQueue<>(QUEUE_CAPACITY);

        // One input queue per FP (LBs dispatch to FPs)
        BoundedQueue<PacketJob>[] fpQueues = new BoundedQueue[numFps];
        for (int i = 0; i < numFps; i++) fpQueues[i] = new BoundedQueue<>(QUEUE_CAPACITY);

        // Single output queue (all FPs write to OutputWriter)
        BoundedQueue<PacketJob> outputQueue = new BoundedQueue<>(QUEUE_CAPACITY);

        // ── Create and start FP workers ───────────────────────────────────────
        FastPath[] fps      = new FastPath[numFps];
        Thread[]   fpThreads = new Thread[numFps];
        for (int i = 0; i < numFps; i++) {
            fps[i]       = new FastPath(i, fpQueues[i], outputQueue, rules, stats);
            fpThreads[i] = new Thread(fps[i], "FP-" + i);
            fpThreads[i].start();
        }

        // ── Create and start LB workers ───────────────────────────────────────
        LoadBalancer[] lbs      = new LoadBalancer[numLbs];
        Thread[]       lbThreads = new Thread[numLbs];
        for (int i = 0; i < numLbs; i++) {
            lbs[i]       = new LoadBalancer(i, lbQueues[i], fpQueues, stats);
            lbThreads[i] = new Thread(lbs[i], "LB-" + i);
            lbThreads[i].start();
        }

        // ── Create and start output writer ────────────────────────────────────
        OutputWriter writer       = new OutputWriter(outputQueue, outputPath);
        Thread       writerThread = new Thread(writer, "OutputWriter");
        writerThread.start();

        // ── Reader: parse PCAP and dispatch to LBs ────────────────────────────
        int packetId = 0;
        try (PcapReader reader = new PcapReader()) {
            reader.open(inputPath);

            RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                ParsedPacket parsed = PacketParser.parse(raw);
                if (parsed == null || !parsed.hasIp) continue;
                if (!parsed.hasTcp && !parsed.hasUdp) continue;

                stats.totalPackets.incrementAndGet();
                stats.totalBytes.addAndGet(raw.data.length);
                if (parsed.hasTcp) stats.tcpPackets.incrementAndGet();
                if (parsed.hasUdp) stats.udpPackets.incrementAndGet();

                PacketJob job = new PacketJob(packetId++, raw, parsed);

                // Dispatch to LB using 5-tuple hash
                int lbIdx = (int)(Math.abs(job.tuple.hashCode()) % numLbs);
                lbQueues[lbIdx].offer(job);
            }
        }

        System.out.printf("%n[Reader] Done reading %d packets.%n", packetId);

        // ── Graceful shutdown: stop in pipeline order ──────────────────────────
        // 1. Shutdown LB input queues → LBs will drain and exit
        for (var q : lbQueues) q.shutdown();
        for (var lb : lbs) lb.stop();
        for (var t : lbThreads) t.join(5000);

        // 2. Shutdown FP input queues → FPs will drain and exit
        for (var q : fpQueues) q.shutdown();
        for (var fp : fps) fp.stop();
        for (var t : fpThreads) t.join(5000);

        // 3. Shutdown output queue → writer will drain and exit
        outputQueue.shutdown();
        writer.stop();
        writerThread.join(5000);

        System.out.printf("[OutputWriter] Wrote %d packets to %s%n%n",
            writer.getWritten(), outputPath);

        return stats;
    }
}

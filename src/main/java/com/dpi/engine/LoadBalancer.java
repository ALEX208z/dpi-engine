package com.dpi.engine;

import com.dpi.model.PacketJob;
import com.dpi.stats.DpiStats;
import com.dpi.util.BoundedQueue;

/**
 * Load Balancer (LB) thread.
 *
 * Sits between the Reader and the FastPath workers. Receives packets from
 * its input queue and dispatches them to the correct FastPath worker using
 * consistent hashing on the 5-tuple.
 *
 * WHY CONSISTENT HASHING?
 * ────────────────────────
 * All packets of the same TCP connection must go to the SAME FP thread.
 * Otherwise two FP threads would each have a partial flow state and
 * classification would fail.
 *
 * The hash is computed from the 5-tuple (src_ip, dst_ip, src_port,
 * dst_port, protocol), which is the same for all packets in a connection.
 *
 * Pipeline:
 *   Reader → [LB0, LB1, ...] → [FP0, FP1, FP2, FP3, ...]
 */
public class LoadBalancer implements Runnable {

    private final int                      id;
    private final BoundedQueue<PacketJob>  inputQueue;
    private final BoundedQueue<PacketJob>[] fpQueues;
    private final DpiStats                 stats;

    private volatile boolean running = true;

    @SuppressWarnings("unchecked")
    public LoadBalancer(int id,
                        BoundedQueue<PacketJob> inputQueue,
                        BoundedQueue<PacketJob>[] fpQueues,
                        DpiStats stats) {
        this.id         = id;
        this.inputQueue = inputQueue;
        this.fpQueues   = fpQueues;
        this.stats      = stats;
    }

    @Override
    public void run() {
        while (running || !inputQueue.isEmpty()) {
            PacketJob job = inputQueue.poll();
            if (job == null) continue;

            // Consistent hash: same 5-tuple → same FP thread always
            int fpIdx = selectFp(job);
            fpQueues[fpIdx].offer(job);

            stats.recordLbDispatch(id);
        }
    }

    /**
     * Select a FastPath worker index using the 5-tuple hash.
     * Mixing srcIp ^ dstIp ensures bidirectional flows map to the same FP.
     */
    private int selectFp(PacketJob job) {
        long hash = (job.tuple.srcIp ^ job.tuple.dstIp) ^
                    ((long) job.tuple.srcPort << 16) ^
                    ((long) job.tuple.dstPort) ^
                    ((long) job.tuple.protocol << 8);
        // Ensure positive index
        return (int) (Math.abs(hash) % fpQueues.length);
    }

    public void stop() { running = false; }
    public int  getId() { return id; }
}

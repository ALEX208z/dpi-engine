package com.dpi.engine;

import com.dpi.model.PacketJob;
import com.dpi.model.RawPacket;
import com.dpi.parser.PcapReader;
import com.dpi.util.BoundedQueue;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Output writer thread.
 *
 * Drains the output queue and writes each allowed (not-blocked) packet
 * to the output PCAP file. Runs on its own thread so FP workers are never
 * stalled waiting for disk I/O.
 *
 * Output format is standard PCAP (little-endian) readable by Wireshark.
 */
public class OutputWriter implements Runnable {

    private static final int PCAP_MAGIC         = 0xa1b2c3d4;
    private static final int PCAP_VERSION_MAJOR = 2;
    private static final int PCAP_VERSION_MINOR = 4;
    private static final int SNAPLEN            = 65535;
    private static final int LINK_TYPE_ETHERNET = 1;

    private final BoundedQueue<PacketJob> outputQueue;
    private final String                  outputPath;

    private volatile boolean running   = true;
    private          long    written   = 0;

    public OutputWriter(BoundedQueue<PacketJob> outputQueue, String outputPath) {
        this.outputQueue = outputQueue;
        this.outputPath  = outputPath;
    }

    @Override
    public void run() {
        try (DataOutputStream out = new DataOutputStream(
                new BufferedOutputStream(new FileOutputStream(outputPath), 128 * 1024))) {

            writeGlobalHeader(out);

            while (running || !outputQueue.isEmpty()) {
                PacketJob job = outputQueue.poll();
                if (job == null) continue;
                writePacket(out, job);
                written++;
            }

            out.flush();
        } catch (IOException e) {
            System.err.println("[OutputWriter] Error: " + e.getMessage());
        }
    }

    private void writeGlobalHeader(DataOutputStream out) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(PCAP_MAGIC);
        buf.putShort((short) PCAP_VERSION_MAJOR);
        buf.putShort((short) PCAP_VERSION_MINOR);
        buf.putInt(0);          // timezone
        buf.putInt(0);          // timestamp accuracy
        buf.putInt(SNAPLEN);
        buf.putInt(LINK_TYPE_ETHERNET);
        out.write(buf.array());
    }

    private void writePacket(DataOutputStream out, PacketJob job) throws IOException {
        ByteBuffer hdr = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        hdr.putInt((int) job.tsSec);
        hdr.putInt((int) job.tsUsec);
        hdr.putInt(job.data.length);
        hdr.putInt(job.originalLen);
        out.write(hdr.array());
        out.write(job.data);
    }

    public void  stop()          { running = false; }
    public long  getWritten()    { return written; }
}

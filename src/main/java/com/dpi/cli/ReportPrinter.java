package com.dpi.cli;

import com.dpi.model.AppType;
import com.dpi.stats.DpiStats;

import java.util.*;

/**
 * Formats and prints the final DPI processing report to stdout.
 *
 * Produces a box-drawing ASCII report similar to the C++ original,
 * with packet counts, protocol breakdown, app classification, and
 * detected SNI hostnames.
 */
public class ReportPrinter {

    private static final String LINE  = "║";
    private static final String TOP   = "╔══════════════════════════════════════════════════════════════╗";
    private static final String MID   = "╠══════════════════════════════════════════════════════════════╣";
    private static final String BOT   = "╚══════════════════════════════════════════════════════════════╝";
    private static final int    WIDTH = 62; // inner width

    public static void print(DpiStats stats, int numLbs, int numFps) {
        long total     = stats.totalPackets.get();
        long forwarded = stats.forwarded.get();
        long dropped   = stats.dropped.get();
        long tcp       = stats.tcpPackets.get();
        long udp       = stats.udpPackets.get();
        long bytes     = stats.totalBytes.get();

        System.out.println(TOP);
        center("DPI ENGINE v2.0 (Java Multi-threaded)");
        System.out.println(MID);
        row("Load Balancers", numLbs);
        row("Fast Path Workers", numFps);
        row("Total Threads", numLbs + numFps + 2); // +2: reader, writer
        System.out.println(MID);
        row("Total Packets",  total);
        row("Total Bytes",    bytes);
        row("TCP Packets",    tcp);
        row("UDP Packets",    udp);
        System.out.println(MID);
        row("Forwarded",      forwarded);
        row("Dropped",        dropped);
        double dropRate = total > 0 ? 100.0 * dropped / total : 0;
        rowPct("Drop Rate", dropRate);
        System.out.println(MID);

        // ── Thread statistics ─────────────────────────────────────────────────
        center("THREAD STATISTICS");
        System.out.println(MID);
        for (int i = 0; i < numLbs; i++) {
            row(String.format("LB%d dispatched", i), stats.getLbCount(i));
        }
        for (int i = 0; i < numFps; i++) {
            row(String.format("FP%d processed", i), stats.getFpCount(i));
        }
        System.out.println(MID);

        // ── Application breakdown ─────────────────────────────────────────────
        center("APPLICATION BREAKDOWN");
        System.out.println(MID);

        Map<AppType, Long> appCounts = stats.getAppCounts();
        if (!appCounts.isEmpty()) {
            List<Map.Entry<AppType, Long>> sorted = new ArrayList<>(appCounts.entrySet());
            sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

            for (var entry : sorted) {
                AppType app   = entry.getKey();
                long    count = entry.getValue();
                double  pct   = total > 0 ? 100.0 * count / total : 0;
                int     bar   = (int)(pct / 4);

                String appName = app.getDisplayName();
                String barStr  = "#".repeat(bar);
                String line    = String.format(" %-14s %6d  %5.1f%% %-18s",
                    appName, count, pct, barStr);
                System.out.printf("%s%s%n", LINE, padRight(line, WIDTH + 1));
            }
        } else {
            System.out.printf("%s%s%n", LINE, padRight("  No traffic classified.", WIDTH + 1));
        }

        System.out.println(MID);

        // ── Detected SNIs ─────────────────────────────────────────────────────
        center("DETECTED DOMAINS / SNIs");
        System.out.println(MID);

        Map<String, AppType> snis = stats.getDetectedSnis();
        if (snis.isEmpty()) {
            System.out.printf("%s%s%n", LINE, padRight("  No SNIs detected.", WIDTH + 1));
        } else {
            List<Map.Entry<String, AppType>> sniList = new ArrayList<>(snis.entrySet());
            sniList.sort(Map.Entry.comparingByKey());
            for (var e : sniList) {
                String line = String.format("  %-35s → %s", e.getKey(), e.getValue().getDisplayName());
                System.out.printf("%s%s%n", LINE, padRight(line, WIDTH + 1));
            }
        }

        System.out.println(BOT);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static void center(String text) {
        int pad = (WIDTH - text.length()) / 2;
        String line = " ".repeat(pad) + text;
        System.out.printf("%s%s%n", LINE, padRight(line, WIDTH + 1));
    }

    private static void row(String label, long value) {
        String line = String.format(" %-30s %10d", label + ":", value);
        System.out.printf("%s%s%n", LINE, padRight(line, WIDTH + 1));
    }

    private static void rowPct(String label, double value) {
        String line = String.format(" %-30s %9.1f%%", label + ":", value);
        System.out.printf("%s%s%n", LINE, padRight(line, WIDTH + 1));
    }

    private static String padRight(String s, int width) {
        if (s.length() >= width) return s.substring(0, width - 1) + LINE;
        return s + " ".repeat(width - s.length()) + LINE;
    }
}

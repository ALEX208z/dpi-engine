package com.dpi;

import com.dpi.cli.ReportPrinter;
import com.dpi.engine.DpiEngine;
import com.dpi.rules.RuleEngine;
import com.dpi.stats.DpiStats;

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║           DPI Engine — Java Deep Packet Inspection           ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Entry point. Parses CLI arguments and launches the DPI pipeline.
 *
 * Usage:
 *   java -jar dpi-engine.jar <input.pcap> <output.pcap> [options]
 *
 * Options:
 *   --block-ip     <ip>      Block all traffic from source IP
 *   --block-app    <app>     Block by application (YouTube, TikTok, etc.)
 *   --block-domain <domain>  Block by domain substring
 *   --lbs          <n>       Number of LoadBalancer threads (default: 2)
 *   --fps          <n>       Number of FastPath threads (default: 4)
 *
 * Examples:
 *   java -jar dpi-engine.jar capture.pcap filtered.pcap
 *   java -jar dpi-engine.jar capture.pcap out.pcap --block-app YouTube --block-app TikTok
 *   java -jar dpi-engine.jar capture.pcap out.pcap --block-domain facebook --lbs 4 --fps 8
 */
public class Main {

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        String     inputPath  = args[0];
        String     outputPath = args[1];
        RuleEngine rules      = new RuleEngine();
        int        numLbs     = 2;
        int        numFps     = 4;

        // Parse options
        for (int i = 2; i < args.length; i++) {
            switch (args[i]) {
                case "--block-ip" -> {
                    if (i + 1 < args.length) rules.blockIp(args[++i]);
                }
                case "--block-app" -> {
                    if (i + 1 < args.length) rules.blockApp(args[++i]);
                }
                case "--block-domain" -> {
                    if (i + 1 < args.length) rules.blockDomain(args[++i]);
                }
                case "--lbs" -> {
                    if (i + 1 < args.length) numLbs = Math.max(1, Integer.parseInt(args[++i]));
                }
                case "--fps" -> {
                    if (i + 1 < args.length) numFps = Math.max(1, Integer.parseInt(args[++i]));
                }
                default -> System.err.println("[Warning] Unknown option: " + args[i]);
            }
        }

        printBanner(numLbs, numFps);

        try {
            long start  = System.currentTimeMillis();
            DpiEngine engine = new DpiEngine(inputPath, outputPath, numLbs, numFps, rules);
            DpiStats  stats  = engine.run();
            long elapsed     = System.currentTimeMillis() - start;

            ReportPrinter.print(stats, numLbs, numFps);
            System.out.printf("%nCompleted in %.2f seconds.%n", elapsed / 1000.0);
            System.out.printf("Output written to: %s%n", outputPath);

        } catch (Exception e) {
            System.err.println("[ERROR] " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void printBanner(int numLbs, int numFps) {
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║          DPI ENGINE v2.0  —  Java Multi-threaded             ║");
        System.out.printf ("║  Load Balancers: %-4d   Fast Paths: %-4d   Total FPs: %-4d  ║%n",
            numLbs, numFps, numLbs * numFps);
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();
    }

    private static void printUsage() {
        System.out.println("""
            DPI Engine — Java Deep Packet Inspection System
            ================================================

            Usage: java -jar dpi-engine.jar <input.pcap> <output.pcap> [options]

            Options:
              --block-ip     <ip>      Block traffic from source IP
              --block-app    <app>     Block application (YouTube, TikTok, Facebook, etc.)
              --block-domain <domain>  Block domain (substring match)
              --lbs          <n>       Number of LoadBalancer threads  (default: 2)
              --fps          <n>       Number of FastPath worker threads (default: 4)

            Supported Apps:
              YouTube, Facebook, Instagram, WhatsApp, Twitter, Netflix,
              Amazon, Microsoft, Apple, Telegram, TikTok, Spotify, Zoom,
              Discord, GitHub, Cloudflare, Google

            Examples:
              # Basic analysis (no blocking)
              java -jar dpi-engine.jar capture.pcap output.pcap

              # Block YouTube and TikTok
              java -jar dpi-engine.jar capture.pcap output.pcap --block-app YouTube --block-app TikTok

              # Block by IP and domain
              java -jar dpi-engine.jar capture.pcap output.pcap --block-ip 192.168.1.50 --block-domain facebook

              # High-performance: 4 LBs × 8 FPs = 32 processing threads
              java -jar dpi-engine.jar large.pcap output.pcap --lbs 4 --fps 8
            """);
    }
}

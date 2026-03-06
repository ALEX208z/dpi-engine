package com.dpi.model;

/**
 * Application types that can be identified via DPI.
 * Mapped from SNI (TLS) or HTTP Host headers.
 */
public enum AppType {
    UNKNOWN("Unknown"),
    HTTP("HTTP"),
    HTTPS("HTTPS"),
    DNS("DNS"),
    TLS("TLS"),
    QUIC("QUIC"),
    GOOGLE("Google"),
    YOUTUBE("YouTube"),
    FACEBOOK("Facebook"),
    INSTAGRAM("Instagram"),
    WHATSAPP("WhatsApp"),
    TWITTER("Twitter/X"),
    NETFLIX("Netflix"),
    AMAZON("Amazon"),
    MICROSOFT("Microsoft"),
    APPLE("Apple"),
    TELEGRAM("Telegram"),
    TIKTOK("TikTok"),
    SPOTIFY("Spotify"),
    ZOOM("Zoom"),
    DISCORD("Discord"),
    GITHUB("GitHub"),
    CLOUDFLARE("Cloudflare");

    private final String displayName;

    AppType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    /**
     * Map an SNI/domain string to an AppType using substring matching.
     */
    public static AppType fromSni(String sni) {
        if (sni == null || sni.isEmpty()) return UNKNOWN;
        String s = sni.toLowerCase();

        if (s.contains("youtube") || s.contains("ytimg") || s.contains("youtu.be")) return YOUTUBE;
        if (s.contains("instagram") || s.contains("cdninstagram"))                  return INSTAGRAM;
        if (s.contains("whatsapp") || s.contains("wa.me"))                          return WHATSAPP;
        if (s.contains("facebook") || s.contains("fbcdn") || s.contains("fb.com"))  return FACEBOOK;
        if (s.contains("google") || s.contains("gstatic") || s.contains("googleapis") || s.contains("gvt1")) return GOOGLE;
        if (s.contains("netflix") || s.contains("nflxvideo") || s.contains("nflximg")) return NETFLIX;
        if (s.contains("amazon") || s.contains("amazonaws") || s.contains("cloudfront")) return AMAZON;
        if (s.contains("microsoft") || s.contains("office") || s.contains("azure") || s.contains("outlook") || s.contains("bing")) return MICROSOFT;
        if (s.contains("apple") || s.contains("icloud") || s.contains("itunes"))    return APPLE;
        if (s.contains("telegram") || s.contains("t.me"))                           return TELEGRAM;
        if (s.contains("tiktok") || s.contains("bytedance") || s.contains("musical.ly")) return TIKTOK;
        if (s.contains("spotify") || s.contains("scdn.co"))                         return SPOTIFY;
        if (s.contains("zoom"))                                                      return ZOOM;
        if (s.contains("discord") || s.contains("discordapp"))                      return DISCORD;
        if (s.contains("github") || s.contains("githubusercontent"))                 return GITHUB;
        if (s.contains("cloudflare") || s.contains("cf-"))                          return CLOUDFLARE;
        if (s.contains("twitter") || s.contains("twimg") || s.contains("x.com"))   return TWITTER;

        return HTTPS; // SNI present but unrecognized → still HTTPS
    }
}

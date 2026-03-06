package com.dpi.model;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Tracks the state of a single network flow (connection).
 *
 * One FlowEntry exists per unique FiveTuple. All packets belonging to the
 * same connection update the same FlowEntry. Once a flow is classified
 * (SNI extracted, app identified), that classification sticks for all
 * future packets in the flow — even before the blocking decision is made
 * for the first time.
 */
public class FlowEntry {

    public final FiveTuple tuple;

    // Classification
    public volatile AppType  appType    = AppType.UNKNOWN;
    public volatile String   sni        = "";
    public volatile boolean  classified = false;

    // Statistics
    public final AtomicLong packets = new AtomicLong(0);
    public final AtomicLong bytes   = new AtomicLong(0);

    // Blocking
    public volatile boolean blocked = false;

    public FlowEntry(FiveTuple tuple) {
        this.tuple = tuple;
    }
}

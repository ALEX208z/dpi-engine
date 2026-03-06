package com.dpi.util;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * A bounded, blocking thread-safe queue used to pass packets between
 * pipeline stages: Reader → LoadBalancer → FastPath → OutputWriter.
 *
 * Uses Java's ArrayBlockingQueue internally (a proven, well-tested
 * concurrent data structure) rather than reimplementing the wheel.
 *
 * Behavior:
 *  - offer(): Attempts to add; blocks up to 100ms if queue is full.
 *  - poll():  Returns next item; blocks up to 100ms if queue is empty.
 *  - Both return null/false on timeout, allowing callers to check shutdown.
 *
 * @param <T> the type of items in the queue
 */
public class BoundedQueue<T> {

    private static final int TIMEOUT_MS = 100;

    private final ArrayBlockingQueue<T> queue;
    private volatile boolean            shutdown = false;

    public BoundedQueue(int capacity) {
        this.queue = new ArrayBlockingQueue<>(capacity);
    }

    /**
     * Add an item to the queue, blocking up to 100ms if full.
     *
     * @return true if successfully added, false if shutdown or timeout
     */
    public boolean offer(T item) {
        if (shutdown) return false;
        try {
            return queue.offer(item, TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /**
     * Take an item from the queue, blocking up to 100ms if empty.
     *
     * @return the next item, or null on timeout / shutdown
     */
    public T poll() {
        try {
            return queue.poll(TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    /** Signal all producers and consumers to stop waiting. */
    public void shutdown() {
        shutdown = true;
    }

    public boolean isShutdown()   { return shutdown; }
    public int     size()         { return queue.size(); }
    public boolean isEmpty()      { return queue.isEmpty(); }
}

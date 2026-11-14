package me.skerik.justlogin.core.crypto;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.jspecify.annotations.Nullable;

/**
 * Bounded pool and queue for memory-hard Argon2id operations (threat model #6: prevents OOM / CPU starvation).
 * Never runs on the server main thread. Also bounds per-IP in-flight hashes (P0-4).
 */
public final class HashingExecutor implements AutoCloseable {

    public static final class HashingBusyException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public HashingBusyException() {
            super("Hashing queue is full");
        }
    }

    private final ExecutorService pool;
    private final int maxPerKey;
    private final Map<String, AtomicInteger> inFlightByKey = new ConcurrentHashMap<>();

    public HashingExecutor(int maxConcurrent, int maxQueued) {
        int threads = Math.max(1, maxConcurrent);
        int queueSize = Math.max(1, maxQueued);
        this.maxPerKey = Math.max(2, Math.min(8, threads * 2));
        AtomicInteger ids = new AtomicInteger();
        this.pool = new ThreadPoolExecutor(
                threads,
                threads,
                30L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(queueSize),
                r -> {
                    Thread t = new Thread(r, "JustLogin-Hash-" + ids.incrementAndGet());
                    t.setDaemon(true);
                    return t;
                },
                new ThreadPoolExecutor.AbortPolicy()
        );
    }

    public <T> CompletableFuture<T> submit(Supplier<T> work) {
        return submitForKey(null, work);
    }

    public <T> CompletableFuture<T> submitForKey(@Nullable String ipKey, Supplier<T> work) {
        AtomicInteger counter = null;
        if (ipKey != null && !ipKey.isEmpty()) {
            counter = inFlightByKey.computeIfAbsent(ipKey, k -> new AtomicInteger());
            int cur = counter.incrementAndGet();
            if (cur > maxPerKey) {
                counter.decrementAndGet();
                CompletableFuture<T> failed = new CompletableFuture<>();
                failed.completeExceptionally(new CompletionException(new HashingBusyException()));
                return failed;
            }
        }
        final AtomicInteger activeCounter = counter;
        try {
            return CompletableFuture.supplyAsync(() -> {
                try {
                    return work.get();
                } finally {
                    if (activeCounter != null && activeCounter.decrementAndGet() <= 0 && ipKey != null) {
                        inFlightByKey.remove(ipKey, activeCounter);
                    }
                }
            }, pool);
        } catch (RejectedExecutionException e) {
            if (activeCounter != null && activeCounter.decrementAndGet() <= 0 && ipKey != null) {
                inFlightByKey.remove(ipKey, activeCounter);
            }
            CompletableFuture<T> failed = new CompletableFuture<>();
            failed.completeExceptionally(new CompletionException(new HashingBusyException()));
            return failed;
        }
    }

    @Override
    public void close() {
        pool.shutdown();
        try {
            if (!pool.awaitTermination(10, TimeUnit.SECONDS)) pool.shutdownNow();
        } catch (InterruptedException e) {
            pool.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}

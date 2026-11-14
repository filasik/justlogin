package me.skerik.justlogin.core.security;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import me.skerik.justlogin.core.model.CoreSettings;

/**
 * Throttling and temporary lockouts keyed by {@code (nameLower, ipHash)} and separately by {@code ipHash}
 * (threat model #5, #6, #7: never locks an account globally across all IPs, preventing username DoS).
 */
public final class LoginRateLimiter {

    public record Decision(boolean allowed, long retryAfterMillis) {
        public static final Decision ALLOW = new Decision(true, 0);

        public long retryAfterSeconds() {
            return Math.max(1L, (retryAfterMillis + 999L) / 1000L);
        }
    }

    private static final class Bucket {
        int failures;
        int inFlight;
        long blockedUntil;
        long lastFailureAt;
    }

    private final Map<String, Bucket> accountIpBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> ipBuckets = new ConcurrentHashMap<>();
    private final LongSupplier clock;

    public LoginRateLimiter(LongSupplier clock) {
        this.clock = clock;
    }

    public Decision check(String nameLower, String ipHash, CoreSettings settings) {
        long now = clock.getAsLong();
        Decision ipDecision = checkBucket(ipBuckets.get(ipHash), now);
        Decision acctDecision = checkBucket(accountIpBuckets.get(pairKey(nameLower, ipHash)), now);
        if (ipDecision.allowed()) return acctDecision;
        if (acctDecision.allowed()) return ipDecision;
        return acctDecision.retryAfterMillis() >= ipDecision.retryAfterMillis() ? acctDecision : ipDecision;
    }

    /**
     * Atomically checks and reserves an in-flight attempt slot BEFORE hashing (P0-4), preventing concurrent
     * requests from bypassing {@code maxLoginAttemptsPerAccountIp} or {@code maxLoginAttemptsPerIp}.
     */
    public Decision tryAcquire(String nameLower, String ipHash, CoreSettings settings) {
        long now = clock.getAsLong();
        long acctLockoutMs = settings.lockoutSeconds() * 1000L;
        long ipLockoutMs = settings.lockoutSeconds() * 2000L;
        Bucket acctB = accountIpBuckets.computeIfAbsent(pairKey(nameLower, ipHash), k -> new Bucket());
        Bucket ipB = ipBuckets.computeIfAbsent(ipHash, k -> new Bucket());

        synchronized (ipB) {
            resetIfWindowExpired(ipB, now, ipLockoutMs);
            if (ipB.blockedUntil > now) {
                return new Decision(false, ipB.blockedUntil - now);
            }
            if (ipB.failures + ipB.inFlight >= settings.maxLoginAttemptsPerIp()) {
                return new Decision(false, Math.max(1000L, ipLockoutMs));
            }
            synchronized (acctB) {
                resetIfWindowExpired(acctB, now, acctLockoutMs);
                if (acctB.blockedUntil > now) {
                    return new Decision(false, acctB.blockedUntil - now);
                }
                if (acctB.failures + acctB.inFlight >= settings.maxLoginAttemptsPerAccountIp()) {
                    return new Decision(false, Math.max(1000L, acctLockoutMs));
                }
                acctB.inFlight++;
                ipB.inFlight++;
                return Decision.ALLOW;
            }
        }
    }

    public void releaseInFlight(String nameLower, String ipHash) {
        Bucket acctB = accountIpBuckets.get(pairKey(nameLower, ipHash));
        if (acctB != null) {
            synchronized (acctB) {
                if (acctB.inFlight > 0) acctB.inFlight--;
            }
        }
        Bucket ipB = ipBuckets.get(ipHash);
        if (ipB != null) {
            synchronized (ipB) {
                if (ipB.inFlight > 0) ipB.inFlight--;
            }
        }
    }

    public boolean recordFailure(String nameLower, String ipHash, CoreSettings settings) {
        long now = clock.getAsLong();
        boolean acctLocked = updateBucket(accountIpBuckets.computeIfAbsent(pairKey(nameLower, ipHash), k -> new Bucket()),
                now, settings.maxLoginAttemptsPerAccountIp(), 3,
                settings.baseBackoffMillis(), settings.lockoutSeconds() * 1000L);
        int ipMax = settings.maxLoginAttemptsPerIp();
        boolean ipLocked = updateBucket(ipBuckets.computeIfAbsent(ipHash, k -> new Bucket()),
                now, ipMax, ipMax,
                settings.baseBackoffMillis(), settings.lockoutSeconds() * 2000L);
        return acctLocked || ipLocked;
    }

    public void recordSuccess(String nameLower, String ipHash) {
        accountIpBuckets.remove(pairKey(nameLower, ipHash));
        Bucket ipB = ipBuckets.get(ipHash);
        if (ipB != null) {
            synchronized (ipB) {
                if (ipB.inFlight > 0) ipB.inFlight--;
            }
        }
    }

    public void pruneExpired(long maxIdleMillis) {
        long now = clock.getAsLong();
        pruneMap(accountIpBuckets, now, maxIdleMillis);
        pruneMap(ipBuckets, now, maxIdleMillis);
    }

    private static Decision checkBucket(Bucket b, long now) {
        if (b == null) return Decision.ALLOW;
        synchronized (b) {
            if (b.blockedUntil > now) {
                return new Decision(false, b.blockedUntil - now);
            }
            return Decision.ALLOW;
        }
    }

    private static void resetIfWindowExpired(Bucket b, long now, long lockoutMs) {
        if (b.inFlight == 0 && b.lastFailureAt > 0 && now - b.lastFailureAt > Math.max(lockoutMs, 300_000L)) {
            b.failures = 0;
            b.blockedUntil = 0;
        }
    }

    private static boolean updateBucket(
            Bucket b, long now, int maxAttempts, int backoffThreshold, long baseBackoffMs, long lockoutMs) {
        synchronized (b) {
            if (b.inFlight > 0) b.inFlight--;
            resetIfWindowExpired(b, now, lockoutMs);
            b.failures++;
            b.lastFailureAt = now;
            if (b.failures >= maxAttempts) {
                b.blockedUntil = now + lockoutMs;
                b.failures = 0;
                return true;
            } else if (b.failures >= backoffThreshold && baseBackoffMs > 0) {
                long delay = Math.min(lockoutMs, baseBackoffMs << Math.min(6, b.failures - backoffThreshold));
                b.blockedUntil = Math.max(b.blockedUntil, now + delay);
            }
            return false;
        }
    }

    private static void pruneMap(Map<String, Bucket> map, long now, long maxIdleMs) {
        Iterator<Map.Entry<String, Bucket>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            Bucket b = it.next().getValue();
            synchronized (b) {
                if (b.inFlight == 0 && b.blockedUntil <= now && now - b.lastFailureAt > maxIdleMs) {
                    it.remove();
                }
            }
        }
    }

    private static String pairKey(String nameLower, String ipHash) {
        return nameLower + "|" + ipHash;
    }
}

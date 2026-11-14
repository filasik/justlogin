package me.skerik.justlogin.paper.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import org.jspecify.annotations.Nullable;

/** Pre-auth alphanumeric captcha challenges triggered on registration or after failed attempts. */
public final class CaptchaManager {

    private static final char[] ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();
    private static final SecureRandom RNG = new SecureRandom();

    public record Challenge(String code, long expiresAt, boolean solved) {
    }

    private final LongSupplier clock;
    private final Map<String, Integer> failuresByName = new ConcurrentHashMap<>();
    private final Map<String, Challenge> challengesByName = new ConcurrentHashMap<>();

    public CaptchaManager(LongSupplier clock) {
        this.clock = clock;
    }

    public @Nullable Challenge getPending(String nameLower) {
        Challenge ch = challengesByName.get(nameLower);
        if (ch == null) return null;
        if (ch.expiresAt() < clock.getAsLong()) {
            challengesByName.remove(nameLower, ch);
            return null;
        }
        return ch.solved() ? null : ch;
    }

    public @Nullable Challenge ensureRequiredForRegister(
            String nameLower, boolean enabled, boolean requireOnRegister, int length, int expireSeconds) {
        if (!enabled || !requireOnRegister) return null;
        Challenge existing = challengesByName.get(nameLower);
        long now = clock.getAsLong();
        if (existing != null && existing.expiresAt() >= now) {
            return existing.solved() ? null : existing;
        }
        Challenge created = new Challenge(randomCode(length), now + Math.max(30L, expireSeconds) * 1000L, false);
        challengesByName.put(nameLower, created);
        return created;
    }

    public @Nullable Challenge recordFailure(
            String nameLower, boolean enabled, int triggerAfterFailures, int length, int expireSeconds) {
        if (!enabled || triggerAfterFailures <= 0) return null;
        int count = failuresByName.merge(nameLower, 1, Integer::sum);
        if (count < triggerAfterFailures) return null;
        Challenge existing = getPending(nameLower);
        if (existing != null) return existing;
        long now = clock.getAsLong();
        Challenge created = new Challenge(randomCode(length), now + Math.max(30L, expireSeconds) * 1000L, false);
        challengesByName.put(nameLower, created);
        return created;
    }

    public boolean verify(String nameLower, String candidate) {
        Challenge ch = challengesByName.get(nameLower);
        long now = clock.getAsLong();
        if (ch == null || ch.expiresAt() < now || candidate == null) {
            if (ch != null && ch.expiresAt() < now) challengesByName.remove(nameLower, ch);
            return false;
        }
        String norm = candidate.trim().toUpperCase(Locale.ROOT);
        boolean ok = MessageDigest.isEqual(
                ch.code().getBytes(StandardCharsets.UTF_8),
                norm.getBytes(StandardCharsets.UTF_8));
        if (!ok) return false;
        challengesByName.put(nameLower, new Challenge(ch.code(), ch.expiresAt(), true));
        failuresByName.remove(nameLower);
        return true;
    }

    public void clear(String nameLower) {
        failuresByName.remove(nameLower);
        challengesByName.remove(nameLower);
    }

    public void pruneExpired() {
        long now = clock.getAsLong();
        Iterator<Map.Entry<String, Challenge>> it = challengesByName.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue().expiresAt() < now) it.remove();
        }
    }

    private static String randomCode(int length) {
        int len = Math.max(4, Math.min(10, length));
        char[] buf = new char[len];
        for (int i = 0; i < len; i++) {
            buf[i] = ALPHABET[RNG.nextInt(ALPHABET.length)];
        }
        return new String(buf);
    }
}

package me.skerik.justlogin.core.service;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import org.jspecify.annotations.Nullable;

/**
 * Asynchronous Mojang profile lookup client with short TTL cache (used only when {@code premium.auto-detect}
 * is explicitly enabled). Lookup results are hints only; premium status is never granted without an actual
 * online-mode handshake (threat model #3).
 */
public final class MojangApiClient {

    public enum Status {
        PREMIUM,
        NOT_FOUND,
        RATE_LIMITED,
        ERROR
    }

    public record LookupResult(Status status, @Nullable UUID uuid, @Nullable String canonicalName) {
    }

    private record CacheEntry(LookupResult result, long expiresAt) {
    }

    private final HttpClient http;
    private final String baseUrl;
    private final LongSupplier clock;
    private final LongSupplier cacheSecondsSupplier;
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public MojangApiClient(long cacheSeconds, LongSupplier clock) {
        this("https://api.minecraftservices.com/minecraft/profile/lookup/name/", cacheSeconds, clock);
    }

    public MojangApiClient(LongSupplier cacheSecondsSupplier, LongSupplier clock) {
        this("https://api.minecraftservices.com/minecraft/profile/lookup/name/", cacheSecondsSupplier, clock);
    }

    public MojangApiClient(String baseUrl, long cacheSeconds, LongSupplier clock) {
        this(baseUrl, () -> cacheSeconds, clock);
    }

    public MojangApiClient(String baseUrl, LongSupplier cacheSecondsSupplier, LongSupplier clock) {
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
        this.cacheSecondsSupplier = cacheSecondsSupplier;
        this.clock = clock;
    }

    public void clearCache() {
        cache.clear();
    }

    public CompletableFuture<LookupResult> lookup(String username) {
        String lower = username.toLowerCase(Locale.ROOT);
        long now = clock.getAsLong();
        CacheEntry cached = cache.get(lower);
        if (cached != null && cached.expiresAt() > now) {
            return CompletableFuture.completedFuture(cached.result());
        }

        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + username))
                .timeout(Duration.ofSeconds(5))
                .header("Accept", "application/json")
                .header("User-Agent", "JustLogin")
                .GET()
                .build();

        return http.sendAsync(req, HttpResponse.BodyHandlers.ofString()).thenApply(resp -> {
            int code = resp.statusCode();
            if (code == 200) {
                JsonObject obj = JsonParser.parseString(resp.body()).getAsJsonObject();
                UUID id = parseUndashedUuid(obj.get("id").getAsString());
                String name = obj.has("name") ? obj.get("name").getAsString() : username;
                LookupResult res = new LookupResult(Status.PREMIUM, id, name);
                putCache(lower, res, now);
                return res;
            }
            if (code == 404 || code == 204) {
                LookupResult res = new LookupResult(Status.NOT_FOUND, null, null);
                putCache(lower, res, now);
                return res;
            }
            if (code == 429) {
                return new LookupResult(Status.RATE_LIMITED, null, null);
            }
            return new LookupResult(Status.ERROR, null, null);
        }).exceptionally(ex -> new LookupResult(Status.ERROR, null, null));
    }

    private void putCache(String lower, LookupResult res, long now) {
        long cacheMillis = Math.max(0L, cacheSecondsSupplier.getAsLong()) * 1000L;
        if (cacheMillis <= 0) return;
        if (cache.size() > 4096) cache.clear();
        cache.put(lower, new CacheEntry(res, now + cacheMillis));
    }

    public static UUID parseUndashedUuid(String hex) {
        String clean = hex.replace("-", "");
        if (clean.length() != 32) throw new IllegalArgumentException("Invalid UUID hex: " + hex);
        String dashed = clean.substring(0, 8) + "-" + clean.substring(8, 12) + "-"
                + clean.substring(12, 16) + "-" + clean.substring(16, 20) + "-" + clean.substring(20);
        return UUID.fromString(dashed);
    }
}

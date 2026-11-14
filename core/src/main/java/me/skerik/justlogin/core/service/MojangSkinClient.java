package me.skerik.justlogin.core.service;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
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
import me.skerik.justlogin.core.security.UsernameValidator;
import org.jspecify.annotations.Nullable;

/**
 * Asynchronous Mojang SessionServer client that fetches signed skin {@code textures} properties
 * ({@code value} + {@code signature}) for a Mojang username with bounded TTL caching.
 * Fail-open: callers must never block authentication if Mojang is unreachable or rate-limited.
 */
public final class MojangSkinClient {

    public static final String DEFAULT_PROFILE_URL =
            "https://sessionserver.mojang.com/session/minecraft/profile/";
    private static final long NEGATIVE_UNAVAILABLE_TTL_MS = 15_000L;
    private static final long RATE_LIMITED_TTL_MS = 30_000L;

    public enum Status {
        FOUND,
        NOT_FOUND,
        RATE_LIMITED,
        UNAVAILABLE
    }

    public record SkinData(
            String ownerName,
            UUID uuid,
            String value,
            String signature
    ) {
    }

    public record SkinLookupResult(
            Status status,
            @Nullable SkinData skin
    ) {
        public static SkinLookupResult found(SkinData skin) {
            return new SkinLookupResult(Status.FOUND, skin);
        }

        public static SkinLookupResult notFound() {
            return new SkinLookupResult(Status.NOT_FOUND, null);
        }

        public static SkinLookupResult rateLimited() {
            return new SkinLookupResult(Status.RATE_LIMITED, null);
        }

        public static SkinLookupResult unavailable() {
            return new SkinLookupResult(Status.UNAVAILABLE, null);
        }
    }

    private record CacheEntry(SkinLookupResult result, long expiresAtMillis) {
    }

    private final MojangApiClient mojangApi;
    private final HttpClient http;
    private final String sessionProfileBaseUrl;
    private final Duration requestTimeout;
    private final LongSupplier cacheSecondsSupplier;
    private final LongSupplier clock;
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public MojangSkinClient(
            MojangApiClient mojangApi,
            LongSupplier cacheSecondsSupplier,
            LongSupplier clock
    ) {
        this(mojangApi, DEFAULT_PROFILE_URL, 3000L, cacheSecondsSupplier, clock);
    }

    public MojangSkinClient(
            MojangApiClient mojangApi,
            String sessionProfileBaseUrl,
            long requestTimeoutMillis,
            LongSupplier cacheSecondsSupplier,
            LongSupplier clock
    ) {
        this.mojangApi = mojangApi;
        this.sessionProfileBaseUrl = sessionProfileBaseUrl.endsWith("/")
                ? sessionProfileBaseUrl
                : sessionProfileBaseUrl + "/";
        long timeoutMs = Math.max(500L, requestTimeoutMillis);
        this.requestTimeout = Duration.ofMillis(timeoutMs);
        this.http = HttpClient.newBuilder().connectTimeout(this.requestTimeout).build();
        this.cacheSecondsSupplier = cacheSecondsSupplier;
        this.clock = clock;
    }

    /** Clears all cached skin lookups (for example on config reload). */
    public void clearCache() {
        cache.clear();
        mojangApi.clearCache();
    }

    public CompletableFuture<SkinLookupResult> fetchByUsername(String username) {
        if (username == null || username.isBlank()) {
            return CompletableFuture.completedFuture(SkinLookupResult.notFound());
        }
        String key = UsernameValidator.normalizeLower(username.strip());
        long now = clock.getAsLong();
        CacheEntry cached = cache.get(key);
        if (cached != null && now < cached.expiresAtMillis()) {
            return CompletableFuture.completedFuture(cached.result());
        }

        return mojangApi.lookup(username.strip()).thenCompose(lookup -> switch (lookup.status()) {
            case NOT_FOUND -> {
                SkinLookupResult nf = SkinLookupResult.notFound();
                putCache(key, nf, positiveCacheMillis(), clock.getAsLong());
                yield CompletableFuture.completedFuture(nf);
            }
            case RATE_LIMITED -> {
                SkinLookupResult rl = SkinLookupResult.rateLimited();
                putCache(key, rl, RATE_LIMITED_TTL_MS, clock.getAsLong());
                yield CompletableFuture.completedFuture(rl);
            }
            case ERROR -> {
                SkinLookupResult unavail = SkinLookupResult.unavailable();
                putCache(key, unavail, NEGATIVE_UNAVAILABLE_TTL_MS, clock.getAsLong());
                yield CompletableFuture.completedFuture(unavail);
            }
            case PREMIUM -> {
                if (lookup.uuid() == null) {
                    yield CompletableFuture.completedFuture(SkinLookupResult.unavailable());
                }
                String resolvedName = lookup.canonicalName() != null ? lookup.canonicalName() : username.strip();
                yield fetchSignedProfile(key, lookup.uuid(), resolvedName);
            }
        });
    }

    private CompletableFuture<SkinLookupResult> fetchSignedProfile(String cacheKey, UUID uuid, String fallbackName) {
        String undashed = uuid.toString().replace("-", "").toLowerCase(Locale.ROOT);
        URI uri = URI.create(sessionProfileBaseUrl + undashed + "?unsigned=false");
        HttpRequest req = HttpRequest.newBuilder(uri)
                .timeout(requestTimeout)
                .header("Accept", "application/json")
                .header("User-Agent", "JustLogin")
                .GET()
                .build();

        return http.sendAsync(req, HttpResponse.BodyHandlers.ofString()).thenApply(resp -> {
            long now = clock.getAsLong();
            int code = resp.statusCode();
            if (code == 204 || code == 404) {
                SkinLookupResult nf = SkinLookupResult.notFound();
                putCache(cacheKey, nf, positiveCacheMillis(), now);
                return nf;
            }
            if (code == 429) {
                SkinLookupResult rl = SkinLookupResult.rateLimited();
                putCache(cacheKey, rl, RATE_LIMITED_TTL_MS, now);
                return rl;
            }
            if (code != 200) {
                SkinLookupResult unavail = SkinLookupResult.unavailable();
                putCache(cacheKey, unavail, NEGATIVE_UNAVAILABLE_TTL_MS, now);
                return unavail;
            }

            SkinData parsed = parseSignedSkin(resp.body(), uuid, fallbackName);
            if (parsed == null) {
                SkinLookupResult nf = SkinLookupResult.notFound();
                putCache(cacheKey, nf, Math.min(positiveCacheMillis(), RATE_LIMITED_TTL_MS), now);
                return nf;
            }
            SkinLookupResult found = SkinLookupResult.found(parsed);
            putCache(cacheKey, found, positiveCacheMillis(), now);
            return found;
        }).exceptionally(ex -> {
            SkinLookupResult unavail = SkinLookupResult.unavailable();
            putCache(cacheKey, unavail, NEGATIVE_UNAVAILABLE_TTL_MS, clock.getAsLong());
            return unavail;
        });
    }

    static @Nullable SkinData parseSignedSkin(@Nullable String body, UUID fallbackUuid, String fallbackName) {
        if (body == null || body.isBlank()) {
            return null;
        }
        try {
            JsonObject obj = JsonParser.parseString(body).getAsJsonObject();
            String owner = obj.has("name") && !obj.get("name").isJsonNull()
                    ? obj.get("name").getAsString()
                    : fallbackName;
            UUID parsedUuid = obj.has("id") && !obj.get("id").isJsonNull()
                    ? MojangApiClient.parseUndashedUuid(obj.get("id").getAsString())
                    : fallbackUuid;
            if (!obj.has("properties") || !obj.get("properties").isJsonArray()) {
                return null;
            }
            JsonArray props = obj.getAsJsonArray("properties");
            for (JsonElement el : props) {
                if (!el.isJsonObject()) continue;
                JsonObject prop = el.getAsJsonObject();
                String propName = prop.has("name") && !prop.get("name").isJsonNull()
                        ? prop.get("name").getAsString()
                        : null;
                if (!"textures".equals(propName)) continue;
                String val = prop.has("value") && !prop.get("value").isJsonNull()
                        ? prop.get("value").getAsString()
                        : null;
                String sig = prop.has("signature") && !prop.get("signature").isJsonNull()
                        ? prop.get("signature").getAsString()
                        : null;
                if (val != null && !val.isBlank() && sig != null && !sig.isBlank()) {
                    return new SkinData(owner, parsedUuid, val, sig);
                }
            }
            return null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private long positiveCacheMillis() {
        return Math.max(10L, cacheSecondsSupplier.getAsLong()) * 1000L;
    }

    private void putCache(String key, SkinLookupResult result, long ttlMillis, long now) {
        if (ttlMillis <= 0L) return;
        if (cache.size() > 4096) {
            cache.clear();
        }
        cache.put(key, new CacheEntry(result, now + ttlMillis));
    }
}

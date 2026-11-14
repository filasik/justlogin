package me.skerik.justlogin.core.service;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.jspecify.annotations.Nullable;

/**
 * Asynchronous Mojang SessionServer {@code hasJoined} client and Minecraft protocol server-ID digest
 * computation used by standalone Paper premium verification.
 */
public final class MojangSessionClient {

    public static final String DEFAULT_HAS_JOINED_URL =
            "https://sessionserver.mojang.com/session/minecraft/hasJoined";

    public enum Status {
        VERIFIED,
        NOT_AUTHENTICATED,
        UNAVAILABLE
    }

    public record HasJoinedResult(
            Status status,
            @Nullable UUID uuid,
            @Nullable String name,
            @Nullable String texturesValue,
            @Nullable String texturesSignature
    ) {
        public static HasJoinedResult notAuthenticated() {
            return new HasJoinedResult(Status.NOT_AUTHENTICATED, null, null, null, null);
        }

        public static HasJoinedResult unavailable() {
            return new HasJoinedResult(Status.UNAVAILABLE, null, null, null, null);
        }
    }

    private final HttpClient http;
    private final String hasJoinedBaseUrl;

    public MojangSessionClient() {
        this(DEFAULT_HAS_JOINED_URL);
    }

    public MojangSessionClient(String hasJoinedBaseUrl) {
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        this.hasJoinedBaseUrl = hasJoinedBaseUrl;
    }

    /**
     * Computes Minecraft's signed two's-complement SHA-1 hex digest from serverId, shared secret,
     * and DER-encoded RSA public key.
     */
    public static String computeServerIdHash(String serverId, byte[] encodedPublicKey, byte[] sharedSecret) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(serverId.getBytes(StandardCharsets.ISO_8859_1));
            md.update(sharedSecret);
            md.update(encodedPublicKey);
            return new BigInteger(md.digest()).toString(16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Missing SHA-1 MessageDigest", e);
        }
    }

    public CompletableFuture<HasJoinedResult> verifyHasJoined(
            String username, String serverIdHash, @Nullable String clientIp) {
        StringBuilder url = new StringBuilder(hasJoinedBaseUrl)
                .append("?username=").append(URLEncoder.encode(username, StandardCharsets.UTF_8))
                .append("&serverId=").append(URLEncoder.encode(serverIdHash, StandardCharsets.UTF_8));
        if (clientIp != null && !clientIp.isBlank()) {
            url.append("&ip=").append(URLEncoder.encode(clientIp, StandardCharsets.UTF_8));
        }

        HttpRequest req = HttpRequest.newBuilder(URI.create(url.toString()))
                .timeout(Duration.ofSeconds(5))
                .header("Accept", "application/json")
                .header("User-Agent", "JustLogin")
                .GET()
                .build();

        return http.sendAsync(req, HttpResponse.BodyHandlers.ofString()).thenApply(resp -> {
            int code = resp.statusCode();
            if (code == 204 || code == 404) {
                return HasJoinedResult.notAuthenticated();
            }
            if (code != 200) {
                return HasJoinedResult.unavailable();
            }
            try {
                JsonObject obj = JsonParser.parseString(resp.body()).getAsJsonObject();
                if (!obj.has("id") || !obj.has("name")) {
                    return HasJoinedResult.unavailable();
                }
                UUID uuid = MojangApiClient.parseUndashedUuid(obj.get("id").getAsString());
                String canonicalName = obj.get("name").getAsString();
                String texturesValue = null;
                String texturesSignature = null;
                if (obj.has("properties") && obj.get("properties").isJsonArray()) {
                    for (JsonElement el : obj.getAsJsonArray("properties")) {
                        if (!el.isJsonObject()) continue;
                        JsonObject prop = el.getAsJsonObject();
                        if (!prop.has("name") || !"textures".equals(prop.get("name").getAsString())) continue;
                        if (prop.has("value") && !prop.get("value").isJsonNull()) {
                            texturesValue = prop.get("value").getAsString();
                        }
                        if (prop.has("signature") && !prop.get("signature").isJsonNull()) {
                            texturesSignature = prop.get("signature").getAsString();
                        }
                        break;
                    }
                }
                return new HasJoinedResult(
                        Status.VERIFIED, uuid, canonicalName, texturesValue, texturesSignature);
            } catch (Exception e) {
                return HasJoinedResult.unavailable();
            }
        }).exceptionally(ex -> HasJoinedResult.unavailable());
    }
}

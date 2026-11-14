package me.skerik.justlogin.editor;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

/** Asynchronous client for a bytebin-compatible encrypted blob relay. */
public final class BytebinClient {

    private final HttpClient http;
    private final String relayUrl;

    public BytebinClient(String relayUrl) {
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8)).build();
        this.relayUrl = relayUrl.endsWith("/") ? relayUrl.substring(0, relayUrl.length() - 1) : relayUrl;
    }

    public CompletableFuture<String> upload(String encryptedJson) {
        HttpRequest req = HttpRequest.newBuilder(URI.create(relayUrl + "/post"))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json; charset=utf-8")
                .header("User-Agent", "JustLogin-Editor")
                .POST(HttpRequest.BodyPublishers.ofString(encryptedJson))
                .build();

        return http.sendAsync(req, HttpResponse.BodyHandlers.ofString()).thenApply(resp -> {
            if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
                throw new IllegalStateException("Relay upload failed: HTTP " + resp.statusCode());
            }
            JsonObject obj = JsonParser.parseString(resp.body()).getAsJsonObject();
            if (!obj.has("key")) throw new IllegalStateException("Relay response missing 'key'");
            return obj.get("key").getAsString();
        });
    }

    public CompletableFuture<String> download(String code) {
        if (code == null || !code.matches("^[a-zA-Z0-9_-]{1,64}$")) {
            return CompletableFuture.failedFuture(new IllegalArgumentException("Invalid editor code format"));
        }
        HttpRequest req = HttpRequest.newBuilder(URI.create(relayUrl + "/" + code))
                .timeout(Duration.ofSeconds(10))
                .header("Accept", "application/json")
                .header("User-Agent", "JustLogin-Editor")
                .GET()
                .build();

        return http.sendAsync(req, HttpResponse.BodyHandlers.ofString()).thenApply(resp -> {
            if (resp.statusCode() != 200) {
                throw new IllegalStateException("Relay download failed: HTTP " + resp.statusCode());
            }
            return resp.body();
        });
    }
}

package me.skerik.justlogin.paper.util;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.logging.Logger;
import org.jspecify.annotations.Nullable;

/** Looks at the latest GitHub release (async, no auth, no personal data sent) and remembers the result. */
public final class UpdateChecker {

    private static final URI LATEST = URI.create("https://api.github.com/repos/filasik/justLogin/releases/latest");

    private final String current;
    private final Logger log;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8)).build();
    private volatile @Nullable String newer;
    private volatile @Nullable String url;

    public UpdateChecker(String currentVersion, Logger log) {
        this.current = currentVersion;
        this.log = log;
    }

    /** Blocking; call from an async task only. */
    public void check() {
        try {
            HttpRequest request = HttpRequest.newBuilder(LATEST)
                    .timeout(Duration.ofSeconds(10))
                    .header("Accept", "application/vnd.github+json")
                    .header("User-Agent", "JustLogin/" + current)
                    .GET()
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                log.fine("Update check: HTTP " + response.statusCode());
                return;
            }
            String tag = parseLatestVersion(response.body());
            JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
            if (tag != null && isNewer(current, tag)) {
                newer = tag.startsWith("v") ? tag.substring(1) : tag;
                url = json.has("html_url") && !json.get("html_url").isJsonNull()
                        ? json.get("html_url").getAsString()
                        : Banner.REPO + "/releases";
                log.info("A new version of JustLogin is available: " + newer + " (running " + current + ") " + url);
            } else {
                newer = null;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            log.fine("Update check failed: " + e.getMessage());
        }
    }

    public @Nullable String newerVersion() {
        return newer;
    }

    public @Nullable String url() {
        return url;
    }

    public static @Nullable String parseLatestVersion(String json) {
        try {
            JsonElement root = JsonParser.parseString(json);
            if (!root.isJsonObject()) return null;
            JsonObject obj = root.getAsJsonObject();
            JsonElement tag = obj.get("tag_name");
            return tag == null || tag.isJsonNull() ? null : tag.getAsString();
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean isNewer(String current, String latest) {
        int[] a = parseSemver(current);
        int[] b = parseSemver(latest);
        for (int i = 0; i < 3; i++) {
            if (b[i] != a[i]) return b[i] > a[i];
        }
        return current.contains("-") && !latest.contains("-");
    }

    private static int[] parseSemver(String raw) {
        String clean = raw.startsWith("v") ? raw.substring(1) : raw;
        int dash = clean.indexOf('-');
        if (dash >= 0) clean = clean.substring(0, dash);
        String[] parts = clean.split("\\.");
        int[] out = new int[3];
        for (int i = 0; i < Math.min(3, parts.length); i++) {
            try {
                out[i] = Integer.parseInt(parts[i].replaceAll("[^0-9]", ""));
            } catch (NumberFormatException ignored) {
            }
        }
        return out;
    }
}

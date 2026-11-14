package me.skerik.justlogin.editor;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

/**
 * Optional local loopback HTTP endpoint ("Varianta B") serving the static web editor UI and a
 * temporary in-memory Bytebin-compatible relay bound strictly to loopback (default {@code 127.0.0.1}).
 */
public final class LocalHttpEditorServer implements AutoCloseable {

    private static final int MAX_BODY_BYTES = 2 * 1024 * 1024;
    private static final int MAX_STORED_BLOBS = 64;
    private static final long BLOB_TTL_MILLIS = 30 * 60_000L;
    private static final SecureRandom RNG = new SecureRandom();
    private static final String INDEX_RESOURCE = "/web-editor/index.html";
    private static final String CSP = "default-src 'none'; script-src 'unsafe-inline'; "
            + "style-src 'unsafe-inline'; connect-src 'self' https: http://localhost:* http://127.0.0.1:*;";

    private record StoredBlob(byte[] json, long expiresAt) {
    }

    private final HttpServer server;
    private final int port;
    private final byte[] htmlBytes;
    private final Map<String, StoredBlob> blobs = new ConcurrentHashMap<>();

    private LocalHttpEditorServer(HttpServer server, int port, byte[] htmlBytes) {
        this.server = server;
        this.port = port;
        this.htmlBytes = htmlBytes;
    }

    public static LocalHttpEditorServer start(String bindHost, int port) throws IOException {
        String host = (bindHost == null || bindHost.isBlank()) ? "127.0.0.1" : bindHost.trim();
        InetAddress addr = InetAddress.getByName(host);
        if (!addr.isLoopbackAddress()) {
            throw new IllegalArgumentException(
                    "editor.local-http.bind must be a loopback address (e.g. 127.0.0.1), refused: " + host);
        }
        byte[] html = loadIndexHtml();
        HttpServer http = HttpServer.create(new InetSocketAddress(addr, port), 16);
        http.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        LocalHttpEditorServer instance = new LocalHttpEditorServer(http, http.getAddress().getPort(), html);
        http.createContext("/", instance::handle);
        http.start();
        return instance;
    }

    public int port() {
        return port;
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + port;
    }

    private void handle(HttpExchange ex) throws IOException {
        try (ex) {
            pruneExpired();
            if (!isAllowedHost(ex.getRequestHeaders())) {
                sendText(ex, 403, "{\"error\":\"forbidden host\"}");
                return;
            }
            String method = ex.getRequestMethod();
            String path = ex.getRequestURI().getPath();
            if ("GET".equals(method) && ("/".equals(path) || "/index.html".equals(path))) {
                Headers h = ex.getResponseHeaders();
                h.set("Content-Type", "text/html; charset=utf-8");
                h.set("Content-Security-Policy", CSP);
                h.set("X-Content-Type-Options", "nosniff");
                h.set("Cache-Control", "no-store");
                send(ex, 200, htmlBytes);
                return;
            }
            if ("POST".equals(method) && "/post".equals(path)) {
                if (!isAllowedOrigin(ex.getRequestHeaders())) {
                    sendText(ex, 403, "{\"error\":\"forbidden origin\"}");
                    return;
                }
                byte[] body = readBounded(ex.getRequestBody(), MAX_BODY_BYTES);
                if (body == null) {
                    sendText(ex, 413, "{\"error\":\"payload too large\"}");
                    return;
                }
                if (blobs.size() >= MAX_STORED_BLOBS) {
                    evictOldest();
                }
                String key = randomKey();
                blobs.put(key, new StoredBlob(body, System.currentTimeMillis() + BLOB_TTL_MILLIS));
                ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                ex.getResponseHeaders().set("Cache-Control", "no-store");
                send(ex, 201, ("{\"key\":\"" + key + "\"}").getBytes(StandardCharsets.UTF_8));
                return;
            }
            if ("GET".equals(method) && path != null && path.length() > 1) {
                String key = path.substring(1);
                if (!key.matches("^[a-zA-Z0-9_-]{1,64}$")) {
                    sendText(ex, 404, "{\"error\":\"not found\"}");
                    return;
                }
                StoredBlob blob = blobs.get(key);
                if (blob == null || blob.expiresAt() < System.currentTimeMillis()) {
                    blobs.remove(key);
                    sendText(ex, 404, "{\"error\":\"not found\"}");
                    return;
                }
                ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                ex.getResponseHeaders().set("Cache-Control", "no-store");
                send(ex, 200, blob.json());
                return;
            }
            sendText(ex, 404, "{\"error\":\"not found\"}");
        }
    }

    private boolean isAllowedHost(Headers reqHeaders) {
        List<String> hosts = reqHeaders.get("Host");
        if (hosts == null || hosts.size() != 1) {
            return false;
        }
        String h = hosts.getFirst().trim().toLowerCase(Locale.ROOT);
        return h.equals("127.0.0.1")
                || h.equals("127.0.0.1:" + port)
                || h.equals("localhost")
                || h.equals("localhost:" + port)
                || h.equals("[::1]")
                || h.equals("[::1]:" + port);
    }

    private static boolean isAllowedOrigin(Headers reqHeaders) {
        String rawOrigin = reqHeaders.getFirst("Origin");
        if (rawOrigin == null || rawOrigin.isBlank()) {
            return true;
        }
        String o = rawOrigin.trim().toLowerCase(Locale.ROOT);
        return o.equals("https://justlogin.net")
                || o.matches("^http://(127\\.0\\.0\\.1|localhost|\\[::1\\])(:[0-9]{1,5})?$");
    }

    private void pruneExpired() {
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, StoredBlob>> it = blobs.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue().expiresAt() < now) it.remove();
        }
    }

    private void evictOldest() {
        String oldestKey = null;
        long oldestExp = Long.MAX_VALUE;
        for (Map.Entry<String, StoredBlob> e : blobs.entrySet()) {
            if (e.getValue().expiresAt() < oldestExp) {
                oldestExp = e.getValue().expiresAt();
                oldestKey = e.getKey();
            }
        }
        if (oldestKey != null) blobs.remove(oldestKey);
    }

    private static byte[] readBounded(InputStream in, int maxBytes) throws IOException {
        byte[] buf = in.readNBytes(maxBytes + 1);
        return buf.length > maxBytes ? null : buf;
    }

    private static void sendText(HttpExchange ex, int status, String json) throws IOException {
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        send(ex, status, json.getBytes(StandardCharsets.UTF_8));
    }

    private static void send(HttpExchange ex, int status, byte[] bytes) throws IOException {
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String randomKey() {
        byte[] b = new byte[9];
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static byte[] loadIndexHtml() throws IOException {
        try (InputStream in = LocalHttpEditorServer.class.getResourceAsStream(INDEX_RESOURCE)) {
            Objects.requireNonNull(in, "Missing bundled resource: " + INDEX_RESOURCE);
            return in.readAllBytes();
        }
    }

    @Override
    public void close() {
        blobs.clear();
        server.stop(0);
    }
}

package me.skerik.justlogin.core.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import me.skerik.justlogin.core.service.MojangSkinClient.Status;
import org.junit.jupiter.api.Test;

final class MojangSkinClientTest {

    @Test
    void fetchesSignedTexturesCachesSuccessAndRespectsReloadClear() throws Exception {
        UUID expectedUuid = UUID.fromString("069a79f4-44e9-4726-a5be-fca90e38aaf5");
        AtomicInteger nameHits = new AtomicInteger();
        AtomicInteger profileHits = new AtomicInteger();
        AtomicLong now = new AtomicLong(1_000_000L);

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        try {
            server.createContext("/names/", ex -> {
                nameHits.incrementAndGet();
                String path = ex.getRequestURI().getPath();
                String name = path.substring(path.lastIndexOf('/') + 1);
                if ("Notch".equalsIgnoreCase(name)) {
                    byte[] body = ("{\"id\":\"069a79f444e94726a5befca90e38aaf5\",\"name\":\"Notch\"}")
                            .getBytes(StandardCharsets.UTF_8);
                    ex.sendResponseHeaders(200, body.length);
                    try (OutputStream os = ex.getResponseBody()) {
                        os.write(body);
                    }
                } else {
                    ex.sendResponseHeaders(404, -1);
                }
                ex.close();
            });
            server.createContext("/profiles/", ex -> {
                profileHits.incrementAndGet();
                if ("unsigned=false".equals(ex.getRequestURI().getQuery())) {
                    byte[] body = ("{\"id\":\"069a79f444e94726a5befca90e38aaf5\",\"name\":\"Notch\","
                            + "\"properties\":[{\"name\":\"textures\",\"value\":\"VAL123\",\"signature\":\"SIG456\"}]}")
                            .getBytes(StandardCharsets.UTF_8);
                    ex.sendResponseHeaders(200, body.length);
                    try (OutputStream os = ex.getResponseBody()) {
                        os.write(body);
                    }
                } else {
                    ex.sendResponseHeaders(400, -1);
                }
                ex.close();
            });
            server.start();
            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            MojangApiClient nameApi = new MojangApiClient(base + "/names/", () -> 600L, now::get);
            MojangSkinClient skins = new MojangSkinClient(
                    nameApi, base + "/profiles/", 2000L, () -> 600L, now::get);

            var first = skins.fetchByUsername("notch").join();
            assertEquals(Status.FOUND, first.status());
            assertNotNull(first.skin());
            assertEquals("Notch", first.skin().ownerName());
            assertEquals(expectedUuid, first.skin().uuid());
            assertEquals("VAL123", first.skin().value());
            assertEquals("SIG456", first.skin().signature());
            assertEquals(1, nameHits.get());
            assertEquals(1, profileHits.get());

            // Second lookup hits in-memory TTL cache without HTTP traffic
            var cached = skins.fetchByUsername("NOTCH").join();
            assertEquals(Status.FOUND, cached.status());
            assertEquals(1, nameHits.get());
            assertEquals(1, profileHits.get());

            // Clearing cache forces fresh Mojang lookup
            skins.clearCache();
            var reloaded = skins.fetchByUsername("Notch").join();
            assertEquals(Status.FOUND, reloaded.status());
            assertEquals(2, nameHits.get());
            assertEquals(2, profileHits.get());

            var missing = skins.fetchByUsername("NoSuchAccountXYZ").join();
            assertEquals(Status.NOT_FOUND, missing.status());
            assertNull(missing.skin());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void handlesMissingSignatureRateLimitAndUnreachableFailOpen() throws Exception {
        AtomicLong now = new AtomicLong(5_000_000L);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        try {
            server.createContext("/names/", ex -> {
                String name = ex.getRequestURI().getPath();
                if (name.endsWith("RateLim")) {
                    ex.sendResponseHeaders(429, -1);
                } else {
                    byte[] body = ("{\"id\":\"069a79f444e94726a5befca90e38aaf5\",\"name\":\"NoSig\"}")
                            .getBytes(StandardCharsets.UTF_8);
                    ex.sendResponseHeaders(200, body.length);
                    try (OutputStream os = ex.getResponseBody()) {
                        os.write(body);
                    }
                }
                ex.close();
            });
            server.createContext("/profiles/", ex -> {
                byte[] body = ("{\"id\":\"069a79f444e94726a5befca90e38aaf5\",\"name\":\"NoSig\","
                        + "\"properties\":[{\"name\":\"textures\",\"value\":\"UNSIGNED_ONLY\"}]}")
                        .getBytes(StandardCharsets.UTF_8);
                ex.sendResponseHeaders(200, body.length);
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(body);
                }
                ex.close();
            });
            server.start();
            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            MojangApiClient api = new MojangApiClient(base + "/names/", () -> 600L, now::get);
            MojangSkinClient skins = new MojangSkinClient(api, base + "/profiles/", 1000L, () -> 600L, now::get);

            // Unsigned textures must not be treated as valid signed client skins
            var unsigned = skins.fetchByUsername("NoSig").join();
            assertEquals(Status.NOT_FOUND, unsigned.status());
            assertNull(unsigned.skin());

            var limited = skins.fetchByUsername("RateLim").join();
            assertEquals(Status.RATE_LIMITED, limited.status());
            assertNull(limited.skin());
        } finally {
            server.stop(0);
        }

        // Unreachable server fails open with UNAVAILABLE
        MojangApiClient downApi = new MojangApiClient("http://127.0.0.1:1/names/", () -> 600L, now::get);
        MojangSkinClient downSkins = new MojangSkinClient(
                downApi, "http://127.0.0.1:1/profiles/", 600L, () -> 600L, now::get);
        var failed = downSkins.fetchByUsername("Notch").join();
        assertEquals(Status.UNAVAILABLE, failed.status());
        assertNull(failed.skin());
    }
}

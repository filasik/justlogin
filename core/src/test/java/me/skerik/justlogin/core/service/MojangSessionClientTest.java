package me.skerik.justlogin.core.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class MojangSessionClientTest {

    /**
     * Independent reference implementation of Minecraft's signed 160-bit two's-complement SHA-1 hex
     * (bitwise invert + 1 for negative digests, no leading zeroes except single-zero digest).
     */
    private static String referenceSignedHex(String serverId, byte[] secret, byte[] pubKey) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(serverId.getBytes(StandardCharsets.ISO_8859_1));
        md.update(secret);
        md.update(pubKey);
        byte[] d = md.digest();
        boolean neg = (d[0] & 0x80) != 0;
        if (neg) {
            byte[] mag = Arrays.copyOf(d, d.length);
            for (int i = 0; i < mag.length; i++) {
                mag[i] = (byte) ~mag[i];
            }
            for (int i = mag.length - 1; i >= 0; i--) {
                int v = (mag[i] & 0xFF) + 1;
                mag[i] = (byte) v;
                if ((v & 0x100) == 0) break;
            }
            d = mag;
        }
        StringBuilder sb = new StringBuilder(neg ? "-" : "");
        boolean started = false;
        for (byte b : d) {
            int unsigned = b & 0xFF;
            if (!started) {
                if (unsigned == 0) continue;
                sb.append(Integer.toHexString(unsigned));
                started = true;
            } else {
                if (unsigned < 16) sb.append('0');
                sb.append(Integer.toHexString(unsigned));
            }
        }
        return started ? sb.toString() : "0";
    }

    @Test
    void computeServerIdHashCoversPositiveNegativeAndLeadingZeroDigests() throws Exception {
        boolean sawPositive = false;
        boolean sawNegative = false;
        boolean sawLeadingZeroNibble = false;
        byte[] fakeKey = new byte[] { 0x30, (byte) 0x81, (byte) 0x9f, 0x01, 0x02, 0x03 };

        for (int i = 0; i < 64 && !(sawPositive && sawNegative && sawLeadingZeroNibble); i++) {
            byte[] secret = new byte[] { (byte) i, (byte) (i * 31 + 7), 0x42 };
            String actual = MojangSessionClient.computeServerIdHash("", fakeKey, secret);
            String expected = referenceSignedHex("", secret, fakeKey);
            assertEquals(expected, actual);

            if (actual.startsWith("-")) {
                sawNegative = true;
            } else {
                sawPositive = true;
                if (actual.length() < 40) {
                    sawLeadingZeroNibble = true;
                }
            }
        }
        assertTrue(sawPositive);
        assertTrue(sawNegative);
        assertTrue(sawLeadingZeroNibble);
    }

    @Test
    void verifyHasJoinedHandlesVerified200NoContent204AndUnavailableErrors() throws Exception {
        AtomicReference<String> lastQuery = new AtomicReference<>();
        UUID expectedUuid = UUID.fromString("069a79f4-44e9-4726-a5be-fca90e38aaf5");
        String undashed = expectedUuid.toString().replace("-", "");

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        try {
            server.createContext("/hasJoined", ex -> {
                lastQuery.set(ex.getRequestURI().getRawQuery());
                String q = ex.getRequestURI().getRawQuery();
                if (q != null && q.contains("username=VerifiedUser")) {
                    byte[] body = ("""
                            {
                              "id": "%s",
                              "name": "VerifiedUser",
                              "properties": [
                                {"name": "ignored", "value": "x"},
                                {"name": "textures", "value": "eyJ0ZXh0dXJlcyI6e319", "signature": "sig123=="}
                              ]
                            }""").formatted(undashed).getBytes(StandardCharsets.UTF_8);
                    ex.sendResponseHeaders(200, body.length);
                    try (OutputStream os = ex.getResponseBody()) {
                        os.write(body);
                    }
                    return;
                }
                if (q != null && q.contains("username=NoPropsUser")) {
                    byte[] body = ("{\"id\":\"" + undashed + "\",\"name\":\"NoPropsUser\"}")
                            .getBytes(StandardCharsets.UTF_8);
                    ex.sendResponseHeaders(200, body.length);
                    try (OutputStream os = ex.getResponseBody()) {
                        os.write(body);
                    }
                    return;
                }
                if (q != null && q.contains("username=ServerError")) {
                    ex.sendResponseHeaders(500, -1);
                    ex.close();
                    return;
                }
                if (q != null && q.contains("username=MalformedJson")) {
                    byte[] body = "{not-json".getBytes(StandardCharsets.UTF_8);
                    ex.sendResponseHeaders(200, body.length);
                    try (OutputStream os = ex.getResponseBody()) {
                        os.write(body);
                    }
                    return;
                }
                if (q != null && q.contains("username=MissingFields")) {
                    byte[] body = "{\"name\":\"OnlyName\"}".getBytes(StandardCharsets.UTF_8);
                    ex.sendResponseHeaders(200, body.length);
                    try (OutputStream os = ex.getResponseBody()) {
                        os.write(body);
                    }
                    return;
                }
                if (q != null && q.contains("username=NotFound404")) {
                    ex.sendResponseHeaders(404, -1);
                    ex.close();
                    return;
                }
                ex.sendResponseHeaders(204, -1);
                ex.close();
            });
            server.start();

            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/hasJoined";
            MojangSessionClient client = new MojangSessionClient(baseUrl);

            MojangSessionClient.HasJoinedResult verified =
                    client.verifyHasJoined("VerifiedUser", "-12ab34", "203.0.113.5").join();
            assertEquals(MojangSessionClient.Status.VERIFIED, verified.status());
            assertEquals(expectedUuid, verified.uuid());
            assertEquals("VerifiedUser", verified.name());
            assertEquals("eyJ0ZXh0dXJlcyI6e319", verified.texturesValue());
            assertEquals("sig123==", verified.texturesSignature());
            assertEquals("username=VerifiedUser&serverId=-12ab34&ip=203.0.113.5", lastQuery.get());

            MojangSessionClient.HasJoinedResult noProps =
                    client.verifyHasJoined("NoPropsUser", "abc123", "   ").join();
            assertEquals(MojangSessionClient.Status.VERIFIED, noProps.status());
            assertNull(noProps.texturesValue());
            assertNull(noProps.texturesSignature());
            assertFalse(lastQuery.get().contains("ip="));

            MojangSessionClient.HasJoinedResult noContent =
                    client.verifyHasJoined("CrackedSpoof", "abc123", null).join();
            assertEquals(MojangSessionClient.Status.NOT_AUTHENTICATED, noContent.status());
            assertNull(noContent.uuid());

            assertEquals(MojangSessionClient.Status.NOT_AUTHENTICATED,
                    client.verifyHasJoined("NotFound404", "abc", null).join().status());
            assertEquals(MojangSessionClient.Status.UNAVAILABLE,
                    client.verifyHasJoined("ServerError", "abc", null).join().status());
            assertEquals(MojangSessionClient.Status.UNAVAILABLE,
                    client.verifyHasJoined("MalformedJson", "abc", null).join().status());
            assertEquals(MojangSessionClient.Status.UNAVAILABLE,
                    client.verifyHasJoined("MissingFields", "abc", null).join().status());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void verifyHasJoinedReturnsUnavailableWhenServerUnreachable() throws IOException {
        int deadPort;
        try (java.net.ServerSocket s = new java.net.ServerSocket(0)) {
            deadPort = s.getLocalPort();
        }
        MojangSessionClient client = new MojangSessionClient("http://127.0.0.1:" + deadPort + "/hasJoined");
        MojangSessionClient.HasJoinedResult res = client.verifyHasJoined("OfflineSrv", "0", null).join();
        assertEquals(MojangSessionClient.Status.UNAVAILABLE, res.status());
    }
}

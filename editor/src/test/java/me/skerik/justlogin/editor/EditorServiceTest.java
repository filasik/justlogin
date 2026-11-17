package me.skerik.justlogin.editor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import javax.crypto.SecretKey;
import me.skerik.justlogin.core.model.HashAlgorithm;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import me.skerik.justlogin.core.storage.Database;
import me.skerik.justlogin.core.storage.DbConfig;
import me.skerik.justlogin.core.storage.Migrations;
import org.junit.jupiter.api.Test;

class EditorServiceTest {

    private static final Gson GSON = new GsonBuilder().serializeNulls().create();

    @Test
    void exportExcludesSecretsDetectsConflictsAndAppliesOnce() throws Exception {
        Map<String, String> relayStore = new ConcurrentHashMap<>();
        AtomicInteger keySeq = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/post", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String key = "blob" + keySeq.incrementAndGet();
            relayStore.put(key, body);
            byte[] resp = GSON.toJson(Map.of("key", key)).getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, resp.length);
            ex.getResponseBody().write(resp);
            ex.close();
        });
        server.createContext("/", ex -> {
            String path = ex.getRequestURI().getPath().replaceAll("^/+", "");
            String val = relayStore.get(path);
            if (val == null) {
                ex.sendResponseHeaders(404, -1);
            } else {
                byte[] resp = val.getBytes(StandardCharsets.UTF_8);
                ex.sendResponseHeaders(200, resp.length);
                ex.getResponseBody().write(resp);
            }
            ex.close();
        });
        server.start();

        try (Database db = new Database(DbConfig.memory())) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            AuditStore audit = new AuditStore(db);
            AtomicLong now = new AtomicLong(1_700_000_000_000L);

            var alice = accounts.createAccount("alice", "Alice", UUID.randomUUID(), null,
                    "$argon2id$SECRET_HASH_MUST_NOT_LEAK", HashAlgorithm.ARGON2ID, false, false, now.get(), "SECRET_IP_HMAC").join();
            accounts.setTotpSecret(alice.id(), "v1:SECRET_TOTP_MUST_NOT_LEAK", 10L, now.get()).join();

            var bob = accounts.createAccount("bob", "Bob", UUID.randomUUID(), null,
                    "$argon2id$BOB_HASH", HashAlgorithm.ARGON2ID, null, false, now.get(), "BOB_IP_HMAC").join();
            var carol = accounts.createAccount("carol", "Carol", UUID.randomUUID(), null,
                    "$argon2id$CAROL_HASH", HashAlgorithm.ARGON2ID, false, false, now.get(), "CAROL_IP_HMAC").join();

            String relayUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            BytebinClient relay = new BytebinClient(relayUrl);
            EditorService editor = new EditorService(accounts, audit, now::get);

            EditorService.ExportSessionResult exported = editor.createSession(
                    1, 50, "https://example.invalid/editor", relay, EditorService.DEFAULT_TTL_MILLIS).join();
            assertEquals(3, exported.exportedCount());
            assertTrue(exported.editorUrl().contains("#"));
            String query = java.net.URI.create(exported.editorUrl()).getRawQuery();
            String encodedRelay = java.util.Arrays.stream(query.split("&"))
                    .filter(part -> part.startsWith("relay=")).findFirst().orElseThrow().substring(6);
            assertEquals(relayUrl, java.net.URLDecoder.decode(encodedRelay, java.nio.charset.StandardCharsets.UTF_8));

            // Threat #13: verify decrypted export JSON excludes hashes, TOTP secrets, and IP hashes
            String fragmentKey = exported.editorUrl().substring(exported.editorUrl().indexOf('#') + 1);
            SecretKey aesKey = EditorCrypto.decodeKey(fragmentKey);
            EditorCrypto.EncryptedEnvelope rawEnv = GSON.fromJson(relayStore.get(exported.blobKey()), EditorCrypto.EncryptedEnvelope.class);
            String plainExport = EditorCrypto.decrypt(aesKey, rawEnv);
            assertFalse(plainExport.contains("SECRET_HASH_MUST_NOT_LEAK"));
            assertFalse(plainExport.contains("SECRET_TOTP_MUST_NOT_LEAK"));
            assertFalse(plainExport.contains("SECRET_IP_HMAC"));
            assertTrue(plainExport.contains("\"hasTotp\":true"));

            // Modify Bob concurrently in DB before edits return -> Bob must be flagged as conflict and skipped!
            now.addAndGet(5000L);
            accounts.updateLoginSuccess(bob.id(), "Bob", "NEW_IP", now.get()).join();

            // Simulate web editor returning encrypted changes: update Alice, update Bob (conflicted), delete Carol
            EditorModels.EditorChanges returned = new EditorModels.EditorChanges(
                    exported.sessionId(),
                    List.of(
                            new EditorModels.AccountUpdate(alice.id(), true, true),
                            new EditorModels.AccountUpdate(bob.id(), true, false)
                    ),
                    List.of(carol.id())
            );
            String editCode = relay.upload(GSON.toJson(EditorCrypto.encrypt(aesKey, GSON.toJson(returned)))).join();

            EditorModels.PendingEditPlan plan = editor.prepareApply("admin1", editCode, relay).join();
            assertEquals(2, plan.changes().size()); // Alice update + Carol delete
            assertEquals(1, plan.conflicts().size()); // Bob skipped
            assertEquals("Bob", plan.conflicts().getFirst().name());

            EditorModels.ApplyReport report = editor.confirmAndApply("admin1", "AdminOne").join();
            assertEquals(2, report.applied());
            assertEquals(0, report.skippedConflicts());
            assertEquals(List.of("Carol", "Alice"), report.affectedNames());
            assertEquals(List.of(carol.id(), alice.id()), report.affectedIds());

            var aliceAfter = accounts.findById(alice.id()).join().orElseThrow();
            assertTrue(aliceAfter.isPremiumConfirmed());
            assertTrue(aliceAfter.forcePasswordChange());
            assertFalse(Boolean.TRUE.equals(accounts.findById(bob.id()).join().orElseThrow().premium()));
            assertTrue(accounts.findById(carol.id()).join().isEmpty());

            // One-time code / session cannot be replayed or applied twice
            assertThrows(Exception.class, () -> editor.prepareApply("admin1", editCode, relay).join());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void warnsWhenDisablingPremiumOnPasswordlessAccount() throws Exception {
        try (LocalHttpEditorServer srv = LocalHttpEditorServer.start("127.0.0.1", 0);
                Database db = new Database(DbConfig.memory())) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            AuditStore audit = new AuditStore(db);
            AtomicLong now = new AtomicLong(1_700_000_000_000L);

            var passwordlessPrem = accounts.createAccount("premuser", "PremUser", UUID.randomUUID(), UUID.randomUUID(),
                    null, HashAlgorithm.NONE, true, false, now.get(), "IP_HMAC").join();
            var withPasswordPrem = accounts.createAccount("pwuser", "PwUser", UUID.randomUUID(), UUID.randomUUID(),
                    "$argon2id$HASH", HashAlgorithm.ARGON2ID, true, false, now.get(), "IP_HMAC").join();

            BytebinClient relay = new BytebinClient(srv.baseUrl());
            EditorService editor = new EditorService(accounts, audit, now::get);

            EditorService.ExportSessionResult exported = editor.createSession(
                    1, 50, "https://justlogin.net", relay, EditorService.DEFAULT_TTL_MILLIS).join();
            SecretKey aesKey = EditorCrypto.decodeKey(
                    exported.editorUrl().substring(exported.editorUrl().indexOf('#') + 1));

            EditorModels.EditorChanges returned = new EditorModels.EditorChanges(
                    exported.sessionId(),
                    List.of(
                            new EditorModels.AccountUpdate(passwordlessPrem.id(), false, false),
                            new EditorModels.AccountUpdate(withPasswordPrem.id(), false, false)
                    ),
                    List.of()
            );
            String editCode = relay.upload(GSON.toJson(EditorCrypto.encrypt(aesKey, GSON.toJson(returned)))).join();

            EditorModels.PendingEditPlan plan = editor.prepareApply("admin1", editCode, relay).join();
            assertEquals(2, plan.changes().size());

            EditorModels.PlannedChange chPasswordless = plan.changes().stream()
                    .filter(c -> c.id() == passwordlessPrem.id())
                    .findFirst()
                    .orElseThrow();
            assertTrue(chPasswordless.warningNoPassword());
            assertTrue(chPasswordless.locksAccountWithoutPassword());

            EditorModels.PlannedChange chWithPw = plan.changes().stream()
                    .filter(c -> c.id() == withPasswordPrem.id())
                    .findFirst()
                    .orElseThrow();
            assertFalse(chWithPw.warningNoPassword());
        }
    }

    @Test
    void localHttpEditorServerServesStaticUiAndRefusesNonLoopbackBind() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> LocalHttpEditorServer.start("0.0.0.0", 0));

        try (LocalHttpEditorServer srv = LocalHttpEditorServer.start("127.0.0.1", 0)) {
            HttpClient client = HttpClient.newHttpClient();
            HttpResponse<String> page = client.send(
                    HttpRequest.newBuilder(java.net.URI.create(srv.baseUrl() + "/")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, page.statusCode());
            assertTrue(page.body().contains("JustLogin Web Editor"));
            assertTrue(page.headers().firstValue("Content-Security-Policy").orElse("").contains("default-src 'none'"));

            BytebinClient relay = new BytebinClient(srv.baseUrl());
            String key = relay.upload("{\"v\":1,\"ct\":\"demo\"}").join();
            assertEquals("{\"v\":1,\"ct\":\"demo\"}", relay.download(key).join());

            // Valid Host: 127.0.0.1:<port> is accepted
            String okResp = sendRawHttp(srv.port(),
                    "GET / HTTP/1.1\r\nHost: 127.0.0.1:" + srv.port() + "\r\nConnection: close\r\n\r\n");
            assertTrue(okResp.startsWith("HTTP/1.1 200"));

            // DNS rebinding defense: untrusted Host header is rejected with HTTP 403
            String badHostResp = sendRawHttp(srv.port(),
                    "GET / HTTP/1.1\r\nHost: evil.example.com\r\nConnection: close\r\n\r\n");
            assertTrue(badHostResp.startsWith("HTTP/1.1 403"));

            // Untrusted Origin on POST /post is rejected with HTTP 403
            String badOriginResp = sendRawHttp(srv.port(),
                    "POST /post HTTP/1.1\r\nHost: 127.0.0.1:" + srv.port()
                            + "\r\nOrigin: https://evil.example.com\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
            assertTrue(badOriginResp.startsWith("HTTP/1.1 403"));

            // Trusted Origin https://justlogin.net on POST /post is accepted with HTTP 201
            String goodOriginResp = sendRawHttp(srv.port(),
                    "POST /post HTTP/1.1\r\nHost: 127.0.0.1:" + srv.port()
                            + "\r\nOrigin: https://justlogin.net\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
            assertTrue(goodOriginResp.startsWith("HTTP/1.1 201"));
        }
    }

    @Test
    void exportPagesByLastLoginWithDeterministicTies() throws Exception {
        try (LocalHttpEditorServer srv = LocalHttpEditorServer.start("127.0.0.1", 0);
                Database db = new Database(DbConfig.memory())) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            for (String name : List.of("active", "tiefirst", "tielast", "never")) {
                accounts.importIfAbsent(name, name, UUID.randomUUID(), null, null, HashAlgorithm.NONE,
                        false, 100L, name.equals("never") ? 0L : 200L, null, 100L).join();
            }
            var active = accounts.findByNameLower("active").join().orElseThrow();
            accounts.updateLoginSuccess(active.id(), "active", null, 300L).join();
            BytebinClient relay = new BytebinClient(srv.baseUrl());
            EditorService editor = new EditorService(accounts, new AuditStore(db), System::currentTimeMillis);
            List<List<String>> expected = List.of(List.of("active", "tielast"), List.of("tiefirst", "never"));
            for (int page = 1; page <= 2; page++) {
                var exported = editor.createSession(page, 2, "https://justlogin.net", relay,
                        EditorService.DEFAULT_TTL_MILLIS).join();
                SecretKey key = EditorCrypto.decodeKey(exported.editorUrl().split("#", 2)[1]);
                var envelope = GSON.fromJson(relay.download(exported.blobKey()).join(), EditorCrypto.EncryptedEnvelope.class);
                var payload = GSON.fromJson(EditorCrypto.decrypt(key, envelope), EditorModels.EditorPayload.class);
                assertEquals(expected.get(page - 1), payload.accounts().stream().map(EditorModels.EditorAccount::name).toList());
                assertEquals(4L, payload.totalAccounts());
            }
        }
    }

    private static String sendRawHttp(int port, String rawRequest) throws IOException {
        try (Socket sock = new Socket("127.0.0.1", port)) {
            sock.setSoTimeout(5000);
            sock.getOutputStream().write(rawRequest.getBytes(StandardCharsets.UTF_8));
            sock.getOutputStream().flush();
            return new String(sock.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}

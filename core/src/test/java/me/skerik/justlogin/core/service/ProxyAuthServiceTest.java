package me.skerik.justlogin.core.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import me.skerik.justlogin.core.crypto.ProxyTokenSigner;
import me.skerik.justlogin.core.crypto.ServerSecrets;
import me.skerik.justlogin.core.model.CoreSettings;
import me.skerik.justlogin.core.model.HashAlgorithm;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import me.skerik.justlogin.core.storage.Database;
import me.skerik.justlogin.core.storage.DbConfig;
import me.skerik.justlogin.core.storage.Migrations;
import org.junit.jupiter.api.Test;

final class ProxyAuthServiceTest {

    @Test
    void premiumVerificationPreservesImmutableGameUuidAndRollsBackPendingOnDisconnect() throws Exception {
        AtomicLong clock = new AtomicLong(1_000_000L);
        ServerSecrets secrets = ServerSecrets.generateEphemeral().withProxySecret("test-shared-secret-value-1234");
        try (Database db = new Database(DbConfig.memory())) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            AuditStore audit = new AuditStore(db);
            MojangApiClient mojang = new MojangApiClient(300, clock::get);
            ProxyAuthService proxy = new ProxyAuthService(
                    accounts, audit, mojang, secrets, CoreSettings::defaults, clock::get);

            UUID crackedGameUuid = UUID.randomUUID();
            UUID mojangUuid = UUID.randomUUID();
            var acc = accounts.createAccount("steve", "Steve", crackedGameUuid, null,
                    "hash", HashAlgorithm.ARGON2ID, null, true, clock.get(), "ip").join();

            // PreLogin arms verification AND resets DB premium_pending=0 so failed cracked handshake auto-rolls back
            var pre = proxy.decidePreLogin("Steve", false).join();
            assertEquals(ProxyAuthService.PreLoginAction.FORCE_ONLINE, pre.action());
            assertFalse(accounts.findById(acc.id()).join().orElseThrow().premiumPending());

            // Simulate cracked disconnect before encryption completes -> next join falls back to offline
            proxy.onDisconnect("Steve");
            var preAfterDrop = proxy.decidePreLogin("Steve", false).join();
            assertEquals(ProxyAuthService.PreLoginAction.FORCE_OFFLINE, preAfterDrop.action());

            // Now re-arm /premium and succeed Mojang online login -> keeps crackedGameUuid!
            accounts.setPremiumPending(acc.id(), true, clock.addAndGet(1000)).join();
            var armed = proxy.decidePreLogin("Steve", false).join();
            assertEquals(ProxyAuthService.PreLoginAction.FORCE_ONLINE, armed.action());

            var res = proxy.resolveJoinProfile("Steve", mojangUuid, true, "127.0.0.1").join();
            assertTrue(res.allowed());
            assertEquals(crackedGameUuid, res.targetGameUuid());

            ProxyTokenSigner signer = new ProxyTokenSigner(secrets.proxySecret());
            byte[] packet = proxy.signBackendMessageIfOnline(signer, "Steve", crackedGameUuid);
            assertNotNull(packet);
            var verified = signer.verify(packet, clock.get());
            assertNotNull(verified);
            assertEquals(ProxyTokenSigner.MessageType.PREMIUM_VERIFIED, verified.type());
            assertEquals(crackedGameUuid, verified.gameUuid());
        }
    }

    @Test
    void mojangRenameAndPremiumUuidConflictAndAutoDetect() throws Exception {
        AtomicLong clock = new AtomicLong(2_000_000L);
        ServerSecrets secrets = ServerSecrets.generateEphemeral().withProxySecret("test-shared-secret-value-1234");
        UUID autoMojangUuid = UUID.randomUUID();
        String hex = autoMojangUuid.toString().replace("-", "");

        HttpServer mojangMock = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        mojangMock.createContext("/users/profiles/minecraft/", ex -> {
            byte[] body = ("{\"id\":\"" + hex + "\",\"name\":\"NotchReal\"}").getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, body.length);
            try (var os = ex.getResponseBody()) {
                os.write(body);
            }
        });
        mojangMock.start();

        try (Database db = new Database(DbConfig.memory())) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            AuditStore audit = new AuditStore(db);
            MojangApiClient mojang = new MojangApiClient(
                    "http://127.0.0.1:" + mojangMock.getAddress().getPort() + "/users/profiles/minecraft/", 300, clock::get);
            CoreSettings autoSettings = new CoreSettings(
                    CoreSettings.defaults().usernamePattern(), 8, 128, true, true, 19456, 2, 1, 2, 16,
                    5, 20, 1000L, 300L, false, 3600L, "JustLogin", 1, true, 300L);
            ProxyAuthService proxy = new ProxyAuthService(
                    accounts, audit, mojang, secrets, () -> autoSettings, clock::get);

            // Auto-detect Mojang player on unseen username
            assertEquals(ProxyAuthService.PreLoginAction.FORCE_ONLINE, proxy.decidePreLogin("NotchReal", false).join().action());
            var joined = proxy.resolveJoinProfile("NotchReal", autoMojangUuid, true, "1.2.3.4").join();
            assertTrue(joined.allowed());
            assertEquals(autoMojangUuid, joined.targetGameUuid());

            // Player renames Mojang account to NotchRenamed -> lookup by premiumUuid keeps original gameUuid
            var renamed = proxy.resolveJoinProfile("NotchRenamed", autoMojangUuid, true, "1.2.3.4").join();
            assertTrue(renamed.allowed());
            assertEquals(autoMojangUuid, renamed.targetGameUuid());
            assertTrue(accounts.findByNameLower("notchrenamed").join().isPresent());

            // Offline cracked account cannot be hijacked as online
            UUID offlineUuid = UUID.randomUUID();
            accounts.createAccount("crackedbob", "CrackedBob", offlineUuid, null, "h", HashAlgorithm.ARGON2ID, false, false, clock.get(), "ip").join();
            var hijack = proxy.resolveJoinProfile("CrackedBob", UUID.randomUUID(), true, "1.2.3.4").join();
            assertFalse(hijack.allowed());

            // Valid offline cracked join gets its immutable gameUuid and NO backend auto-login token
            var offline = proxy.resolveJoinProfile("CrackedBob", null, false, "1.2.3.4").join();
            assertTrue(offline.allowed());
            assertEquals(offlineUuid, offline.targetGameUuid());
            assertNull(proxy.signBackendMessageIfOnline(new ProxyTokenSigner(secrets.proxySecret()), "CrackedBob", offlineUuid));
        } finally {
            mojangMock.stop(0);
        }
    }
}

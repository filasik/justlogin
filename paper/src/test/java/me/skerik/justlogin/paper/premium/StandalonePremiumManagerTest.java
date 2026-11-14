package me.skerik.justlogin.paper.premium;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.embedded.EmbeddedChannel;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import me.skerik.justlogin.core.crypto.ServerSecrets;
import me.skerik.justlogin.core.model.Account;
import me.skerik.justlogin.core.model.HashAlgorithm;
import me.skerik.justlogin.core.service.MojangSessionClient;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import me.skerik.justlogin.core.storage.Database;
import me.skerik.justlogin.core.storage.DbConfig;
import me.skerik.justlogin.core.storage.Migrations;
import me.skerik.justlogin.paper.Scheduler;
import me.skerik.justlogin.paper.config.Settings;
import net.kyori.adventure.key.Key;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Entity;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class StandalonePremiumManagerTest {

    @TempDir Path tempDir;

    private record FakeHello(String name, @Nullable UUID profileId) {
    }

    private record FakeEncryptionRequest(String serverId, byte[] pubKey, byte[] challenge, boolean shouldAuth) {
    }

    private record FakeKeyResponse(byte[] encryptedSecret, byte[] encryptedChallenge) {
    }

    private record FakeDisconnect(Component reason) {
    }

    private static final class InlineScheduler implements Scheduler {
        @Override public void runGlobal(Runnable task) { task.run(); }
        @Override public void runForEntity(Entity entity, Runnable task, @Nullable Runnable retired) { task.run(); }
        @Override public void runEntityLater(Entity entity, Runnable task, @Nullable Runnable retired, long delayTicks) {}
        @Override public Runnable runEntityTimer(Entity entity, Runnable task, @Nullable Runnable retired, long delayTicks, long periodTicks) { return () -> {}; }
        @Override public void runAsync(Runnable task) { task.run(); }
        @Override public void runLater(Runnable task, long ticks) {}
        @Override public Runnable runGlobalTimer(Runnable task, long delayTicks, long periodTicks) { return () -> {}; }
        @Override public Runnable runAsyncTimer(Runnable task, long delayTicks, long periodTicks) { return () -> {}; }
    }

    private static final class FakeLoginBridge implements LoginBridge {
        final KeyPair keyPair;
        final AtomicReference<@Nullable Consumer<Channel>> initCallback = new AtomicReference<>();
        final AtomicBoolean encryptionEnabled = new AtomicBoolean();
        final AtomicReference<@Nullable SecretKey> installedSecret = new AtomicReference<>();

        FakeLoginBridge() throws Exception {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(1024);
            this.keyPair = gen.generateKeyPair();
        }

        @Override
        public void registerChannelListener(Key key, Consumer<Channel> onInit) {
            initCallback.set(onInit);
        }

        @Override
        public void unregisterChannelListener(Key key) {
            initCallback.set(null);
        }

        @Override
        public byte[] publicKeyEncoded() {
            return keyPair.getPublic().getEncoded();
        }

        @Override
        public @Nullable HelloPacketInfo inspectHelloPacket(Object msg) {
            if (msg instanceof FakeHello fh) {
                return new HelloPacketInfo(fh.name(), fh.profileId());
            }
            return null;
        }

        @Override
        public Object newHelloPacket(String canonicalName, UUID mojangUuid, Object originalFallback) {
            return new FakeHello(canonicalName, mojangUuid);
        }

        @Override
        public Object newEncryptionRequestPacket(byte[] verifyToken) {
            return new FakeEncryptionRequest("", keyPair.getPublic().getEncoded(), verifyToken, true);
        }

        @Override
        public boolean isKeyPacket(Object msg) {
            return msg instanceof FakeKeyResponse;
        }

        @Override
        public @Nullable SecretKey decryptVerifiedKeyPacket(Object msg, byte[] expectedChallenge) {
            if (!(msg instanceof FakeKeyResponse kr)) return null;
            try {
                Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                rsa.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
                byte[] decChallenge = rsa.doFinal(kr.encryptedChallenge());
                if (!Arrays.equals(decChallenge, expectedChallenge)) {
                    return null;
                }
                rsa.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
                byte[] secretBytes = rsa.doFinal(kr.encryptedSecret());
                return new SecretKeySpec(secretBytes, "AES");
            } catch (Exception e) {
                return null;
            }
        }

        @Override
        public void enableEncryption(Channel channel, SecretKey secretKey) {
            encryptionEnabled.set(true);
            installedSecret.set(secretKey);
        }

        @Override
        public @Nullable Channel extractChannel(AsyncPlayerPreLoginEvent event) {
            return null;
        }

        @Override
        public void sendDisconnect(ChannelHandlerContext ctx, Component message) {
            ctx.channel().writeAndFlush(new FakeDisconnect(message)).addListener(ChannelFutureListener.CLOSE);
        }
    }

    private static FakeKeyResponse encryptKeyResponse(byte[] encodedPubKey, byte[] challenge, SecretKey secret) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
        java.security.PublicKey pub = kf.generatePublic(new java.security.spec.X509EncodedKeySpec(encodedPubKey));
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, pub);
        byte[] encSecret = rsa.doFinal(secret.getEncoded());
        rsa.init(Cipher.ENCRYPT_MODE, pub);
        byte[] encChallenge = rsa.doFinal(challenge);
        assertNotNull(kpg);
        return new FakeKeyResponse(encSecret, encChallenge);
    }

    private static <T> T awaitOutbound(EmbeddedChannel ch, Class<T> type) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            ch.runPendingTasks();
            Object out = ch.readOutbound();
            if (out != null) {
                return assertInstanceOf(type, out);
            }
            Thread.sleep(5);
        }
        throw new AssertionError("Timed out waiting for outbound " + type.getSimpleName());
    }

    private static <T> T awaitInbound(EmbeddedChannel ch, Class<T> type) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            ch.runPendingTasks();
            Object in = ch.readInbound();
            if (in != null) {
                return assertInstanceOf(type, in);
            }
            Thread.sleep(5);
        }
        throw new AssertionError("Timed out waiting for inbound " + type.getSimpleName());
    }

    private Settings standaloneSettings(boolean autoDetectMojang) {
        YamlConfiguration cfg = new YamlConfiguration();
        cfg.set("premium.standalone-enabled", true);
        cfg.set("premium.auto-detect-mojang", autoDetectMojang);
        cfg.set("proxy.enabled", false);
        return Settings.load(cfg, tempDir);
    }

    private static void installDummyPacketHandler(EmbeddedChannel ch) {
        ch.pipeline().addLast("packet_handler", new io.netty.channel.ChannelInboundHandlerAdapter());
    }

    @Test
    void unregisteredPlayerPassesThroughWhenAutoDetectDisabled() throws Exception {
        try (Database db = new Database(DbConfig.memory())) {
            Migrations.migrate(db);
            FakeLoginBridge bridge = new FakeLoginBridge();
            Settings settings = standaloneSettings(false);
            StandalonePremiumManager mgr = new StandalonePremiumManager(
                    new InlineScheduler(), Component::text, u -> false, () -> false,
                    new AccountStore(db), new AuditStore(db), ServerSecrets.generateEphemeral(),
                    () -> settings, () -> false, bridge, new MojangSessionClient("http://127.0.0.1:1/unused"));
            mgr.install();

            EmbeddedChannel ch = new EmbeddedChannel();
            installDummyPacketHandler(ch);
            bridge.initCallback.get().accept(ch);
            assertNotNull(ch.pipeline().get(StandalonePremiumManager.HANDLER_NAME));

            FakeHello hello = new FakeHello("CrackedNew", UUID.randomUUID());
            ch.writeInbound(hello);

            FakeHello passed = awaitInbound(ch, FakeHello.class);
            assertEquals("CrackedNew", passed.name());
            assertNull(ch.readOutbound());
            assertNull(ch.pipeline().get(StandalonePremiumManager.HANDLER_NAME));
            ch.finishAndReleaseAll();
        }
    }

    @Test
    void pendingPremiumVerifiesRsaAesHasJoinedAndPreservesGameUuid() throws Exception {
        UUID offlineUuid = UUID.randomUUID();
        UUID mojangUuid = UUID.randomUUID();
        String undashedMojang = mojangUuid.toString().replace("-", "");
        AtomicReference<String> lastQuery = new AtomicReference<>();

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        try (Database db = new Database(DbConfig.memory())) {
            server.createContext("/hasJoined", ex -> {
                lastQuery.set(ex.getRequestURI().getRawQuery());
                byte[] body = ("""
                        {
                          "id": "%s",
                          "name": "AlexPrem",
                          "properties": [{"name":"textures","value":"texVal","signature":"texSig"}]
                        }""").formatted(undashedMojang).getBytes(StandardCharsets.UTF_8);
                ex.sendResponseHeaders(200, body.length);
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(body);
                }
            });
            server.start();

            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            accounts.createAccount("alexprem", "AlexPrem", offlineUuid, null, "hash",
                    HashAlgorithm.ARGON2ID, false, true, 1_000L, "127.0.0.1").join();

            FakeLoginBridge bridge = new FakeLoginBridge();
            Settings settings = standaloneSettings(false);
            MojangSessionClient client = new MojangSessionClient(
                    "http://127.0.0.1:" + server.getAddress().getPort() + "/hasJoined");
            StandalonePremiumManager mgr = new StandalonePremiumManager(
                    new InlineScheduler(), Component::text, u -> false, () -> false,
                    accounts, new AuditStore(db), ServerSecrets.generateEphemeral(),
                    () -> settings, () -> false, bridge, client);
            mgr.install();

            EmbeddedChannel ch = new EmbeddedChannel();
            installDummyPacketHandler(ch);
            bridge.initCallback.get().accept(ch);

            ch.writeInbound(new FakeHello("AlexPrem", UUID.randomUUID()));
            FakeEncryptionRequest encReq = awaitOutbound(ch, FakeEncryptionRequest.class);
            assertTrue(encReq.shouldAuth());
            assertNull(ch.readInbound());

            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            SecretKey aes = kg.generateKey();
            String expectedHash = MojangSessionClient.computeServerIdHash("", bridge.publicKeyEncoded(), aes.getEncoded());

            ch.writeInbound(encryptKeyResponse(encReq.pubKey(), encReq.challenge(), aes));
            FakeHello passed = awaitInbound(ch, FakeHello.class);
            assertEquals("AlexPrem", passed.name());
            assertEquals(mojangUuid, passed.profileId());
            assertTrue(bridge.encryptionEnabled.get());
            assertTrue(lastQuery.get().contains("serverId=" + expectedHash));

            StandalonePremiumManager.VerifiedChannelData verified =
                    ch.attr(StandalonePremiumManager.VERIFIED_ATTR).getAndSet(null);
            assertNotNull(verified);
            assertEquals(mojangUuid, verified.mojangUuid());
            assertEquals("texVal", verified.texturesValue());
            assertEquals("texSig", verified.texturesSignature());

            var res = mgr.resolveVerifiedJoin(verified.canonicalName(), verified.mojangUuid(), "127.0.0.1").join();
            assertTrue(res.allowed());
            assertTrue(res.pendingConfirmed());
            // Immutable offline game_uuid MUST stay intact after /premium confirmation
            assertEquals(offlineUuid, res.targetGameUuid());

            Account updated = accounts.findByNameLower("alexprem").join().orElseThrow();
            assertTrue(updated.isPremiumConfirmed());
            assertFalse(updated.premiumPending());
            assertEquals(mojangUuid, updated.premiumUuid());
            assertEquals(offlineUuid, updated.gameUuid());

            // Grant is single-use
            mgr.recordVerifiedGrant(res.accountId(), offlineUuid, "AlexPrem", res.pendingConfirmed());
            assertNotNull(mgr.consumeVerifiedGrant(offlineUuid, "AlexPrem"));
            assertNull(mgr.consumeVerifiedGrant(offlineUuid, "AlexPrem"));
            ch.finishAndReleaseAll();
        } finally {
            server.stop(0);
        }
    }

    @Test
    void pendingPremiumDisconnectRollsBackPendingFlag() throws Exception {
        try (Database db = new Database(DbConfig.memory())) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            accounts.createAccount("rollbackbob", "RollbackBob", UUID.randomUUID(), null, "hash",
                    HashAlgorithm.ARGON2ID, false, true, 1_000L, "127.0.0.1").join();

            FakeLoginBridge bridge = new FakeLoginBridge();
            Settings settings = standaloneSettings(false);
            StandalonePremiumManager mgr = new StandalonePremiumManager(
                    new InlineScheduler(), Component::text, u -> false, () -> false,
                    accounts, new AuditStore(db), ServerSecrets.generateEphemeral(),
                    () -> settings, () -> false, bridge, new MojangSessionClient("http://127.0.0.1:1/unused"));
            mgr.install();

            EmbeddedChannel ch = new EmbeddedChannel();
            installDummyPacketHandler(ch);
            bridge.initCallback.get().accept(ch);

            ch.writeInbound(new FakeHello("RollbackBob", UUID.randomUUID()));
            awaitOutbound(ch, FakeEncryptionRequest.class);

            // Cracked client disconnects or rejects Encryption Request -> channel closes
            ch.close().syncUninterruptibly();
            Account after = accounts.findByNameLower("rollbackbob").join().orElseThrow();
            assertFalse(after.isPremiumConfirmed());
            assertFalse(after.premiumPending());
        }
    }

    @Test
    void confirmedPremiumFailsClosedOnBadHasJoinedOrMojangOutage() throws Exception {
        UUID gameUuid = UUID.randomUUID();
        UUID premUuid = UUID.randomUUID();

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        try (Database db = new Database(DbConfig.memory())) {
            server.createContext("/hasJoined", ex -> {
                String q = ex.getRequestURI().getRawQuery();
                if (q != null && q.contains("OutageUser")) {
                    ex.sendResponseHeaders(500, -1);
                } else {
                    ex.sendResponseHeaders(204, -1);
                }
                ex.close();
            });
            server.start();

            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            accounts.createAccount("strictprem", "StrictPrem", gameUuid, premUuid, "hash",
                    HashAlgorithm.ARGON2ID, true, false, 1_000L, "127.0.0.1").join();
            accounts.createAccount("outageuser", "OutageUser", UUID.randomUUID(), UUID.randomUUID(), "hash",
                    HashAlgorithm.ARGON2ID, true, false, 1_000L, "127.0.0.1").join();

            FakeLoginBridge bridge = new FakeLoginBridge();
            Settings settings = standaloneSettings(false);
            MojangSessionClient client = new MojangSessionClient(
                    "http://127.0.0.1:" + server.getAddress().getPort() + "/hasJoined");
            StandalonePremiumManager mgr = new StandalonePremiumManager(
                    new InlineScheduler(), Component::text, u -> false, () -> false,
                    accounts, new AuditStore(db), ServerSecrets.generateEphemeral(),
                    () -> settings, () -> false, bridge, client);
            mgr.install();

            // Case 1: 204 Not Authenticated -> disconnects with verification-failed, never passes Hello
            EmbeddedChannel ch1 = new EmbeddedChannel();
            installDummyPacketHandler(ch1);
            bridge.initCallback.get().accept(ch1);
            ch1.writeInbound(new FakeHello("StrictPrem", UUID.randomUUID()));
            FakeEncryptionRequest req1 = awaitOutbound(ch1, FakeEncryptionRequest.class);
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            ch1.writeInbound(encryptKeyResponse(req1.pubKey(), req1.challenge(), kg.generateKey()));
            FakeDisconnect disc1 = awaitOutbound(ch1, FakeDisconnect.class);
            assertEquals("premium.verification-failed", PlainTextComponentSerializer.plainText().serialize(disc1.reason()));
            assertNull(ch1.readInbound());

            // Case 2: 500 Server Error -> disconnects with auth-servers-unavailable, never passes Hello
            EmbeddedChannel ch2 = new EmbeddedChannel();
            installDummyPacketHandler(ch2);
            bridge.initCallback.get().accept(ch2);
            ch2.writeInbound(new FakeHello("OutageUser", UUID.randomUUID()));
            FakeEncryptionRequest req2 = awaitOutbound(ch2, FakeEncryptionRequest.class);
            ch2.writeInbound(encryptKeyResponse(req2.pubKey(), req2.challenge(), kg.generateKey()));
            FakeDisconnect disc2 = awaitOutbound(ch2, FakeDisconnect.class);
            assertEquals("premium.auth-servers-unavailable", PlainTextComponentSerializer.plainText().serialize(disc2.reason()));
            assertNull(ch2.readInbound());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void activeRuntimeRespectsOnlineModeProxyAndForwardingGuards() throws Exception {
        try (Database db = new Database(DbConfig.memory())) {
            Migrations.migrate(db);
            FakeLoginBridge bridge = new FakeLoginBridge();
            AtomicBoolean onlineMode = new AtomicBoolean(false);
            AtomicBoolean forwarding = new AtomicBoolean(false);
            AtomicReference<Settings> settingsRef = new AtomicReference<>(standaloneSettings(false));

            StandalonePremiumManager mgr = new StandalonePremiumManager(
                    new InlineScheduler(), Component::text, u -> false, onlineMode::get,
                    new AccountStore(db), new AuditStore(db), ServerSecrets.generateEphemeral(),
                    settingsRef::get, forwarding::get, bridge, new MojangSessionClient());

            assertTrue(mgr.isHookAvailable());
            assertTrue(mgr.isActiveRuntime());

            onlineMode.set(true);
            assertFalse(mgr.isActiveRuntime());
            onlineMode.set(false);

            forwarding.set(true);
            assertFalse(mgr.isActiveRuntime());
            forwarding.set(false);

            YamlConfiguration proxyCfg = new YamlConfiguration();
            proxyCfg.set("premium.standalone-enabled", true);
            proxyCfg.set("proxy.enabled", true);
            settingsRef.set(Settings.load(proxyCfg, tempDir));
            assertFalse(mgr.isActiveRuntime());

            YamlConfiguration disabledCfg = new YamlConfiguration();
            disabledCfg.set("premium.standalone-enabled", false);
            disabledCfg.set("proxy.enabled", false);
            settingsRef.set(Settings.load(disabledCfg, tempDir));
            assertFalse(mgr.isActiveRuntime());
        }
    }
}

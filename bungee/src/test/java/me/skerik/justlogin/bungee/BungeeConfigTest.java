package me.skerik.justlogin.bungee;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;
import me.skerik.justlogin.core.service.ProxyAuthService;
import me.skerik.justlogin.core.storage.DbConfig;
import net.md_5.bungee.api.chat.BaseComponent;
import net.md_5.bungee.api.config.ListenerInfo;
import net.md_5.bungee.api.connection.PendingConnection;
import net.md_5.bungee.config.Configuration;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class BungeeConfigTest {

    @Test
    void loadsDefaultConfigAndRejectsPlaceholderSecret(@TempDir Path dir) throws Exception {
        BungeeConfig cfg = BungeeConfig.load(dir);
        assertEquals(DbConfig.Dialect.SQLITE, cfg.dbConfig().dialect());
        assertEquals("en", cfg.locale());
        assertFalse(cfg.core().premiumAutoDetect());
        assertTrue(cfg.metrics());
        assertFalse(cfg.isSecretValid(), "Default placeholder secret must fail validation");

        Configuration custom = new Configuration();
        custom.set("proxy.shared-secret", "another-strong-shared-secret-key");
        custom.set("storage.type", "mariadb");
        custom.set("storage.mariadb.database", "jl_net");
        custom.set("metrics", false);
        BungeeConfig parsed = BungeeConfig.fromConfiguration(custom, dir);
        assertTrue(parsed.isSecretValid());
        assertEquals(DbConfig.Dialect.MARIADB, parsed.dbConfig().dialect());
        assertEquals("jl_net", parsed.dbConfig().database());
        assertFalse(parsed.metrics());

        Configuration legacy = new Configuration();
        legacy.set("database.type", "mariadb");
        legacy.set("database.mariadb.database", "jl_old");
        BungeeConfig legacyParsed = BungeeConfig.fromConfiguration(legacy, dir);
        assertEquals(DbConfig.Dialect.MARIADB, legacyParsed.dbConfig().dialect());
        assertEquals("jl_old", legacyParsed.dbConfig().database());
        assertTrue(legacyParsed.authServers().isEmpty());

        Configuration routed = new Configuration();
        routed.set("proxy.auth-servers", List.of("Auth", "Limbo2"));
        routed.set("messages.auth-required-server", "Authenticate first");
        BungeeConfig routedParsed = BungeeConfig.fromConfiguration(routed, dir);
        assertTrue(routedParsed.authServers().contains("auth"));
        assertTrue(routedParsed.authServers().contains("limbo2"));
        assertEquals("Authenticate first", routedParsed.authRequiredServerMessage());
    }

    @Test
    void applyUniqueIdRewritesPrivateFieldWhenSetUniqueIdThrowsIllegalState() {
        UUID mojangUuid = UUID.randomUUID();
        UUID preservedOfflineGameUuid = UUID.randomUUID();
        FakeInitialHandler handler = new FakeInitialHandler("TestPlayer", mojangUuid, new InetSocketAddress("198.51.100.10", 25565));

        // Prove that calling setUniqueId directly throws IllegalStateException (just like BungeeCord's InitialHandler in LoginEvent)
        assertThrows(IllegalStateException.class, () -> handler.setUniqueId(preservedOfflineGameUuid));
        assertEquals(mojangUuid, handler.getUniqueId());

        // P0-5: applyUniqueId rewrites the private uniqueId field via reflection without calling setUniqueId
        assertTrue(JustLoginBungee.applyUniqueId(handler, preservedOfflineGameUuid, Logger.getLogger("test")));
        assertEquals(preservedOfflineGameUuid, handler.getUniqueId());

        // Also test fallback to setUniqueId on a custom PendingConnection without a uniqueId field
        AtomicReference<UUID> fallbackHolder = new AtomicReference<>(mojangUuid);
        PendingConnection proxyConn = (PendingConnection) Proxy.newProxyInstance(
                PendingConnection.class.getClassLoader(),
                new Class<?>[]{PendingConnection.class},
                (proxy, method, args) -> {
                    if ("setUniqueId".equals(method.getName()) && args != null && args.length == 1) {
                        fallbackHolder.set((UUID) args[0]);
                        return null;
                    }
                    if ("getUniqueId".equals(method.getName())) {
                        return fallbackHolder.get();
                    }
                    if ("getName".equals(method.getName())) {
                        return "FallbackPlayer";
                    }
                    return null;
                });
        UUID nextUuid = UUID.randomUUID();
        assertTrue(JustLoginBungee.applyUniqueId(proxyConn, nextUuid, Logger.getLogger("test")));
        assertEquals(nextUuid, proxyConn.getUniqueId());
    }

    @Test
    void formatsLocalizedDenyReasonsAndKickMessagesInEnCsSk(@TempDir Path dir) {
        Configuration enRaw = new Configuration();
        enRaw.set("locale", "en");
        BungeeConfig enCfg = BungeeConfig.fromConfiguration(enRaw, dir);

        Configuration csRaw = new Configuration();
        csRaw.set("locale", "cs");
        BungeeConfig csCfg = BungeeConfig.fromConfiguration(csRaw, dir);

        Configuration skRaw = new Configuration();
        skRaw.set("locale", "sk");
        BungeeConfig skCfg = BungeeConfig.fromConfiguration(skRaw, dir);

        assertEquals("en", enCfg.locale());
        assertEquals("cs", csCfg.locale());
        assertEquals("sk", skCfg.locale());

        for (ProxyAuthService.DenyReason reason : ProxyAuthService.DenyReason.values()) {
            String en = enCfg.formatDenyReason(reason);
            String cs = csCfg.formatDenyReason(reason);
            String sk = skCfg.formatDenyReason(reason);

            assertFalse(en.isBlank());
            assertFalse(cs.isBlank());
            assertFalse(sk.isBlank());
            assertNotEquals(en, cs, "Czech translation should differ from English for " + reason);
            assertNotEquals(en, sk, "Slovak translation should differ from English for " + reason);
            assertNotEquals(cs, sk, "Czech and Slovak translations should differ for " + reason);
        }

        var mojangDown = ProxyAuthService.JoinResolution.deny(ProxyAuthService.DenyReason.MOJANG_UNAVAILABLE);
        assertTrue(enCfg.formatDeny(mojangDown).contains("Mojang"));
        assertTrue(csCfg.formatDeny(mojangDown).contains("Mojang"));
        assertTrue(skCfg.formatDeny(mojangDown).contains("Mojang"));

        for (String key : new String[]{"not-ready", "auth-service-error", "auth-server-unavailable"}) {
            String enKick = ProxyMessages.translateKickReason("en", key);
            String csKick = ProxyMessages.translateKickReason("cs", key);
            String skKick = ProxyMessages.translateKickReason("sk", key);
            assertNotEquals(enKick, csKick);
            assertNotEquals(enKick, skKick);
        }
    }

    @Test
    void floodgateAndExtractIpHelpersBehaveSafely() throws Exception {
        UUID floodgateLikeUuid = new UUID(0L, 77L);
        UUID normalJavaUuid = UUID.randomUUID();
        FakeFloodgateApi fakeApi = new FakeFloodgateApi(floodgateLikeUuid);
        Method checkMethod = FakeFloodgateApi.class.getMethod("isFloodgatePlayer", UUID.class);

        // P1-6(b): never blindly trust zero MSB UUID unless Floodgate API confirms the player
        assertFalse(JustLoginBungee.isFloodgate(floodgateLikeUuid, null, null));
        assertFalse(JustLoginBungee.isFloodgate(new UUID(0L, 123L), fakeApi, checkMethod));
        assertFalse(JustLoginBungee.isFloodgate(normalJavaUuid, fakeApi, checkMethod));
        assertTrue(JustLoginBungee.isFloodgate(floodgateLikeUuid, fakeApi, checkMethod));

        // P1-3: non-InetSocketAddress returns "unknown", never "127.0.0.1"
        FakeInitialHandler domainSocketConn = new FakeInitialHandler(
                "UnixPlayer", normalJavaUuid, new SocketAddress() {
                    private static final long serialVersionUID = 1L;
                });
        assertEquals("unknown", JustLoginBungee.extractIp(domainSocketConn));

        FakeInitialHandler resolvedConn = new FakeInitialHandler(
                "IpPlayer", normalJavaUuid, new InetSocketAddress(InetAddress.getByName("203.0.113.9"), 25565));
        assertEquals("203.0.113.9", JustLoginBungee.extractIp(resolvedConn));
    }

    public static final class FakeFloodgateApi {
        private final UUID confirmedUuid;

        FakeFloodgateApi(UUID confirmedUuid) {
            this.confirmedUuid = confirmedUuid;
        }

        public boolean isFloodgatePlayer(UUID uuid) {
            return confirmedUuid.equals(uuid);
        }
    }

    @SuppressWarnings("deprecation")
    private static final class FakeInitialHandler implements PendingConnection {
        private final String name;
        private UUID uniqueId;
        private final SocketAddress socketAddress;
        private boolean onlineMode = true;

        FakeInitialHandler(String name, UUID uniqueId, SocketAddress socketAddress) {
            this.name = name;
            this.uniqueId = uniqueId;
            this.socketAddress = socketAddress;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public int getVersion() {
            return 767;
        }

        @Override
        public @Nullable InetSocketAddress getVirtualHost() {
            return null;
        }

        @Override
        public @Nullable ListenerInfo getListener() {
            return null;
        }

        @Override
        @Deprecated
        public String getUUID() {
            return uniqueId.toString();
        }

        @Override
        public UUID getUniqueId() {
            return uniqueId;
        }

        @Override
        public void setUniqueId(UUID uuid) {
            throw new IllegalStateException("Can only set uuid while state is USERNAME");
        }

        @Override
        public boolean isOnlineMode() {
            return onlineMode;
        }

        @Override
        public void setOnlineMode(boolean onlineMode) {
            this.onlineMode = onlineMode;
        }

        @Override
        public boolean isLegacy() {
            return false;
        }

        @Override
        public boolean isTransferred() {
            return false;
        }

        @Override
        public CompletableFuture<byte[]> retrieveCookie(String cookie) {
            return CompletableFuture.completedFuture(new byte[0]);
        }

        @Override
        public CompletableFuture<byte[]> sendData(String channel, byte[] data) {
            return CompletableFuture.completedFuture(new byte[0]);
        }

        @Override
        @Deprecated
        public @Nullable InetSocketAddress getAddress() {
            return socketAddress instanceof InetSocketAddress isa ? isa : null;
        }

        @Override
        public SocketAddress getSocketAddress() {
            return socketAddress;
        }

        @Override
        @Deprecated
        public void disconnect(String reason) {
        }

        @Override
        public void disconnect(BaseComponent... reason) {
        }

        @Override
        public void disconnect(BaseComponent reason) {
        }

        @Override
        public boolean isConnected() {
            return true;
        }

        @Override
        public Unsafe unsafe() {
            throw new UnsupportedOperationException();
        }
    }
}

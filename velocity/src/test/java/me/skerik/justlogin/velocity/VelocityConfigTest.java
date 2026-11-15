package me.skerik.justlogin.velocity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.velocitypowered.api.proxy.InboundConnection;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.UUID;
import me.skerik.justlogin.core.service.ProxyAuthService;
import me.skerik.justlogin.core.storage.DbConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.spongepowered.configurate.yaml.YamlConfigurationLoader;

final class VelocityConfigTest {

    @Test
    void loadsDefaultConfigAndRejectsPlaceholderSecret(@TempDir Path dir) throws Exception {
        VelocityConfig cfg = VelocityConfig.load(dir);
        assertEquals(DbConfig.Dialect.SQLITE, cfg.dbConfig().dialect());
        assertEquals("en", cfg.locale());
        assertFalse(cfg.core().premiumAutoDetect());
        assertTrue(cfg.core().skinsEnabled());
        assertTrue(cfg.core().skinsRestoreByName());
        assertEquals(600L, cfg.core().skinsCacheSeconds());
        assertTrue(cfg.metrics());
        assertFalse(cfg.isSecretValid(), "Default placeholder secret must fail validation");
        assertTrue(VelocityConfig.fromNode(
                YamlConfigurationLoader.builder()
                        .buildAndLoadString("proxy:\n  shared-secret: \"valid-shared-secret-key-999\"\n"),
                dir).isSecretValid());

        VelocityConfig maria = VelocityConfig.fromNode(
                YamlConfigurationLoader.builder()
                        .buildAndLoadString("storage:\n  type: mariadb\n  mariadb:\n    database: jl_net\nmetrics: false\n"),
                dir);
        assertEquals(DbConfig.Dialect.MARIADB, maria.dbConfig().dialect());
        assertEquals("jl_net", maria.dbConfig().database());
        assertFalse(maria.metrics());

        VelocityConfig legacy = VelocityConfig.fromNode(
                YamlConfigurationLoader.builder()
                        .buildAndLoadString("database:\n  type: mariadb\n  mariadb:\n    database: jl_old\n"),
                dir);
        assertEquals(DbConfig.Dialect.MARIADB, legacy.dbConfig().dialect());
        assertEquals("jl_old", legacy.dbConfig().database());
        assertTrue(legacy.authServers().isEmpty());

        VelocityConfig routed = VelocityConfig.fromNode(
                YamlConfigurationLoader.builder()
                        .buildAndLoadString("proxy:\n  auth-servers:\n    - Limbo\n    - Auth-1\nmessages:\n  auth-required-server: \"Login first\"\n"),
                dir);
        assertTrue(routed.authServers().contains("limbo"));
        assertTrue(routed.authServers().contains("auth-1"));
        assertEquals("Login first", routed.authRequiredServerMessage());
    }

    @Test
    void formatsLocalizedDenyReasonsAndKickMessagesInEnCsSk(@TempDir Path dir) throws Exception {
        VelocityConfig enCfg = VelocityConfig.fromNode(
                YamlConfigurationLoader.builder().buildAndLoadString("locale: en\n"), dir);
        VelocityConfig csCfg = VelocityConfig.fromNode(
                YamlConfigurationLoader.builder().buildAndLoadString("locale: cs\n"), dir);
        VelocityConfig skCfg = VelocityConfig.fromNode(
                YamlConfigurationLoader.builder().buildAndLoadString("locale: sk\n"), dir);

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
    void floodgateAndIpExtractionHelpersBehaveSafely() throws Exception {
        UUID floodgateLikeUuid = new UUID(0L, 42L);
        UUID normalJavaUuid = UUID.randomUUID();
        FakeFloodgateApi fakeApi = new FakeFloodgateApi(floodgateLikeUuid);
        Method checkMethod = FakeFloodgateApi.class.getMethod("isFloodgatePlayer", UUID.class);

        // P1-6(b): never trust zero MSB UUID when Floodgate API is absent or does not confirm the player
        assertFalse(JustLoginVelocity.isFloodgate(floodgateLikeUuid, null, null));
        assertFalse(JustLoginVelocity.isFloodgate(new UUID(0L, 999L), fakeApi, checkMethod));
        assertFalse(JustLoginVelocity.isFloodgate(normalJavaUuid, fakeApi, checkMethod));
        assertTrue(JustLoginVelocity.isFloodgate(floodgateLikeUuid, fakeApi, checkMethod));

        // P1-3: unknown / unresolved addresses return "unknown", never "127.0.0.1"
        assertEquals("unknown", JustLoginVelocity.extractIp(null));
        InboundConnection unresolvedConn = (InboundConnection) Proxy.newProxyInstance(
                InboundConnection.class.getClassLoader(),
                new Class<?>[]{InboundConnection.class},
                (proxy, method, args) -> "getRemoteAddress".equals(method.getName())
                        ? InetSocketAddress.createUnresolved("unresolved.example", 25565)
                        : null);
        assertEquals("unknown", JustLoginVelocity.extractIp(unresolvedConn));

        InetSocketAddress resolvedAddr = new InetSocketAddress(InetAddress.getByName("198.51.100.25"), 25565);
        InboundConnection resolvedConn = (InboundConnection) Proxy.newProxyInstance(
                InboundConnection.class.getClassLoader(),
                new Class<?>[]{InboundConnection.class},
                (proxy, method, args) -> "getRemoteAddress".equals(method.getName()) ? resolvedAddr : null);
        assertEquals("198.51.100.25", JustLoginVelocity.extractIp(resolvedConn));
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
}

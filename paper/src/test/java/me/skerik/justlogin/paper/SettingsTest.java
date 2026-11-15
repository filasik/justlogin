package me.skerik.justlogin.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import me.skerik.justlogin.paper.config.Settings;
import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.jupiter.api.Test;

final class SettingsTest {

    @Test
    void bundledConfigLoadsWithSafeSecurityDefaults() throws Exception {
        YamlConfiguration cfg = new YamlConfiguration();
        try (var in = getClass().getResourceAsStream("/config.yml")) {
            cfg.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }

        Settings s = Settings.load(cfg, Path.of("/tmp/justlogin-test"));
        assertEquals("en", s.language());
        assertTrue(s.checkUpdates());
        assertTrue(s.metrics());
        assertEquals(Settings.UiMode.DIALOG, s.loginUi());
        assertFalse(s.core().sessionsEnabled(), "Sessions must be disabled by default");
        assertTrue(s.standalonePremiumEnabled(), "Standalone premium auto-login should be enabled by default");
        assertFalse(s.standalonePreventProxyConnections());
        assertFalse(s.core().premiumAutoDetect(), "Mojang auto-detect must be disabled by default");
        assertFalse(s.proxyEnabled());
        assertEquals(Settings.ProxyMode.STANDALONE, s.proxyMode());
        assertTrue(s.kickDuplicateOnline());
        assertEquals(8, s.core().minPasswordLength());
        assertEquals(19456, s.core().argon2MemoryKib());
        assertTrue(s.skinsEnabled());
        assertTrue(s.skinsRestoreByName());
        assertTrue(s.skinsCommandEnabled());
        assertEquals(60L, s.skinCooldownSeconds());
        assertEquals(600L, s.skinsCacheSeconds());
    }

    @Test
    void skinRestoreOptionFallsBackToLegacyKeyWhenNewKeyIsMissing() throws Exception {
        YamlConfiguration cfg = new YamlConfiguration();
        try (var in = getClass().getResourceAsStream("/config.yml")) {
            cfg.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
        cfg.set("skins.restore-by-name", null);
        cfg.set("skins.restore-cracked-by-name", false);

        Settings s = Settings.load(cfg, Path.of("/tmp/justlogin-test"));
        assertFalse(s.skinsRestoreByName(), "admin's old value must be honoured when only the legacy key exists");
    }
}

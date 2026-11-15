package me.skerik.justlogin.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import me.skerik.justlogin.paper.config.ConfigUpdater;
import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.jupiter.api.Test;

final class ConfigUpdaterTest {

    @Test
    void mergeAddsMissingDefaultsAndPreservesExistingValues() throws Exception {
        YamlConfiguration defaults = new YamlConfiguration();
        try (var in = getClass().getResourceAsStream("/config.yml")) {
            defaults.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }

        YamlConfiguration user = new YamlConfiguration();
        user.set("config-version", 0);
        user.set("locale", "cs");
        user.set("sessions.enabled", true);

        int added = ConfigUpdater.merge(user, defaults);
        assertTrue(added > 5);
        assertEquals("cs", user.getString("locale"));
        assertTrue(user.getBoolean("sessions.enabled"));
        assertEquals(defaults.getInt("config-version"), user.getInt("config-version"));
        assertFalse(user.getComments("sessions.enabled").isEmpty());
    }

    @Test
    void migrateMovesOldKeyAndDeletesSource() {
        YamlConfiguration user = new YamlConfiguration();
        user.set("language", "cs");
        user.set("updates.check", false);

        int moved = ConfigUpdater.migrate(user, ConfigUpdater.RENAMES);
        assertEquals(2, moved);
        assertEquals("cs", user.getString("locale"));
        assertFalse(user.getBoolean("update-check"));
        assertFalse(user.contains("language"));
        assertFalse(user.contains("updates.check"));
    }

    @Test
    void migrateMovesV1ProxyMojangKeysToPremiumSection() {
        YamlConfiguration user = new YamlConfiguration();
        user.set("config-version", 1);
        user.set("proxy.auto-detect-mojang", true);
        user.set("proxy.mojang-cache-seconds", 600);

        int moved = ConfigUpdater.migrate(user, ConfigUpdater.RENAMES);
        assertEquals(2, moved);
        assertEquals(true, user.getBoolean("premium.auto-detect-mojang"));
        assertEquals(600, user.getInt("premium.mojang-cache-seconds"));
        assertFalse(user.contains("proxy.auto-detect-mojang"));
        assertFalse(user.contains("proxy.mojang-cache-seconds"));
    }

    @Test
    void migrateKeepsAdminValueWhenSkinRestoreOptionIsRenamed() {
        YamlConfiguration user = new YamlConfiguration();
        user.set("config-version", 5);
        user.set("skins.restore-cracked-by-name", false);

        int moved = ConfigUpdater.migrate(user, ConfigUpdater.RENAMES);
        assertEquals(1, moved);
        assertFalse(user.getBoolean("skins.restore-by-name"), "admin's value must be preserved");
        assertFalse(user.contains("skins.restore-cracked-by-name"));
    }

    @Test
    void mergeUpgradesV2ConfigToV3WithEmailCaptchaBedrockAndLocalEditor() throws Exception {
        YamlConfiguration defaults = new YamlConfiguration();
        try (var in = getClass().getResourceAsStream("/config.yml")) {
            defaults.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }

        YamlConfiguration v2 = new YamlConfiguration();
        v2.set("config-version", 2);
        v2.set("locale", "sk");
        v2.set("premium.standalone-enabled", false);

        int added = ConfigUpdater.merge(v2, defaults);
        assertTrue(added > 5);
        assertEquals(6, v2.getInt("config-version"));
        assertEquals("sk", v2.getString("locale"));
        assertFalse(v2.getBoolean("premium.standalone-enabled"));
        assertTrue(v2.getBoolean("login.dialog-single-password"));
        assertTrue(v2.getBoolean("bedrock.cumulus-forms"));
        assertTrue(v2.getBoolean("captcha.enabled"));
        assertFalse(v2.getBoolean("email.enabled"));
        assertFalse(v2.getBoolean("editor.local-http.enabled"));
        assertTrue(v2.getBoolean("skins.enabled"));
        assertTrue(v2.getBoolean("skins.restore-by-name"));
        assertTrue(v2.getBoolean("skins.command-enabled"));
        assertEquals(60, v2.getInt("skins.cooldown-seconds"));
    }
}

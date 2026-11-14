package me.skerik.justlogin.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicLong;
import me.skerik.justlogin.core.model.CoreSettings;
import me.skerik.justlogin.core.storage.DbConfig;
import me.skerik.justlogin.paper.auth.AuthSessionManager.AuthState;
import me.skerik.justlogin.paper.auth.CaptchaManager;
import me.skerik.justlogin.paper.config.Settings;
import me.skerik.justlogin.paper.listener.PreAuthProtectionListener;
import me.skerik.justlogin.paper.util.ProxyStartupCheck;
import me.skerik.justlogin.paper.util.UpdateChecker;
import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class SecurityPaperTest {

    @Test
    void preAuthAllowlistEnforcesStrictStateAndRejectsForeignNamespaces() {
        assertTrue(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_LOGIN, "/login hunter2"));
        assertTrue(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_LOGIN, "/L hunter2"));
        assertTrue(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_LOGIN, "/justlogin:login hunter2"));
        assertTrue(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_LOGIN, "/captcha AB12C"));
        assertTrue(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_LOGIN, "/email recover Alice"));
        assertTrue(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_LOGIN, "/jl"));
        assertTrue(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_LOGIN, "/jl help"));
        assertTrue(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_LOGIN, "/justlogin ?"));
        assertFalse(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_LOGIN, "/jl reload"));
        assertFalse(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_LOGIN, "/email set a@b.com"));
        assertFalse(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_LOGIN, "/op Alice"));
        assertFalse(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_LOGIN, "/essentials:msg Bob hi"));
        assertFalse(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_LOGIN, "/register a a"));
        assertFalse(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_LOGIN, "/skin Notch"));
        assertFalse(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_LOGIN, "/skins reset"));
        assertFalse(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_LOGIN, "/jl skin Steve Alex"));

        assertTrue(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_REGISTER, "/register pass1 pass1"));
        assertTrue(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_REGISTER, "/captcha ZX98Q"));
        assertTrue(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_REGISTER, "/jl help"));
        assertFalse(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_REGISTER, "/2fa setup"));
        assertFalse(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_REGISTER, "/skin Notch"));

        assertTrue(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_2FA, "/2fa verify 123456"));
        assertFalse(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_2FA, "/2fa disable 123456"));

        assertTrue(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_FORCED_PW_CHANGE, "/cp old newpass1"));
        assertFalse(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_PROXY, "/login test"));
        assertFalse(PreAuthProtectionListener.isAllowedPreAuthCommand(AuthState.AWAITING_PROXY, "/jl help"));

        assertTrue(PreAuthProtectionListener.isAllowedPreAuthTabComplete(AuthState.AWAITING_LOGIN, "/login "));
        assertTrue(PreAuthProtectionListener.isAllowedPreAuthTabComplete(AuthState.AWAITING_LOGIN, "/captcha "));
        assertTrue(PreAuthProtectionListener.isAllowedPreAuthTabComplete(AuthState.AWAITING_LOGIN, "/email "));
        assertTrue(PreAuthProtectionListener.isAllowedPreAuthTabComplete(AuthState.AWAITING_LOGIN, "/email rec"));
        assertTrue(PreAuthProtectionListener.isAllowedPreAuthTabComplete(AuthState.AWAITING_LOGIN, "/email recover Alice"));
        assertTrue(PreAuthProtectionListener.isAllowedPreAuthTabComplete(AuthState.AWAITING_LOGIN, "/jl h"));
        assertFalse(PreAuthProtectionListener.isAllowedPreAuthTabComplete(AuthState.AWAITING_LOGIN, "/email set "));
        assertFalse(PreAuthProtectionListener.isAllowedPreAuthTabComplete(AuthState.AWAITING_LOGIN, "/op "));

        assertTrue(PreAuthProtectionListener.isAllowedPreAuthTabComplete(AuthState.AWAITING_2FA, "/2fa "));
        assertTrue(PreAuthProtectionListener.isAllowedPreAuthTabComplete(AuthState.AWAITING_2FA, "/2fa ver"));
        assertTrue(PreAuthProtectionListener.isAllowedPreAuthTabComplete(AuthState.AWAITING_2FA, "/2fa verify 123"));
        assertFalse(PreAuthProtectionListener.isAllowedPreAuthTabComplete(AuthState.AWAITING_2FA, "/2fa disable "));
    }

    @Test
    void configUpdaterMigratesWebUrlToJustLoginNet(@TempDir Path dir) throws Exception {
        YamlConfiguration defaults = new YamlConfiguration();
        try (var in = getClass().getResourceAsStream("/config.yml")) {
            assertNotNull(in);
            defaults.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
        assertEquals("https://justlogin.net", defaults.getString("editor.web-url"));

        Path cfgFile = dir.resolve("config.yml");
        Files.writeString(cfgFile,
                "config-version: 1\neditor:\n  web-url: \"https://filasik.github.io/justLogin/editor/\"\n");
        YamlConfiguration userCfg = YamlConfiguration.loadConfiguration(cfgFile.toFile());
        assertTrue(me.skerik.justlogin.paper.config.ConfigUpdater.migrate(userCfg, java.util.Map.of()) > 0);
        assertEquals("https://justlogin.net", userCfg.getString("editor.web-url"));
    }

    @Test
    void proxyStartupCheckFailsClosedOnMisconfiguration(@TempDir Path dir) throws Exception {
        Settings standalone = dummySettings(false, Settings.ProxyMode.STANDALONE, "", true);
        assertTrue(ProxyStartupCheck.evaluate(standalone, dir).healthy());

        Settings missingSecret = dummySettings(true, Settings.ProxyMode.VELOCITY, "", true);
        assertFalse(ProxyStartupCheck.evaluate(missingSecret, dir).healthy());

        Files.createDirectories(dir.resolve("config"));
        Files.writeString(dir.resolve("config/paper-global.yml"), "proxies:\n  velocity:\n    enabled: false\n");
        Settings forwardingDisabled = dummySettings(true, Settings.ProxyMode.VELOCITY, "super-strong-shared-secret-123", true);
        assertFalse(ProxyStartupCheck.evaluate(forwardingDisabled, dir).healthy());

        Files.writeString(dir.resolve("config/paper-global.yml"), "proxies:\n  velocity:\n    enabled: true\n    secret: abc\n");
        assertTrue(ProxyStartupCheck.evaluate(forwardingDisabled, dir).healthy());
    }

    @Test
    void updateCheckerSemverComparison() {
        assertTrue(UpdateChecker.isNewer("1.0.0", "1.0.1"));
        assertTrue(UpdateChecker.isNewer("1.0.0-SNAPSHOT", "1.0.0"));
        assertFalse(UpdateChecker.isNewer("1.0.0", "0.9.9"));
        assertFalse(UpdateChecker.isNewer("1.0.0", "1.0.0"));
    }

    @Test
    void captchaManagerTriggersAfterFailuresVerifiesOnceAndExpires() {
        AtomicLong clock = new AtomicLong(1_700_000_000_000L);
        CaptchaManager captcha = new CaptchaManager(clock::get);

        assertNull(captcha.recordFailure("alice", true, 3, 5, 120));
        assertNull(captcha.recordFailure("alice", true, 3, 5, 120));
        CaptchaManager.Challenge ch = captcha.recordFailure("alice", true, 3, 5, 120);
        assertNotNull(ch);
        assertEquals(5, ch.code().length());

        assertFalse(captcha.verify("alice", "WRONG"));
        assertTrue(captcha.verify("alice", ch.code().toLowerCase()));
        assertNull(captcha.getPending("alice"));

        CaptchaManager.Challenge exp = captcha.ensureRequiredForRegister("bob", true, true, 6, 30);
        assertNotNull(exp);
        clock.addAndGet(31_000L);
        assertNull(captcha.getPending("bob"));
    }

    @Test
    void paperPluginYmlDefinesGranularAdminPermissionsAndEmail() throws Exception {
        YamlConfiguration pluginYml = new YamlConfiguration();
        pluginYml.options().pathSeparator('/');
        try (var in = getClass().getResourceAsStream("/paper-plugin.yml")) {
            assertNotNull(in);
            pluginYml.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
        assertTrue(pluginYml.getBoolean("folia-supported"));
        assertTrue(pluginYml.contains("permissions/justlogin.email"));
        for (String sub : new String[] { "reload", "status", "audit", "unregister", "changepass",
                "reset2fa", "setpremium", "forcepw", "rename", "merge", "gui", "import" }) {
            assertTrue(pluginYml.getBoolean("permissions/justlogin.admin/children/justlogin.admin." + sub),
                    "Missing child permission justlogin.admin." + sub);
        }
    }

    @Test
    void accountSnapshotExcludesAllSecretsAndPiiHashes() {
        java.util.Set<String> forbidden = java.util.Set.of(
                "passwordHash", "totpSecretEncrypted", "lastIpHash", "email", "recoveryCodeHash", "recoveryExpiresAt");
        for (java.lang.reflect.RecordComponent rc : me.skerik.justlogin.api.AccountSnapshot.class.getRecordComponents()) {
            assertFalse(forbidden.contains(rc.getName()),
                    "AccountSnapshot must never expose sensitive field: " + rc.getName());
        }

        java.util.UUID gameUuid = java.util.UUID.randomUUID();
        java.util.UUID premUuid = java.util.UUID.randomUUID();
        me.skerik.justlogin.core.model.Account acc = new me.skerik.justlogin.core.model.Account(
                7L, "alice", "Alice", gameUuid, premUuid, "$argon2id$secret",
                me.skerik.justlogin.core.model.HashAlgorithm.ARGON2ID, Boolean.TRUE, false,
                "v1:encryptedTotp", 12L, false, 1000L, 2000L, "hmac-ip", 2500L,
                "alice@example.com", "hmac-recovery", 3000L);

        me.skerik.justlogin.api.AccountSnapshot snap = me.skerik.justlogin.api.AccountSnapshot.fromAccount(acc);
        assertEquals(7L, snap.id());
        assertEquals("Alice", snap.username());
        assertEquals(gameUuid, snap.gameUuid());
        assertEquals(premUuid, snap.premiumUuid());
        assertTrue(snap.premiumConfirmed());
        assertTrue(snap.hasTotp());
        assertFalse(snap.forcePasswordChange());
        assertTrue(snap.hasEmail());
        assertEquals(1000L, snap.registeredAt());
        assertEquals(2000L, snap.lastLoginAt());
    }

    @Test
    void adminGuiClickAndDragHandlersEnforceRule8CancelOnHighestPriority() throws Exception {
        java.lang.reflect.Method onClick = me.skerik.justlogin.paper.gui.AdminGui.class.getMethod(
                "onInventoryClick", org.bukkit.event.inventory.InventoryClickEvent.class);
        java.lang.reflect.Method onDrag = me.skerik.justlogin.paper.gui.AdminGui.class.getMethod(
                "onInventoryDrag", org.bukkit.event.inventory.InventoryDragEvent.class);

        org.bukkit.event.EventHandler clickAnn = onClick.getAnnotation(org.bukkit.event.EventHandler.class);
        org.bukkit.event.EventHandler dragAnn = onDrag.getAnnotation(org.bukkit.event.EventHandler.class);
        assertNotNull(clickAnn);
        assertNotNull(dragAnn);
        assertEquals(org.bukkit.event.EventPriority.HIGHEST, clickAnn.priority());
        assertEquals(org.bukkit.event.EventPriority.HIGHEST, dragAnn.priority());
        assertFalse(clickAnn.ignoreCancelled(), "Rule 8 requires handling even pre-cancelled events");
        assertFalse(dragAnn.ignoreCancelled(), "Rule 8 requires handling even pre-cancelled events");
    }

    @Test
    void p01PreAuthGrantAndConfigDialogConcurrencyGuards() {
        me.skerik.justlogin.paper.auth.AuthSessionManager mgr = new me.skerik.justlogin.paper.auth.AuthSessionManager();
        java.util.UUID aliceUuid = java.util.UUID.randomUUID();
        Object connA = new Object();

        var pending = mgr.createConfigAuth("Alice", aliceUuid, "203.0.113.5", connA,
                me.skerik.justlogin.paper.auth.AuthSessionManager.ConfigPhase.LOGIN, null);
        assertTrue(mgr.hasActiveConfigAuth("alice"));

        // P0-4: PendingConfigAuth allows only one in-flight operation at a time
        assertTrue(pending.tryBeginOp());
        assertFalse(pending.tryBeginOp());
        pending.endOp();
        assertTrue(pending.tryBeginOp());
        pending.endOp();

        // P0-1: Rejected duplicate connection close must not cancel Connection A's active dialog
        mgr.recordRejectedDuplicate("Alice");
        mgr.onConnectionClosed("Alice", aliceUuid);
        assertFalse(pending.future().isDone());
        assertTrue(mgr.hasActiveConfigAuth("Alice"));

        // P0-1: PreAuthGrant binds IP and UUID
        mgr.finishConfigAuth(pending, me.skerik.justlogin.paper.auth.AuthSessionManager.ConfigOutcome.ok(null));
        assertFalse(mgr.hasActiveConfigAuth("Alice"));

        mgr.grantPreAuth("Alice", aliceUuid, "203.0.113.5", AuthState.AUTHENTICATED, null, false);
        assertNull(mgr.consumePreAuthGrant("Alice", aliceUuid, "198.51.100.99"),
                "Mismatched IP must not consume PreAuthGrant");

        mgr.grantPreAuth("Alice", aliceUuid, "203.0.113.5", AuthState.AUTHENTICATED, null, false);
        assertNull(mgr.consumePreAuthGrant("Alice", java.util.UUID.randomUUID(), "203.0.113.5"),
                "Mismatched UUID must not consume PreAuthGrant");

        mgr.grantPreAuth("Alice", aliceUuid, "203.0.113.5", AuthState.AUTHENTICATED, null, false);
        assertNotNull(mgr.consumePreAuthGrant("Alice", aliceUuid, "203.0.113.5"));
    }

    @Test
    void p03LogPasswordFilterRedactsEmailSetAndConfirm() {
        assertTrue(me.skerik.justlogin.paper.util.LogPasswordFilter.isSensitiveCommandLog(
                "Alice issued server command: /email set alice@example.com MySecretPass123"));
        assertTrue(me.skerik.justlogin.paper.util.LogPasswordFilter.isSensitiveCommandLog(
                "Alice issued server command: /email confirm AB12CD34"));
        assertTrue(me.skerik.justlogin.paper.util.LogPasswordFilter.isSensitiveCommandLog(
                "Alice issued server command: /justlogin:email set alice@example.com MySecretPass123"));
        assertFalse(me.skerik.justlogin.paper.util.LogPasswordFilter.isSensitiveCommandLog(
                "Alice issued server command: /email clear"));
    }

    private static Settings dummySettings(boolean proxyEnabled, Settings.ProxyMode mode, String secret, boolean requireFwd) {
        return new Settings(
                "en", Settings.UiMode.DIALOG, 60, true, true, true,
                CoreSettings.defaults(), true, false, proxyEnabled, mode, secret, requireFwd,
                DbConfig.memory(), "https://example.com", "https://bytebin.lucko.me", 500, 1800, false, true);
    }
}

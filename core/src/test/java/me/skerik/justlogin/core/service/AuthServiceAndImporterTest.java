package me.skerik.justlogin.core.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.HexFormat;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import me.skerik.justlogin.core.crypto.HashingExecutor;
import me.skerik.justlogin.core.crypto.PasswordHasher;
import me.skerik.justlogin.core.crypto.ServerSecrets;
import me.skerik.justlogin.core.crypto.TotpService;
import me.skerik.justlogin.core.importer.AuthMeImporter;
import me.skerik.justlogin.core.importer.FastLoginImporter;
import me.skerik.justlogin.core.model.Account;
import me.skerik.justlogin.core.model.CoreSettings;
import me.skerik.justlogin.core.model.HashAlgorithm;
import me.skerik.justlogin.core.security.LoginRateLimiter;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import me.skerik.justlogin.core.storage.BackupCodeStore;
import me.skerik.justlogin.core.storage.Database;
import me.skerik.justlogin.core.storage.DbConfig;
import me.skerik.justlogin.core.storage.Migrations;
import me.skerik.justlogin.core.storage.SessionStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuthServiceAndImporterTest {

    @TempDir Path dir;

    private static CoreSettings testSettings(boolean sessionsEnabled) {
        return new CoreSettings(
                Pattern.compile("^[a-zA-Z0-9_]{3,16}$"),
                8, 128, true, true,
                4096, 1, 1, 2, 16,
                5, 20, 500L, 60L,
                sessionsEnabled, 3600L, "JustLoginTest", 1, false, 300L
        );
    }

    @Test
    void fullAuthLifecycleSessions2faAndRehash() throws Exception {
        AtomicLong now = new AtomicLong(1_700_000_000_000L);
        ServerSecrets secrets = ServerSecrets.generateEphemeral();
        try (Database db = new Database(DbConfig.memory());
             HashingExecutor hashing = new HashingExecutor(2, 16)) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            SessionStore sessions = new SessionStore(db);
            BackupCodeStore backupCodes = new BackupCodeStore(db);
            AuditStore audit = new AuditStore(db);

            // Start with sessions disabled (secure default)
            CoreSettings[] activeSettings = { testSettings(false) };
            AuthService auth = new AuthService(accounts, sessions, backupCodes, audit, secrets, hashing,
                    new LoginRateLimiter(now::get), () -> activeSettings[0], now::get);

            UUID steveUuid = AuthMeImporter.offlineUuid("Steve");
            AuthService.RegisterResult reg = auth.register("Steve", steveUuid, "SecretPass#42".toCharArray(), "10.0.0.5", "Steve").join();
            assertEquals(AuthService.Status.SUCCESS, reg.status());
            assertNotNull(reg.account());

            // Case-insensitive duplicate registration blocked (threat #12)
            AuthService.RegisterResult dup = auth.register("sTeVe", UUID.randomUUID(), "AnotherPass#99".toCharArray(), "10.0.0.6", "sTeVe").join();
            assertEquals(AuthService.Status.ALREADY_REGISTERED, dup.status());

            // Enable sessions and verify session created on login & invalidated on changePassword/logout
            activeSettings[0] = testSettings(true);
            AuthService.LoginResult login = auth.login("steve", "SecretPass#42".toCharArray(), "10.0.0.5").join();
            assertEquals(AuthService.Status.SUCCESS, login.status());
            assertEquals(AuthService.PreAuthCheck.Decision.SESSION_RESUMED,
                    auth.checkPreAuth("Steve", "10.0.0.5").join().decision());
            assertEquals(AuthService.PreAuthCheck.Decision.REQUIRE_LOGIN,
                    auth.checkPreAuth("Steve", "10.0.0.99").join().decision());

            // Change password invalidates session
            assertEquals(AuthService.Status.SUCCESS,
                    auth.changePassword("Steve", "SecretPass#42".toCharArray(), "NewStrong!Pass88".toCharArray(), "Steve", false).join().status());
            assertEquals(AuthService.PreAuthCheck.Decision.REQUIRE_LOGIN,
                    auth.checkPreAuth("Steve", "10.0.0.5").join().decision());

            // Setup 2FA
            AuthService.TotpSetupData setup = auth.beginTotpSetup("Steve").join();
            assertEquals(AuthService.Status.SUCCESS, setup.status());
            String code = TotpService.generateCodeForStep(TotpService.decodeBase32(setup.base32Secret()), now.get() / 30_000L);
            AuthService.TotpConfirmResult confirm = auth.confirmTotpSetup("Steve", setup.base32Secret(), code, "Steve").join();
            assertEquals(AuthService.Status.SUCCESS, confirm.status());
            assertEquals(8, confirm.backupCodes().size());

            // Login now requires 2FA
            AuthService.LoginResult need2fa = auth.login("Steve", "NewStrong!Pass88".toCharArray(), "10.0.0.5").join();
            assertEquals(AuthService.Status.NEEDS_2FA, need2fa.status());

            // Replay same setup step code is rejected!
            assertEquals(AuthService.Status.INVALID_CODE, auth.verifyTotp("Steve", code, "10.0.0.5").join().status());

            // Backup code works once, then fails
            String backup = confirm.backupCodes().getFirst();
            assertEquals(AuthService.Status.SUCCESS, auth.verifyTotp("Steve", backup, "10.0.0.5").join().status());
            assertEquals(AuthService.Status.INVALID_CODE, auth.verifyTotp("Steve", backup, "10.0.0.5").join().status());

            // Audit log has entries and NEVER contains passwords or secrets
            var logs = audit.recent(20).join();
            assertFalse(logs.isEmpty());
            for (var entry : logs) {
                String details = entry.details() == null ? "" : entry.details();
                assertFalse(details.contains("SecretPass") || details.contains("NewStrong"));
            }
        }
    }

    @Test
    void authMeAndFastLoginImportersMigrateAndUpgradeHashes() throws Exception {
        AtomicLong now = new AtomicLong(1_700_000_000_000L);
        ServerSecrets secrets = ServerSecrets.generateEphemeral();
        Path authMeDb = dir.resolve("authme.db");
        Path fastLoginDb = dir.resolve("fastlogin.db");

        String salt = "deadbeef01020304";
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String inner = HexFormat.of().formatHex(md.digest("LegacyPass!9".getBytes(StandardCharsets.UTF_8)));
        String outer = HexFormat.of().formatHex(md.digest((inner + salt).getBytes(StandardCharsets.UTF_8)));
        String shaHash = "$SHA$" + salt + "$" + outer;

        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + authMeDb); Statement st = c.createStatement()) {
            st.execute("CREATE TABLE authme (id INTEGER PRIMARY KEY, username VARCHAR(32), realname VARCHAR(32), password VARCHAR(255), ip VARCHAR(40), lastlogin BIGINT, regdate BIGINT)");
            st.execute("INSERT INTO authme VALUES (1, 'legacyuser', 'LegacyUser', '" + shaHash + "', '192.168.1.5', 1600000000000, 1500000000000)");
        }

        UUID mojangUuid = UUID.randomUUID();
        UUID anotherUuid = UUID.randomUUID();
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + fastLoginDb); Statement st = c.createStatement()) {
            st.execute("CREATE TABLE premium (UserID INTEGER PRIMARY KEY, UUID VARCHAR(36), Name VARCHAR(32), Premium BOOLEAN, Floodgate BOOLEAN)");
            st.execute("INSERT INTO premium VALUES (1, '" + mojangUuid + "', 'LegacyUser', 1, 0)");
            st.execute("INSERT INTO premium VALUES (2, '" + anotherUuid + "', 'PurePrem', 1, 0)");
            st.execute("INSERT INTO premium VALUES (3, '" + UUID.randomUUID() + "', '.BedrockGuy', 0, 1)");
        }

        try (Database db = new Database(DbConfig.memory());
             HashingExecutor hashing = new HashingExecutor(2, 16)) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            SessionStore sessions = new SessionStore(db);
            BackupCodeStore backupCodes = new BackupCodeStore(db);
            AuditStore audit = new AuditStore(db);
            CoreSettings settings = testSettings(false);
            AuthService auth = new AuthService(accounts, sessions, backupCodes, audit, secrets, hashing,
                    new LoginRateLimiter(now::get), () -> settings, now::get);

            AuthMeImporter.ImportReport r1 = AuthMeImporter.importFromSqlite(
                    authMeDb.toString(), "authme", accounts, audit, secrets, "CONSOLE", now.get()).join();
            assertEquals(1, r1.imported());

            Account legacy = accounts.findByNameLower("legacyuser").join().orElseThrow();
            assertEquals(HashAlgorithm.AUTHME_SHA256, legacy.hashAlgo());
            UUID assignedGameUuid = legacy.gameUuid();

            // Login upgrades legacy SHA256 hash to Argon2id
            AuthService.LoginResult login = auth.login("LegacyUser", "LegacyPass!9".toCharArray(), "192.168.1.5").join();
            assertEquals(AuthService.Status.SUCCESS, login.status());
            Account upgraded = accounts.findByNameLower("legacyuser").join().orElseThrow();
            assertEquals(HashAlgorithm.ARGON2ID, upgraded.hashAlgo());
            assertTrue(upgraded.passwordHash().startsWith("$argon2id$"));

            // P0-6: FastLogin import for a Premium=1 player pairs onto the AuthMe account and aligns game_uuid
            // with FastLogin's Mojang UUID (since AuthMe had no UUID column and only generated a synthetic offline UUID)
            FastLoginImporter.ImportReport r2 = FastLoginImporter.importFromSqlite(
                    fastLoginDb.toString(), "premium", accounts, audit, "CONSOLE", now.get()).join();
            assertEquals(1, r2.importedNew());
            assertEquals(1, r2.updatedExisting());
            assertEquals(1, r2.skipped()); // Floodgate skipped

            Account afterFl = accounts.findByNameLower("legacyuser").join().orElseThrow();
            assertNotEquals(assignedGameUuid, mojangUuid);
            assertEquals(mojangUuid, afterFl.gameUuid());
            assertEquals(mojangUuid, afterFl.premiumUuid());
            assertTrue(afterFl.isPremiumConfirmed());

            Account purePrem = accounts.findByNameLower("pureprem").join().orElseThrow();
            assertEquals(anotherUuid, purePrem.gameUuid());
            assertTrue(purePrem.isPremiumConfirmed());
        }
    }

    @Test
    void requestPremiumAndCrackedManagePendingAndConfirmedStates() throws Exception {
        AtomicLong now = new AtomicLong(1_700_000_000_000L);
        ServerSecrets secrets = ServerSecrets.generateEphemeral();
        try (Database db = new Database(DbConfig.memory());
             HashingExecutor hashing = new HashingExecutor(2, 16)) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            SessionStore sessions = new SessionStore(db);
            BackupCodeStore backupCodes = new BackupCodeStore(db);
            AuditStore audit = new AuditStore(db);
            CoreSettings settings = testSettings(false);
            AuthService auth = new AuthService(accounts, sessions, backupCodes, audit, secrets, hashing,
                    new LoginRateLimiter(now::get), () -> settings, now::get);

            UUID gameUuid = UUID.randomUUID();
            auth.register("PremPlayer", gameUuid, "Strong!Pass99".toCharArray(), "127.0.0.1", "PremPlayer").join();

            // First /premium sets pending flag
            assertEquals(AuthService.Status.SUCCESS, auth.requestPremium("PremPlayer", "PremPlayer").join().status());
            assertTrue(accounts.findByNameLower("premplayer").join().orElseThrow().premiumPending());

            // Confirming Mojang ownership enables premium=true while preserving gameUuid
            Account acc = accounts.findByNameLower("premplayer").join().orElseThrow();
            UUID mojangUuid = UUID.randomUUID();
            accounts.confirmPremium(acc.id(), mojangUuid, "premplayer", "PremPlayer", now.get()).join();

            // Repeat /premium on already-confirmed account returns ALREADY_PREMIUM
            assertEquals(AuthService.Status.ALREADY_PREMIUM, auth.requestPremium("PremPlayer", "PremPlayer").join().status());

            // Switching back to /unpremium disables premium & preserves original gameUuid
            assertEquals(AuthService.Status.SUCCESS, auth.setCracked("PremPlayer", "PremPlayer").join().status());
            Account crackedAgain = accounts.findByNameLower("premplayer").join().orElseThrow();
            assertFalse(crackedAgain.isPremiumConfirmed());
            assertFalse(crackedAgain.premiumPending());
            assertEquals(gameUuid, crackedAgain.gameUuid());
        }
    }
}

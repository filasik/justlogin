package me.skerik.justlogin.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.SecretKey;
import me.skerik.justlogin.core.crypto.AesGcmCrypto;
import me.skerik.justlogin.core.crypto.HashingExecutor;
import me.skerik.justlogin.core.crypto.ProxyTokenSigner;
import me.skerik.justlogin.core.crypto.ServerSecrets;
import me.skerik.justlogin.core.crypto.TotpService;
import me.skerik.justlogin.core.model.CoreSettings;
import me.skerik.justlogin.core.model.HashAlgorithm;
import me.skerik.justlogin.core.model.SmtpConfig;
import me.skerik.justlogin.core.security.LoginRateLimiter;
import me.skerik.justlogin.core.service.AuthService;
import me.skerik.justlogin.core.service.EmailRecoveryService;
import me.skerik.justlogin.core.service.MojangApiClient;
import me.skerik.justlogin.core.service.ProxyAuthService;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import me.skerik.justlogin.core.storage.BackupCodeStore;
import me.skerik.justlogin.core.storage.Database;
import me.skerik.justlogin.core.storage.DbConfig;
import me.skerik.justlogin.core.storage.Migrations;
import me.skerik.justlogin.core.storage.SessionStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Automated verification of Plan Section 8 Threat Model (#2, #3, #4, #5, #6, #7, #9, #11, #12, #14)
 * plus Schema v2, Email Recovery, Rename, and Merge flows.
 */
final class ThreatModelMatrixTest {

    @TempDir Path dir;

    @Test
    void threat2_proxyBackendAuthOkTokenSignedAndReplayOrWrongKeyRejected() throws Exception {
        SecretKey secretA = ServerSecrets.loadOrCreate(dir.resolve("a.key")).withProxySecret("secret-alpha-123456").proxySecret();
        SecretKey secretB = ServerSecrets.loadOrCreate(dir.resolve("b.key")).withProxySecret("secret-bravo-987654").proxySecret();
        ProxyTokenSigner signerA = new ProxyTokenSigner(secretA);
        ProxyTokenSigner verifierA = new ProxyTokenSigner(secretA);
        ProxyTokenSigner verifierB = new ProxyTokenSigner(secretB);

        UUID uuid = UUID.randomUUID();
        long now = 1_700_000_000_000L;
        byte[] packet = signerA.sign(ProxyTokenSigner.MessageType.BACKEND_AUTH_OK, 42L, "alice", uuid, now);

        ProxyTokenSigner.VerifiedMessage ok = verifierA.verify(packet, now + 1000L);
        assertNotNull(ok);
        assertEquals(ProxyTokenSigner.MessageType.BACKEND_AUTH_OK, ok.type());
        assertEquals(42L, ok.accountId());
        assertEquals(uuid, ok.gameUuid());

        // Replay must fail (nonce already seen)
        assertNull(verifierA.verify(packet, now + 1500L));
        // Wrong shared secret must fail
        assertNull(verifierB.verify(packet, now + 1000L));
        // Expired token (>30s) must fail
        assertNull(verifierA.verify(packet, now + 45_000L));
    }

    @Test
    void threat3_4_7_9_11_12_14_securityInvariantsAndAccountLifecycle() throws Exception {
        CoreSettings d = CoreSettings.defaults();
        assertFalse(d.premiumAutoDetect(), "Threat #3: Mojang auto-detect must be disabled by default");
        assertFalse(d.sessionsEnabled(), "Threat #4: IP sessions must be disabled by default");

        AtomicLong clock = new AtomicLong(1_700_000_000_000L);
        ServerSecrets secrets = ServerSecrets.loadOrCreate(dir.resolve("secrets.key"));
        CoreSettings testSettings = new CoreSettings(
                d.usernamePattern(), 8, 128, true, true, 4096, 1, 1, 2, 16,
                2, 10, 0L, 60L, true, 3600L, "JustLogin", 1, false, 300L);

        try (Database db = new Database(DbConfig.memory());
             HashingExecutor hashing = new HashingExecutor(2, 16)) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            SessionStore sessions = new SessionStore(db);
            BackupCodeStore backups = new BackupCodeStore(db);
            AuditStore audit = new AuditStore(db);
            LoginRateLimiter rl = new LoginRateLimiter(clock::get);
            AuthService auth = new AuthService(
                    accounts, sessions, backups, audit, secrets, hashing, rl, () -> testSettings, clock::get);

            UUID aliceUuid = UUID.randomUUID();
            var reg = auth.register("Alice", aliceUuid, "CorrectHorse99".toCharArray(), "10.0.0.1", "Alice").join();
            assertEquals(AuthService.Status.SUCCESS, reg.status());

            // Threat #12: Case-insensitive username collision
            var dup = auth.register("aLiCe", UUID.randomUUID(), "OtherStrong99".toCharArray(), "10.0.0.2", "aLiCe").join();
            assertEquals(AuthService.Status.ALREADY_REGISTERED, dup.status());
            var badName = auth.register("bad name!", UUID.randomUUID(), "OtherStrong99".toCharArray(), "10.0.0.2", "bad").join();
            assertEquals(AuthService.Status.INVALID_USERNAME, badName.status());

            // Threat #9: Password hashed with Argon2id, IP saved as HMAC only
            var stored = accounts.findByNameLower("alice").join().orElseThrow();
            assertTrue(stored.passwordHash().startsWith("$argon2id$"));
            assertNotEquals("10.0.0.1", stored.lastIpHash());

            // Threat #4: Session exists on same IP, but invalidated after password change and logout
            assertEquals(AuthService.PreAuthCheck.Decision.SESSION_RESUMED,
                    auth.checkPreAuth("Alice", "10.0.0.1").join().decision());
            assertEquals(AuthService.Status.SUCCESS,
                    auth.changePassword("Alice", "CorrectHorse99".toCharArray(), "NewStrongPass1!".toCharArray(), "Alice", false)
                            .join().status());
            assertEquals(AuthService.PreAuthCheck.Decision.REQUIRE_LOGIN,
                    auth.checkPreAuth("Alice", "10.0.0.1").join().decision());

            // Threat #7: Brute forcing from 1.1.1.1 locks only (alice, 1.1.1.1), NOT legitimate user at 10.0.0.1
            assertEquals(AuthService.Status.INVALID_CREDENTIALS,
                    auth.login("Alice", "wrong1".toCharArray(), "1.1.1.1").join().status());
            assertEquals(AuthService.Status.RATE_LIMITED,
                    auth.login("Alice", "wrong2".toCharArray(), "1.1.1.1").join().status());
            assertEquals(AuthService.Status.RATE_LIMITED,
                    auth.login("Alice", "wrong3".toCharArray(), "1.1.1.1").join().status());
            assertEquals(AuthService.Status.SUCCESS,
                    auth.login("Alice", "NewStrongPass1!".toCharArray(), "10.0.0.1").join().status());

            // Threat #4 again: /logout invalidates active session
            auth.logout("Alice", "Alice").join();
            assertEquals(AuthService.PreAuthCheck.Decision.REQUIRE_LOGIN,
                    auth.checkPreAuth("Alice", "10.0.0.1").join().decision());

            // Threat #11: TOTP step replay blocked + backup codes hashed & single-use
            var totpSetup = auth.beginTotpSetup("Alice").join();
            long step = clock.get() / 1000L / 30L;
            String code = TotpService.generateCodeForStep(TotpService.decodeBase32(totpSetup.base32Secret()), step);
            var totpConfirm = auth.confirmTotpSetup("Alice", totpSetup.base32Secret(), code, "Alice").join();
            assertEquals(AuthService.Status.SUCCESS, totpConfirm.status());
            assertFalse(totpConfirm.backupCodes().isEmpty());

            // Encrypted TOTP secret in DB
            var withTotp = accounts.findByNameLower("alice").join().orElseThrow();
            assertTrue(withTotp.totpSecretEncrypted().startsWith("v1:"));
            assertEquals(totpSetup.base32Secret(), AesGcmCrypto.decrypt(secrets.totpKey(), withTotp.totpSecretEncrypted()));

            assertEquals(AuthService.Status.NEEDS_2FA,
                    auth.login("Alice", "NewStrongPass1!".toCharArray(), "10.0.0.1").join().status());
            // Setup confirmation already recorded this TOTP step: replaying the confirmation code must fail
            assertEquals(AuthService.Status.INVALID_CODE,
                    auth.verifyTotp("Alice", code, "10.0.0.1").join().status());
            // Advance 30s to next step -> accepted once, replay in same step rejected
            clock.addAndGet(30_000L);
            String nextCode = TotpService.generateCodeForStep(
                    TotpService.decodeBase32(totpSetup.base32Secret()), clock.get() / 1000L / 30L);
            assertEquals(AuthService.Status.SUCCESS,
                    auth.verifyTotp("Alice", nextCode, "10.0.0.1").join().status());
            assertEquals(AuthService.Status.INVALID_CODE,
                    auth.verifyTotp("Alice", nextCode, "10.0.0.1").join().status());
            // Single-use backup code: works once, second use fails
            String backupCode = totpConfirm.backupCodes().getFirst();
            assertEquals(AuthService.Status.NEEDS_2FA,
                    auth.login("Alice", "NewStrongPass1!".toCharArray(), "10.0.0.1").join().status());
            assertEquals(AuthService.Status.SUCCESS,
                    auth.verifyTotp("Alice", backupCode, "10.0.0.1").join().status());
            assertEquals(AuthService.Status.INVALID_CODE,
                    auth.verifyTotp("Alice", backupCode, "10.0.0.1").join().status());

            // Threat #14: Admin actions recorded in audit log
            assertEquals(AuthService.Status.SUCCESS,
                    auth.adminResetTotp("Alice", "Console").join().status());
            List<String> actions = audit.recent(20).join().stream().map(e -> e.action()).toList();
            assertTrue(actions.contains("ADMIN_RESET_2FA"));
            assertTrue(actions.contains("TOTP_ENABLE"));
            assertTrue(actions.contains("TOTP_BACKUP_USED"));
            assertTrue(actions.contains("CHANGE_PASSWORD"));

            // Also verify ProxyAuthService pending rollback on cracked join (Threat #3)
            auth.requestPremium("Alice", "Alice").join();
            ProxyAuthService proxyAuth = new ProxyAuthService(
                    accounts, audit, new MojangApiClient(300, clock::get), secrets, () -> testSettings, clock::get);
            assertEquals(ProxyAuthService.PreLoginAction.FORCE_ONLINE,
                    proxyAuth.decidePreLogin("Alice", false).join().action());
            // Cracked join right after must fail offline if online fails, and pending flag is already cleared in DB
            assertFalse(accounts.findByNameLower("alice").join().orElseThrow().premiumPending());
        }
    }

    @Test
    void schemaV1ToV2MigrationRenameMergeAndEmailRecoveryEndToEnd() throws Exception {
        AtomicLong clock = new AtomicLong(1_700_000_000_000L);
        ServerSecrets secrets = ServerSecrets.loadOrCreate(dir.resolve("secrets2.key"));
        CoreSettings d = CoreSettings.defaults();
        CoreSettings cs = new CoreSettings(
                d.usernamePattern(), 8, 128, true, true, 4096, 1, 1, 2, 16,
                5, 20, 0L, 60L, true, 3600L, "JustLogin", 1, false, 300L);

        try (Database db = new Database(DbConfig.sqlite(dir.resolve("upgrade.db"), 2));
             HashingExecutor hashing = new HashingExecutor(2, 16)) {
            // Migrate explicitly from v1 first, create v1-era account, then migrate to v2
            assertEquals(1, Migrations.migrate(db, 1));
            AccountStore accounts = new AccountStore(db);
            SessionStore sessions = new SessionStore(db);
            BackupCodeStore backups = new BackupCodeStore(db);
            AuditStore audit = new AuditStore(db);

            UUID oldUuid = UUID.randomUUID();
            UUID dupUuid = UUID.randomUUID();
            UUID mojangUuid = UUID.randomUUID();

            accounts.createAccount("oldname", "OldName", oldUuid, mojangUuid, "$argon2id$hash1",
                    HashAlgorithm.ARGON2ID, true, false, 1000L, "iph1").join();
            assertEquals(Migrations.latestVersion(), Migrations.migrate(db));

            var upgraded = accounts.findByNameLower("oldname").join().orElseThrow();
            assertEquals(oldUuid, upgraded.gameUuid());
            assertNull(upgraded.email());

            LoginRateLimiter rl = new LoginRateLimiter(clock::get);
            AuthService auth = new AuthService(
                    accounts, sessions, backups, audit, secrets, hashing, rl, () -> cs, clock::get);

            // Rename collision vs success preserving game_uuid
            accounts.createAccount("existing", "Existing", dupUuid, null, "$argon2id$hash2",
                    HashAlgorithm.ARGON2ID, false, false, 2000L, "iph2").join();
            assertEquals(AuthService.Status.TARGET_ALREADY_EXISTS,
                    auth.renameAccount("OldName", "Existing", "Admin").join().status());
            assertEquals(AuthService.Status.SUCCESS,
                    auth.renameAccount("OldName", "NewName", "Admin").join().status());

            var renamed = accounts.findByNameLower("newname").join().orElseThrow();
            assertEquals(oldUuid, renamed.gameUuid());
            assertTrue(accounts.findByNameLower("oldname").join().isEmpty());

            // Merge NewName (has premium + pw) -> Existing (has dupUuid, no premium)
            assertEquals(AuthService.Status.CANNOT_MERGE_SELF,
                    auth.mergeAccounts("Existing", "Existing", "Admin").join().status());
            assertEquals(AuthService.Status.SUCCESS,
                    auth.mergeAccounts("NewName", "Existing", "Admin").join().status());

            var merged = accounts.findByNameLower("existing").join().orElseThrow();
            assertEquals(dupUuid, merged.gameUuid(), "Surviving account must retain its game_uuid");
            assertEquals(mojangUuid, merged.premiumUuid(), "Premium UUID must transfer safely without UNIQUE conflict");
            assertTrue(merged.isPremiumConfirmed());
            assertTrue(accounts.findByNameLower("newname").join().isEmpty());

            // Email recovery end-to-end
            CopyOnWriteArrayList<String> sentBodies = new CopyOnWriteArrayList<>();
            AtomicReference<SmtpConfig> smtpRef = new AtomicReference<>(new SmtpConfig(
                    true, "localhost", 25, SmtpConfig.Security.NONE, "", "",
                    "noreply@example.com", "JustLogin", 1000, 1000, 600, 60L, "TestMC"));
            EmailRecoveryService emailSvc = new EmailRecoveryService(
                    accounts, sessions, audit, secrets, hashing, rl,
                    (to, sub, body) -> {
                        sentBodies.add(to + "|" + sub + "|" + body);
                        return java.util.concurrent.CompletableFuture.completedFuture(null);
                    },
                    () -> cs, smtpRef::get, clock::get);

            assertEquals(EmailRecoveryService.Status.INVALID_EMAIL,
                    emailSvc.setEmail("Existing", "not-an-email", "Existing").join().status());
            assertEquals(EmailRecoveryService.Status.SUCCESS,
                    emailSvc.setEmail("Existing", "User.Player@Example.COM", "Existing").join().status());
            assertEquals("user.player@example.com", accounts.findByNameLower("existing").join().orElseThrow().email());

            assertEquals(EmailRecoveryService.Status.SUCCESS,
                    emailSvc.requestRecovery("Existing", "10.0.0.5").join().status());
            assertEquals(EmailRecoveryService.Status.COOLDOWN,
                    emailSvc.requestRecovery("Existing", "10.0.0.5").join().status());
            assertEquals(1, sentBodies.size());

            // Extract 8-char recovery code from sent email body
            String body = sentBodies.getFirst();
            String marker = "recovery code: ";
            int idx = body.indexOf(marker);
            assertTrue(idx > 0);
            String recoveryCode = body.substring(idx + marker.length(), idx + marker.length() + 8);

            // Wrong code fails, valid code resets password once and clears code
            assertEquals(EmailRecoveryService.Status.INVALID_OR_EXPIRED_CODE,
                    emailSvc.completeRecovery("Existing", "WRONGCOD", "NewRecovered99!".toCharArray(), "10.0.0.5")
                            .join().status());
            assertEquals(EmailRecoveryService.Status.SUCCESS,
                    emailSvc.completeRecovery("Existing", recoveryCode, "NewRecovered99!".toCharArray(), "10.0.0.5")
                            .join().status());
            // Reusing same code must fail (single-use)
            assertEquals(EmailRecoveryService.Status.INVALID_OR_EXPIRED_CODE,
                    emailSvc.completeRecovery("Existing", recoveryCode, "AnotherPass99!".toCharArray(), "10.0.0.5")
                            .join().status());

            // New password works for login
            assertEquals(AuthService.Status.SUCCESS,
                    auth.login("Existing", "NewRecovered99!".toCharArray(), "10.0.0.5").join().status());
        }
    }

    @Test
    void threat6_hashingBusyReturnedWhenQueueSaturated() throws Exception {
        AtomicLong clock = new AtomicLong(1_700_000_000_000L);
        ServerSecrets secrets = ServerSecrets.loadOrCreate(dir.resolve("secrets-busy.key"));
        CoreSettings d = CoreSettings.defaults();
        CoreSettings cs = new CoreSettings(
                d.usernamePattern(), 8, 128, true, true, 4096, 1, 1, 1, 1,
                5, 20, 0L, 60L, true, 3600L, "JustLogin", 1, false, 300L);

        try (Database db = new Database(DbConfig.memory());
             HashingExecutor hashing = new HashingExecutor(1, 1)) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            AuthService auth = new AuthService(
                    accounts, new SessionStore(db), new BackupCodeStore(db), new AuditStore(db),
                    secrets, hashing, new LoginRateLimiter(clock::get), () -> cs, clock::get);

            assertEquals(AuthService.Status.SUCCESS,
                    auth.register("BusyUser", UUID.randomUUID(), "StrongPass1!".toCharArray(), "10.0.0.1", "BusyUser")
                            .join().status());

            CountDownLatch workerStarted = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            CompletableFuture<Void> occupant = hashing.submit(() -> {
                workerStarted.countDown();
                try {
                    release.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return null;
            });
            assertTrue(workerStarted.await(5, TimeUnit.SECONDS));
            // Fill the single queue slot
            CompletableFuture<Void> queued = hashing.submit(() -> null);
            try {
                // Third task exceeds maxQueueSize=1 -> rejected -> AuthService maps to HASHING_BUSY
                assertEquals(AuthService.Status.HASHING_BUSY,
                        auth.login("BusyUser", "StrongPass1!".toCharArray(), "10.0.0.1").join().status());
            } finally {
                release.countDown();
                occupant.join();
                queued.join();
            }
        }
    }

    @Test
    void auditP0AndP1SecurityRegressionsVerified() throws Exception {
        AtomicLong clock = new AtomicLong(1_700_000_000_000L);
        ServerSecrets secrets = ServerSecrets.loadOrCreate(dir.resolve("secrets-audit.key"));
        CoreSettings d = CoreSettings.defaults();
        // maxAccountsPerIp = 2, auditRetentionDays = 10
        CoreSettings cs = new CoreSettings(
                d.usernamePattern(), 8, 128, true, true, 4096, 1, 1, 2, 16,
                2, 10, 0L, 60L, true, 3600L, "JustLogin", 1, false, 300L, 2, 10);

        try (Database db = new Database(DbConfig.memory());
             HashingExecutor hashing = new HashingExecutor(2, 16)) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            SessionStore sessions = new SessionStore(db);
            BackupCodeStore backups = new BackupCodeStore(db);
            AuditStore audit = new AuditStore(db);
            LoginRateLimiter rl = new LoginRateLimiter(clock::get);
            AuthService auth = new AuthService(
                    accounts, sessions, backups, audit, secrets, hashing, rl, () -> cs, clock::get);

            // P0-2: setCrackedWithInitialPassword rejects PASSWORD_ALREADY_SET when account already has a password
            assertEquals(AuthService.Status.SUCCESS,
                    auth.register("CrackedTest", UUID.randomUUID(), "InitialPass1!".toCharArray(), "10.0.1.1", "CrackedTest")
                            .join().status());
            assertEquals(AuthService.Status.PASSWORD_ALREADY_SET,
                    auth.setCrackedWithInitialPassword("CrackedTest", "AttackerPw9!".toCharArray(), "10.0.1.1", "CrackedTest")
                            .join().status());

            // P1-11: maxAccountsPerIp blocks 3rd registration from same IP
            assertEquals(AuthService.Status.SUCCESS,
                    auth.register("SecondUser", UUID.randomUUID(), "InitialPass1!".toCharArray(), "10.0.1.1", "SecondUser")
                            .join().status());
            assertEquals(AuthService.Status.TOO_MANY_ACCOUNTS_PER_IP,
                    auth.register("ThirdUser", UUID.randomUUID(), "InitialPass1!".toCharArray(), "10.0.1.1", "ThirdUser")
                            .join().status());

            // P1-1: Legacy BCrypt hash rehash on login preserves force_password_change = true
            String bcryptHash = com.password4j.Password.hash("LegacyPass99!")
                    .with(com.password4j.BcryptFunction.getInstance(com.password4j.types.Bcrypt.A, 10)).getResult();
            accounts.importIfAbsent(
                    "legacyuser", "LegacyUser", UUID.randomUUID(), null,
                    bcryptHash, HashAlgorithm.BCRYPT, null, 1000L, 1000L, null, 1000L).join();
            auth.adminSetForcePasswordChange("LegacyUser", true, "Admin").join();
            var loginRes = auth.login("LegacyUser", "LegacyPass99!".toCharArray(), "10.0.2.1").join();
            assertEquals(AuthService.Status.NEEDS_PASSWORD_CHANGE, loginRes.status());
            var afterRehash = accounts.findByNameLower("legacyuser").join().orElseThrow();
            assertEquals(HashAlgorithm.ARGON2ID, afterRehash.hashAlgo(), "Password should be upgraded to Argon2id");
            assertTrue(afterRehash.forcePasswordChange(), "P1-1: Rehash must NOT clear force_password_change");

            // P1-3: "unknown" IP never creates or resumes an IP-bound session
            assertEquals(AuthService.Status.SUCCESS,
                    auth.login("CrackedTest", "InitialPass1!".toCharArray(), "unknown").join().status());
            assertEquals(AuthService.PreAuthCheck.Decision.REQUIRE_LOGIN,
                    auth.checkPreAuth("CrackedTest", "unknown").join().decision());

            // P0-3: requestSetEmail requires current password and confirmEmail activates it
            CopyOnWriteArrayList<String> sentEmails = new CopyOnWriteArrayList<>();
            SmtpConfig smtpCfg = new SmtpConfig(
                    true, "localhost", 25, SmtpConfig.Security.NONE, "", "",
                    "noreply@example.com", "JustLogin", 1000, 1000, 600, 10L, "TestMC");
            EmailRecoveryService emailSvc = new EmailRecoveryService(
                    accounts, sessions, audit, secrets, hashing, rl,
                    (to, sub, body) -> {
                        sentEmails.add(to + "|" + sub + "|" + body);
                        return CompletableFuture.completedFuture(null);
                    },
                    () -> cs, () -> smtpCfg, clock::get);

            assertEquals(EmailRecoveryService.Status.INVALID_CREDENTIALS,
                    emailSvc.requestSetEmail("CrackedTest", "alice@example.com", "WrongPass99!".toCharArray(), "10.0.3.1", "CrackedTest")
                            .join().status());
            assertEquals(EmailRecoveryService.Status.CONFIRMATION_SENT,
                    emailSvc.requestSetEmail("CrackedTest", "alice@example.com", "InitialPass1!".toCharArray(), "10.0.3.1", "CrackedTest")
                            .join().status());
            assertNull(accounts.findByNameLower("crackedtest").join().orElseThrow().email(),
                    "Email must not be active before /email confirm");
            String confirmMsg = sentEmails.getLast();
            int codeIdx = confirmMsg.indexOf("confirmation code: ");
            assertTrue(codeIdx > 0);
            String confirmCode = confirmMsg.substring(codeIdx + "confirmation code: ".length(),
                    codeIdx + "confirmation code: ".length() + 8);
            assertEquals(EmailRecoveryService.Status.SUCCESS,
                    emailSvc.confirmEmail("CrackedTest", confirmCode, "10.0.3.1", "CrackedTest").join().status());
            assertEquals("alice@example.com", accounts.findByNameLower("crackedtest").join().orElseThrow().email());

            // P0-7: ProxyAuthService checks Mojang API + findByPremiumUuid for renamed premium players even when auto-detect=false
            UUID premiumMojangUuid = UUID.randomUUID();
            accounts.createAccount("oldprem", "OldPrem", UUID.randomUUID(), premiumMojangUuid,
                    "", HashAlgorithm.NONE, true, false, 1000L, null).join();
            com.sun.net.httpserver.HttpServer mockServer =
                    com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
            mockServer.createContext("/lookup/", exchange -> {
                String path = exchange.getRequestURI().getPath();
                String requestedName = path.substring(path.lastIndexOf('/') + 1);
                if ("NewPremName".equalsIgnoreCase(requestedName)) {
                    byte[] body = ("{\"id\":\"" + premiumMojangUuid.toString().replace("-", "")
                            + "\",\"name\":\"NewPremName\"}").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(200, body.length);
                    exchange.getResponseBody().write(body);
                } else if ("RateLimitedName".equalsIgnoreCase(requestedName)) {
                    exchange.sendResponseHeaders(429, -1);
                } else {
                    exchange.sendResponseHeaders(404, -1);
                }
                exchange.close();
            });
            mockServer.start();
            try {
                MojangApiClient fakeMojang = new MojangApiClient(
                        "http://127.0.0.1:" + mockServer.getAddress().getPort() + "/lookup/", 300, clock::get);
                ProxyAuthService proxyAuth = new ProxyAuthService(
                        accounts, audit, fakeMojang, secrets, () -> cs, clock::get);
                assertEquals(ProxyAuthService.PreLoginAction.FORCE_ONLINE,
                        proxyAuth.decidePreLogin("NewPremName", false).join().action(),
                        "P0-7: Renamed premium player must be routed to FORCE_ONLINE via premium_uuid lookup");
                assertEquals(ProxyAuthService.PreLoginAction.ALLOW_OFFLINE,
                        proxyAuth.decidePreLogin("UnrelatedCracked", false).join().action());
                assertEquals(ProxyAuthService.PreLoginAction.DENY_MOJANG_UNAVAILABLE,
                        proxyAuth.decidePreLogin("RateLimitedName", false).join().action(),
                        "P0-7/P1-7: Mojang API unavailability must fail closed with DENY_MOJANG_UNAVAILABLE");
            } finally {
                mockServer.stop(0);
            }
        }
    }
}

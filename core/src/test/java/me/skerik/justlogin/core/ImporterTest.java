package me.skerik.justlogin.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.password4j.BcryptFunction;
import com.password4j.Password;
import com.password4j.types.Bcrypt;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import me.skerik.justlogin.core.crypto.AesGcmCrypto;
import me.skerik.justlogin.core.crypto.PasswordHasher;
import me.skerik.justlogin.core.crypto.ServerSecrets;
import me.skerik.justlogin.core.importer.AuthMeImporter;
import me.skerik.justlogin.core.importer.FastLoginImporter;
import me.skerik.justlogin.core.importer.LibreLoginImporter;
import me.skerik.justlogin.core.importer.LoginSecurityImporter;
import me.skerik.justlogin.core.importer.MigrationScanner;
import me.skerik.justlogin.core.importer.NLoginImporter;
import me.skerik.justlogin.core.model.Account;
import me.skerik.justlogin.core.model.HashAlgorithm;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import me.skerik.justlogin.core.storage.Database;
import me.skerik.justlogin.core.storage.DbConfig;
import me.skerik.justlogin.core.storage.Migrations;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests for legacy database importers (AuthMe, FastLogin P0-6 UUID preservation, LibreLogin,
 * LoginSecurity, nLogin) and automatic 1-click migration scanning ({@link MigrationScanner}).
 */
final class ImporterTest {

    private static final String SAMPLE_SHA256_HASH =
            "$SHA$abcd1234$10f9d4a653780385e641f3f21c33eb2015be9be8b5406b3556d3d00e26b48996";

    @TempDir Path dir;

    @Test
    void p0_6_authMeThenFastLoginPreservesMojangGameUuidForPremiumAndOfflineUuidForCracked() throws Exception {
        Path authMeDb = dir.resolve("authme.db");
        Path fastLoginDb = dir.resolve("FastLogin.db");
        UUID premiumMojangUuid = UUID.fromString("069a79f4-44e9-4726-a5be-fca90e38aaf5");
        String undashedMojangUuid = premiumMojangUuid.toString().replace("-", "");

        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + authMeDb);
             Statement st = c.createStatement()) {
            st.execute("""
                    CREATE TABLE authme (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username VARCHAR(255) NOT NULL,
                      realname VARCHAR(255) NOT NULL,
                      password VARCHAR(255) NOT NULL,
                      ip VARCHAR(40),
                      lastlogin BIGINT,
                      regdate BIGINT,
                      email VARCHAR(255),
                      totp VARCHAR(64)
                    )""");
            st.execute("INSERT INTO authme (username, realname, password, ip, lastlogin, regdate, email, totp) "
                    + "VALUES ('notch', 'Notch', '" + SAMPLE_SHA256_HASH + "', '10.0.0.1', 2000, 1000, "
                    + "'notch@mojang.com', 'JBSWY3DPEHPK3PXP')");
            st.execute("INSERT INTO authme (username, realname, password, ip, lastlogin, regdate, email, totp) "
                    + "VALUES ('crackedbob', 'CrackedBob', '" + SAMPLE_SHA256_HASH + "', '10.0.0.2', 2000, 1000, "
                    + "'your@email.com', NULL)");
            st.execute("INSERT INTO authme (username, realname, password, ip, lastlogin, regdate, email, totp) "
                    + "VALUES ('bad name!', 'bad name!', '" + SAMPLE_SHA256_HASH + "', '10.0.0.3', 2000, 1000, NULL, NULL)");
        }

        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + fastLoginDb);
             Statement st = c.createStatement()) {
            st.execute("""
                    CREATE TABLE premium (
                      UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                      UUID CHAR(36),
                      Name VARCHAR(16) NOT NULL,
                      Premium BOOLEAN NOT NULL,
                      LastIp VARCHAR(255),
                      LastLogin TIMESTAMP,
                      Floodgate INTEGER
                    )""");
            st.execute("INSERT INTO premium (UUID, Name, Premium, LastIp, Floodgate) "
                    + "VALUES ('" + undashedMojangUuid + "', 'Notch', 1, '10.0.0.1', 0)");
            st.execute("INSERT INTO premium (UUID, Name, Premium, LastIp, Floodgate) "
                    + "VALUES (NULL, 'CrackedBob', 0, '10.0.0.2', 0)");
        }

        ServerSecrets secrets = ServerSecrets.generateEphemeral();
        long now = 1_700_000_000_000L;

        try (Database db = new Database(DbConfig.memory())) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            AuditStore audit = new AuditStore(db);

            AuthMeImporter.ImportReport authMeRep = AuthMeImporter.importFromSqlite(
                    authMeDb.toString(), "authme", accounts, audit, secrets, "Console", now).join();
            assertEquals(2, authMeRep.imported());
            assertEquals(0, authMeRep.skippedExisting());
            assertEquals(1, authMeRep.skippedInvalid());
            assertEquals(1, authMeRep.skippedDetails().size());
            assertEquals("invalid_username", authMeRep.skippedDetails().getFirst().reason());

            // Before FastLogin runs, Notch has synthetic offline UUID and imported email + encrypted TOTP
            Account notchBefore = accounts.findByNameLower("notch").join().orElseThrow();
            assertEquals(AuthMeImporter.offlineUuid("Notch"), notchBefore.gameUuid());
            assertNull(notchBefore.premiumUuid());
            assertEquals("notch@mojang.com", notchBefore.email());
            assertNotNull(notchBefore.totpSecretEncrypted());
            assertEquals("JBSWY3DPEHPK3PXP",
                    AesGcmCrypto.decrypt(secrets.totpKey(), notchBefore.totpSecretEncrypted()));

            // CrackedBob's placeholder email 'your@email.com' must be ignored
            Account bobBefore = accounts.findByNameLower("crackedbob").join().orElseThrow();
            assertNull(bobBefore.email());
            assertNull(bobBefore.totpSecretEncrypted());

            // Run FastLoginImporter: P0-6 must upgrade Notch's game_uuid from offline UUID to Mojang UUID
            FastLoginImporter.ImportReport flRep = FastLoginImporter.importFromSqlite(
                    fastLoginDb.toString(), "premium", accounts, audit, "Console", now + 1000L).join();
            assertEquals(0, flRep.importedNew());
            assertEquals(2, flRep.updatedExisting());
            assertEquals(0, flRep.skipped());

            Account notchAfter = accounts.findByNameLower("notch").join().orElseThrow();
            assertEquals(premiumMojangUuid, notchAfter.gameUuid(),
                    "P0-6: Premium player migrated from AuthMe+FastLogin must have Mojang UUID as game_uuid");
            assertEquals(premiumMojangUuid, notchAfter.premiumUuid());
            assertTrue(notchAfter.isPremiumConfirmed());

            Account bobAfter = accounts.findByNameLower("crackedbob").join().orElseThrow();
            assertEquals(AuthMeImporter.offlineUuid("CrackedBob"), bobAfter.gameUuid(),
                    "Cracked player must retain offline game_uuid");
            assertNull(bobAfter.premiumUuid());
            assertEquals(Boolean.FALSE, bobAfter.premium());
        }
    }

    @Test
    void libreLoginLoginSecurityAndNLoginSqliteImportsWork() throws Exception {
        Path libreDb = dir.resolve("librelogin.db");
        Path lsDb = dir.resolve("LoginSecurity.db");
        Path nloginDb = dir.resolve("nlogin.db");

        UUID libreCrackedUuid = UUID.randomUUID();
        UUID librePremUuid = UUID.randomUUID();
        UUID lsUuid = UUID.randomUUID();
        UUID nloginUuid = UUID.randomUUID();

        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + libreDb);
             Statement st = c.createStatement()) {
            st.execute("""
                    CREATE TABLE librelogin_data (
                      uuid VARCHAR(36) PRIMARY KEY,
                      premium_uuid VARCHAR(36),
                      hashed_password VARCHAR(255),
                      salt VARCHAR(255),
                      algo VARCHAR(64),
                      last_nickname VARCHAR(32) NOT NULL,
                      joined BIGINT,
                      last_seen BIGINT,
                      secret VARCHAR(255),
                      ip VARCHAR(64)
                    )""");
            // SHA-256 with separate salt column + TOTP secret
            st.execute("INSERT INTO librelogin_data (uuid, premium_uuid, hashed_password, salt, algo, "
                    + "last_nickname, joined, last_seen, secret, ip) VALUES ('"
                    + libreCrackedUuid + "', NULL, '10f9d4a653780385e641f3f21c33eb2015be9be8b5406b3556d3d00e26b48996', "
                    + "'abcd1234', 'SHA-256', 'LibreUser', 1000, 2000, 'JBSWY3DPEHPK3PXP', '10.1.1.1')");
            // Passwordless premium account in LibreLogin
            st.execute("INSERT INTO librelogin_data (uuid, premium_uuid, hashed_password, salt, algo, "
                    + "last_nickname, joined, last_seen, secret, ip) VALUES ('"
                    + librePremUuid + "', '" + librePremUuid + "', NULL, NULL, NULL, "
                    + "'LibrePrem', 1000, 2000, NULL, '10.1.1.2')");
        }

        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + lsDb);
             Statement st = c.createStatement()) {
            st.execute("""
                    CREATE TABLE ls_players (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      unique_user_id VARCHAR(128),
                      last_name VARCHAR(16),
                      password VARCHAR(512),
                      hashing_algorithm INTEGER,
                      ip_address VARCHAR(64),
                      last_login BIGINT,
                      registration_date BIGINT
                    )""");
            st.execute("INSERT INTO ls_players (unique_user_id, last_name, password, hashing_algorithm, "
                    + "ip_address, last_login, registration_date) VALUES ('"
                    + lsUuid + "', 'LsPlayer', '" + SAMPLE_SHA256_HASH + "', 7, '10.2.2.2', 4000, 3000)");
        }

        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + nloginDb);
             Statement st = c.createStatement()) {
            st.execute("""
                    CREATE TABLE ai_accounts (
                      ai_id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name VARCHAR(16),
                      last_name VARCHAR(16),
                      unique_id VARCHAR(36),
                      mojang_id VARCHAR(36),
                      password VARCHAR(512),
                      ip VARCHAR(64)
                    )""");
            st.execute("INSERT INTO ai_accounts (name, last_name, unique_id, mojang_id, password, ip) VALUES ("
                    + "'nloginplayer', 'NLoginPlayer', '" + nloginUuid + "', NULL, '" + SAMPLE_SHA256_HASH + "', '10.3.3.3')");
        }

        ServerSecrets secrets = ServerSecrets.generateEphemeral();
        long now = 1_700_000_000_000L;

        try (Database db = new Database(DbConfig.memory())) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            AuditStore audit = new AuditStore(db);

            LibreLoginImporter.ImportReport libreRep = LibreLoginImporter.importFromSqlite(
                    libreDb.toString(), "librelogin_data", accounts, audit, secrets, "Console", now).join();
            assertEquals(2, libreRep.imported());
            assertEquals(0, libreRep.skippedInvalid());

            Account libreUser = accounts.findByNameLower("libreuser").join().orElseThrow();
            assertEquals(libreCrackedUuid, libreUser.gameUuid());
            assertEquals(HashAlgorithm.AUTHME_SHA256, libreUser.hashAlgo());
            assertEquals(SAMPLE_SHA256_HASH, libreUser.passwordHash());
            assertEquals("JBSWY3DPEHPK3PXP",
                    AesGcmCrypto.decrypt(secrets.totpKey(), libreUser.totpSecretEncrypted()));
            PasswordHasher hasher = new PasswordHasher(4096, 1, 1);
            assertNotNull(hasher);

            Account librePrem = accounts.findByNameLower("libreprem").join().orElseThrow();
            assertEquals(librePremUuid, librePrem.gameUuid());
            assertEquals(librePremUuid, librePrem.premiumUuid());
            assertTrue(librePrem.isPremiumConfirmed());
            assertFalse(librePrem.hasPassword());

            LoginSecurityImporter.ImportReport lsRep = LoginSecurityImporter.importFromSqlite(
                    lsDb.toString(), "ls_players", accounts, audit, secrets, "Console", now).join();
            assertEquals(1, lsRep.imported());
            Account lsAcc = accounts.findByNameLower("lsplayer").join().orElseThrow();
            assertEquals(lsUuid, lsAcc.gameUuid());
            assertEquals(HashAlgorithm.AUTHME_SHA256, lsAcc.hashAlgo());

            // NLoginImporter automatically falls back from 'nlogin' to 'ai_accounts' when 'ai_accounts' is present
            NLoginImporter.ImportReport nlRep = NLoginImporter.importFromSqlite(
                    nloginDb.toString(), "nlogin", accounts, audit, secrets, "Console", now).join();
            assertEquals(1, nlRep.imported());
            Account nlAcc = accounts.findByNameLower("nloginplayer").join().orElseThrow();
            assertEquals(nloginUuid, nlAcc.gameUuid());
        }
    }

    @Test
    void migrationScannerDetectsAndOrdersPluginsAndSupportsDryRunAndReportFile() throws Exception {
        Path pluginsDir = dir.resolve("plugins");
        Path authMeDir = Files.createDirectories(pluginsDir.resolve("AuthMe"));
        Path fastLoginDir = Files.createDirectories(pluginsDir.resolve("FastLogin"));
        Path reportDir = dir.resolve("reports");

        Files.writeString(authMeDir.resolve("config.yml"), """
                DataSource:
                  backend: 'SQLITE'
                  mySQLTablename: 'authme'
                  mySQLDatabase: 'authme'
                """, StandardCharsets.UTF_8);

        Files.writeString(fastLoginDir.resolve("config.yml"), """
                driver: 'org.sqlite.JDBC'
                database: '{pluginDir}/FastLogin.db'
                """, StandardCharsets.UTF_8);

        Path authMeDb = authMeDir.resolve("authme.db");
        Path fastLoginDb = fastLoginDir.resolve("FastLogin.db");
        UUID alexMojangUuid = UUID.fromString("ec561538-f3fd-461d-aff5-086b22154bce");

        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + authMeDb);
             Statement st = c.createStatement()) {
            st.execute("""
                    CREATE TABLE authme (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username VARCHAR(255) NOT NULL,
                      realname VARCHAR(255) NOT NULL,
                      password VARCHAR(255) NOT NULL
                    )""");
            st.execute("INSERT INTO authme (username, realname, password) VALUES ('alex', 'Alex', '" + SAMPLE_SHA256_HASH + "')");
            st.execute("INSERT INTO authme (username, realname, password) VALUES ('invalid user', 'invalid user', '" + SAMPLE_SHA256_HASH + "')");
        }

        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + fastLoginDb);
             Statement st = c.createStatement()) {
            st.execute("""
                    CREATE TABLE premium (
                      UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                      UUID CHAR(36),
                      Name VARCHAR(16) NOT NULL,
                      Premium BOOLEAN NOT NULL
                    )""");
            st.execute("INSERT INTO premium (UUID, Name, Premium) VALUES ('" + alexMojangUuid + "', 'Alex', 1)");
        }

        List<MigrationScanner.DetectedSource> detected = MigrationScanner.scan(pluginsDir);
        assertEquals(2, detected.size());
        assertEquals(MigrationScanner.SourceType.AUTHME, detected.get(0).type(),
                "Password importer (AUTHME) must be ordered before FASTLOGIN");
        assertEquals(MigrationScanner.SourceType.FASTLOGIN, detected.get(1).type());

        ServerSecrets secrets = ServerSecrets.generateEphemeral();
        long now = 1_700_000_000_000L;

        try (Database db = new Database(DbConfig.memory())) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            AuditStore audit = new AuditStore(db);

            // 1. Dry-run must not insert accounts into the database, but must produce summary & report file
            MigrationScanner.AutoMigrationSummary drySummary = MigrationScanner.importAll(
                    detected, accounts, audit, secrets, "Console", true, reportDir, now).join();
            assertTrue(drySummary.dryRun());
            assertEquals(2, drySummary.totalImported()); // 1 in AuthMe + 1 in FastLogin (since AuthMe didn't write in dry-run)
            assertEquals(1, drySummary.totalSkippedInvalid());
            assertEquals(0L, accounts.countAccounts().join(), "Dry-run must not write to AccountStore");
            assertNotNull(drySummary.reportFile());
            assertTrue(Files.isRegularFile(drySummary.reportFile()));
            String reportContent = Files.readString(drySummary.reportFile(), StandardCharsets.UTF_8);
            assertTrue(reportContent.contains("invalid_username"));

            // 2. Real import writes to AccountStore and pairs FastLogin Mojang UUID onto Alex's account
            MigrationScanner.AutoMigrationSummary realSummary = MigrationScanner.importAll(
                    detected, accounts, audit, secrets, "Console", false, reportDir, now + 5000L).join();
            assertFalse(realSummary.dryRun());
            assertEquals(1, realSummary.totalImported());
            assertEquals(1, realSummary.totalUpdated());
            assertEquals(1, realSummary.totalSkippedInvalid());

            Account alex = accounts.findByNameLower("alex").join().orElseThrow();
            assertEquals(alexMojangUuid, alex.gameUuid());
            assertEquals(alexMojangUuid, alex.premiumUuid());
            assertTrue(alex.isPremiumConfirmed());
        }
    }

    @Test
    void libreLoginRealWorldSplitHashesAndTableAutoDetect(@TempDir Path tmp) throws Exception {
        Path pluginDir = tmp.resolve("LibreLogin");
        Files.createDirectories(pluginDir);
        Files.writeString(pluginDir.resolve("config.conf"), """
                database {
                  type = "SQLITE"
                  sqlite {
                    path = "user-data.db"
                  }
                }
                """, StandardCharsets.UTF_8);

        PasswordHasher hasher = new PasswordHasher(4096, 1, 1);

        // 1. LibreLogin Argon-2ID split format: hashed_password = "v,t,m$<b64hash>", salt = "<b64salt>"
        String argonFull = hasher.hash("ArgonPass1!".toCharArray()).hash(); // $argon2id$v=19$m=...,t=...,p=1$<salt>$<hash>
        String[] argonParts = argonFull.split("\\$");
        // argonParts = ["", "argon2id", "v=19", "m=19456,t=2,p=1", "<salt>", "<hash>"]
        String versionNum = argonParts[2].substring("v=".length());
        String memNum = argonParts[3].split(",")[0].substring("m=".length());
        String iterNum = argonParts[3].split(",")[1].substring("t=".length());
        String libreArgonHash = versionNum + "," + iterNum + "," + memNum + "$" + argonParts[5];
        String libreArgonSalt = argonParts[4];

        // 2. LibreLogin BCrypt-2A split format: hashed_password = "<cost>$<31chars>", salt = "<22chars>"
        String bcryptFull = Password.hash("BcryptPass2!").with(BcryptFunction.getInstance(Bcrypt.A, 10)).getResult();
        // $2a$10$<22charSalt><31charHash>
        String libreBcryptHash = "10$" + bcryptFull.substring(29);
        String libreBcryptSalt = bcryptFull.substring(7, 29);

        // 3. LibreLogin MessageDigestCryptoProvider salted SHA-256 (double-hash hex(sha(hex(sha(pw))+salt)))
        String shaSalt = "LibreSalt42";
        String sha256Hash = shaHex("SHA-256", shaHex("SHA-256", "Sha256Pass3!") + shaSalt);

        // 4. LibreLogin unsalted SHA-512
        String sha512Unsalted = shaHex("SHA-512", "Sha512Pass4!");

        Path dbFile = pluginDir.resolve("user-data.db");
        String uuid1 = UUID.randomUUID().toString();
        String uuid2 = UUID.randomUUID().toString();
        String uuid3 = UUID.randomUUID().toString();
        String uuid4 = UUID.randomUUID().toString();
        String prem1 = UUID.randomUUID().toString();

        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + dbFile);
             Statement st = conn.createStatement()) {
            st.execute("""
                    CREATE TABLE librepremium_data (
                      uuid VARCHAR(36) PRIMARY KEY,
                      premium_uuid VARCHAR(36),
                      hashed_password VARCHAR(512),
                      salt VARCHAR(128),
                      algo VARCHAR(32),
                      last_nickname VARCHAR(32),
                      joined VARCHAR(64),
                      last_seen VARCHAR(64),
                      secret VARCHAR(64),
                      ip VARCHAR(64),
                      last_authentication VARCHAR(64),
                      email VARCHAR(128)
                    )
                    """);
            st.execute("INSERT INTO librepremium_data VALUES ('" + uuid1 + "', '" + prem1 + "', '" + libreArgonHash + "', '"
                    + libreArgonSalt + "', 'Argon-2ID', 'ArgonPlayer', '2026-01-01T10:00:00', '2026-01-02T12:00:00', NULL, '127.0.0.1', NULL, 'a@example.com')");
            st.execute("INSERT INTO librepremium_data VALUES ('" + uuid2 + "', NULL, '" + libreBcryptHash + "', '"
                    + libreBcryptSalt + "', 'BCrypt-2A', 'BcryptPlayer', '1700000000000', '1700000010000', NULL, '10.0.0.2', NULL, NULL)");
            st.execute("INSERT INTO librepremium_data VALUES ('" + uuid3 + "', NULL, '" + sha256Hash + "', '"
                    + shaSalt + "', 'SHA-256', 'Sha256Player', NULL, NULL, NULL, NULL, NULL, NULL)");
            st.execute("INSERT INTO librepremium_data VALUES ('" + uuid4 + "', NULL, '" + sha512Unsalted + "', "
                    + "NULL, 'SHA-512', 'Sha512Player', NULL, NULL, NULL, NULL, NULL, NULL)");
        }

        List<MigrationScanner.DetectedSource> detected = MigrationScanner.scan(tmp);
        assertEquals(1, detected.size());
        assertEquals(MigrationScanner.SourceType.LIBRELOGIN, detected.get(0).type());
        assertEquals("librepremium_data", detected.get(0).tableName());

        ServerSecrets secrets = ServerSecrets.generateEphemeral();
        try (Database db = new Database(DbConfig.memory())) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            AuditStore audit = new AuditStore(db);

            MigrationScanner.AutoMigrationSummary summary = MigrationScanner.importAll(
                    detected, accounts, audit, secrets, "Console", false, tmp, 1_700_000_000_000L).join();
            assertEquals(4, summary.totalImported());

            Account a1 = accounts.findByNameLower("argonplayer").join().orElseThrow();
            assertEquals(UUID.fromString(uuid1), a1.gameUuid());
            assertEquals(UUID.fromString(prem1), a1.premiumUuid());
            assertTrue(a1.isPremiumConfirmed());
            assertEquals("a@example.com", a1.email());
            assertTrue(hasher.verify("ArgonPass1!".toCharArray(), a1.passwordHash(), a1.hashAlgo()).valid());

            Account a2 = accounts.findByNameLower("bcryptplayer").join().orElseThrow();
            assertEquals(HashAlgorithm.BCRYPT, a2.hashAlgo());
            assertTrue(hasher.verify("BcryptPass2!".toCharArray(), a2.passwordHash(), a2.hashAlgo()).valid());

            Account a3 = accounts.findByNameLower("sha256player").join().orElseThrow();
            assertEquals(HashAlgorithm.AUTHME_SHA256, a3.hashAlgo());
            assertTrue(hasher.verify("Sha256Pass3!".toCharArray(), a3.passwordHash(), a3.hashAlgo()).valid());

            Account a4 = accounts.findByNameLower("sha512player").join().orElseThrow();
            assertEquals(HashAlgorithm.SHA512, a4.hashAlgo());
            assertTrue(hasher.verify("Sha512Pass4!".toCharArray(), a4.passwordHash(), a4.hashAlgo()).valid());
        }
    }

    @Test
    void loginSecurityDatabaseYmlDetectionAndImports(@TempDir Path tmp) throws Exception {
        Path pluginDir = tmp.resolve("LoginSecurity");
        Files.createDirectories(pluginDir);
        Files.writeString(pluginDir.resolve("database.yml"), """
                mysql:
                  enabled: true
                  host: 'db.internal:3307'
                  database: ls_prod
                  username: ls_user
                  password: 'ls_secret'
                """, StandardCharsets.UTF_8);

        List<MigrationScanner.DetectedSource> detectedMysql = MigrationScanner.scan(tmp);
        assertEquals(1, detectedMysql.size());
        MigrationScanner.DetectedSource mysqlSrc = detectedMysql.get(0);
        assertEquals(MigrationScanner.SourceType.LOGINSECURITY, mysqlSrc.type());
        assertEquals(MigrationScanner.Backend.MYSQL, mysqlSrc.backend());
        assertEquals("jdbc:mariadb://db.internal:3307/ls_prod", mysqlSrc.jdbcUrl());
        assertEquals("ls_user", mysqlSrc.user());
        assertEquals("ls_secret", mysqlSrc.password());

        // Switch to SQLite and verify real ls_players rows + hashing_algorithm hints
        Files.writeString(pluginDir.resolve("database.yml"), """
                mysql:
                  enabled: false
                """, StandardCharsets.UTF_8);
        Path lsDb = pluginDir.resolve("LoginSecurity.db");
        String bcryptHash = Password.hash("LsBcrypt!").with(BcryptFunction.getInstance(Bcrypt.A, 10)).getResult();
        String authMeSha = "$SHA$salt99$" + shaHex("SHA-256", shaHex("SHA-256", "LsSha256!") + "salt99");

        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + lsDb);
             Statement st = conn.createStatement()) {
            st.execute("""
                    CREATE TABLE ls_players (
                      unique_user_id VARCHAR(36),
                      last_name VARCHAR(32),
                      password VARCHAR(255),
                      hashing_algorithm INTEGER,
                      ip_address VARCHAR(64),
                      last_login VARCHAR(64),
                      registration_date VARCHAR(64)
                    )
                    """);
            st.execute("INSERT INTO ls_players VALUES ('" + UUID.randomUUID() + "', 'LsUserOne', '"
                    + bcryptHash + "', 7, '127.0.0.1', '2026-02-01 10:00:00', '2026-01-01 10:00:00')");
            st.execute("INSERT INTO ls_players VALUES ('" + UUID.randomUUID() + "', 'LsUserTwo', '"
                    + authMeSha + "', 30, '10.0.0.5', NULL, NULL)");
        }

        List<MigrationScanner.DetectedSource> detectedSqlite = MigrationScanner.scan(tmp);
        assertEquals(1, detectedSqlite.size());
        assertEquals(MigrationScanner.Backend.SQLITE, detectedSqlite.get(0).backend());

        ServerSecrets secrets = ServerSecrets.generateEphemeral();
        PasswordHasher hasher = new PasswordHasher(4096, 1, 1);
        try (Database db = new Database(DbConfig.memory())) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            AuditStore audit = new AuditStore(db);

            MigrationScanner.AutoMigrationSummary summary = MigrationScanner.importAll(
                    detectedSqlite, accounts, audit, secrets, "Console", false, tmp, 1_700_000_000_000L).join();
            assertEquals(2, summary.totalImported());

            Account u1 = accounts.findByNameLower("lsuserone").join().orElseThrow();
            assertTrue(hasher.verify("LsBcrypt!".toCharArray(), u1.passwordHash(), u1.hashAlgo()).valid());

            Account u2 = accounts.findByNameLower("lsusertwo").join().orElseThrow();
            assertTrue(hasher.verify("LsSha256!".toCharArray(), u2.passwordHash(), u2.hashAlgo()).valid());
        }
    }

    @Test
    void nLoginReversedSha512AndMojangIdPlusOpenLoginScan(@TempDir Path tmp) throws Exception {
        // 1. nLogin with mojang_id (dashless) + reversed $SHA512$<hash>$<salt>
        Path nloginDir = tmp.resolve("nLogin");
        Files.createDirectories(nloginDir);
        Path nloginDb = nloginDir.resolve("nlogin.db");

        String salt = "nSalt7";
        String digest512 = shaHex("SHA-512", shaHex("SHA-512", "NLoginPass!") + salt);
        String reversedNLoginHash = "$SHA512$" + digest512 + "$" + salt;
        UUID premUuid = UUID.fromString("11112222-3333-4444-5555-666677778888");
        String dashlessPrem = premUuid.toString().replace("-", "");

        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + nloginDb);
             Statement st = conn.createStatement()) {
            st.execute("""
                    CREATE TABLE nlogin (
                      last_name VARCHAR(32),
                      password VARCHAR(255),
                      mojang_id VARCHAR(36),
                      bedrock_id VARCHAR(36),
                      email VARCHAR(128),
                      last_ip VARCHAR(64),
                      creation_date BIGINT
                    )
                    """);
            st.execute("INSERT INTO nlogin VALUES ('NLoginPrem', '" + reversedNLoginHash + "', '" + dashlessPrem
                    + "', NULL, 'n@example.com', '1.2.3.4', 1700000000)");
        }

        // 2. OpeNLogin accounts.db + openlogin table
        Path openLoginDir = tmp.resolve("OpeNLogin");
        Files.createDirectories(openLoginDir);
        Path openDb = openLoginDir.resolve("accounts.db");
        String openBcrypt = Password.hash("OpenPass9!").with(BcryptFunction.getInstance(Bcrypt.A, 10)).getResult();

        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + openDb);
             Statement st = conn.createStatement()) {
            st.execute("""
                    CREATE TABLE openlogin (
                      name VARCHAR(32),
                      realname VARCHAR(32),
                      password VARCHAR(255),
                      address VARCHAR(64),
                      lastlogin BIGINT,
                      regdate BIGINT
                    )
                    """);
            st.execute("INSERT INTO openlogin VALUES ('openuser', 'OpenUser', '" + openBcrypt
                    + "', '5.6.7.8', 1700000020000, 1700000000000)");
        }

        List<MigrationScanner.DetectedSource> detected = MigrationScanner.scan(tmp);
        assertEquals(2, detected.size());
        assertEquals(MigrationScanner.SourceType.NLOGIN, detected.get(0).type());
        assertEquals(MigrationScanner.SourceType.OPENLOGIN, detected.get(1).type());

        ServerSecrets secrets = ServerSecrets.generateEphemeral();
        PasswordHasher hasher = new PasswordHasher(4096, 1, 1);
        try (Database db = new Database(DbConfig.memory())) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            AuditStore audit = new AuditStore(db);

            MigrationScanner.AutoMigrationSummary summary = MigrationScanner.importAll(
                    detected, accounts, audit, secrets, "Console", false, tmp, 1_700_000_000_000L).join();
            assertEquals(2, summary.totalImported());

            Account nUser = accounts.findByNameLower("nloginprem").join().orElseThrow();
            assertEquals(premUuid, nUser.gameUuid(), "mojang_id should upgrade offline gameUuid for nLogin");
            assertEquals(premUuid, nUser.premiumUuid());
            assertTrue(nUser.isPremiumConfirmed());
            assertTrue(hasher.verify("NLoginPass!".toCharArray(), nUser.passwordHash(), nUser.hashAlgo()).valid());

            Account oUser = accounts.findByNameLower("openuser").join().orElseThrow();
            assertEquals("OpenUser", oUser.lastName());
            assertTrue(hasher.verify("OpenPass9!".toCharArray(), oUser.passwordHash(), oUser.hashAlgo()).valid());
        }
    }

    @Test
    void limboAuthAndAuthyMigrationAndVerification(@TempDir Path tmp) throws Exception {
        // 1. LimboAuth
        Path limboDir = tmp.resolve("LimboAuth");
        Files.createDirectories(limboDir);
        Files.writeString(limboDir.resolve("config.yml"), """
                database:
                  storage-type: "SQLITE"
                """, StandardCharsets.UTF_8);
        Path limboDb = limboDir.resolve("limboauth.db");
        String limboSalt = "LmbSalt";
        String limboHash = "SHA256$" + limboSalt + "$" + shaHex("SHA-256", shaHex("SHA-256", "LimboPass!") + limboSalt);
        UUID limboUuid = UUID.randomUUID();
        UUID limboPremUuid = UUID.randomUUID();

        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + limboDb);
             Statement st = conn.createStatement()) {
            st.execute("""
                    CREATE TABLE AUTH (
                      NICKNAME VARCHAR(32),
                      LOWERCASENICKNAME VARCHAR(32),
                      HASH VARCHAR(255),
                      TOTPTOKEN VARCHAR(64),
                      IP VARCHAR(64),
                      LOGINIP VARCHAR(64),
                      UUID VARCHAR(36),
                      PREMIUMUUID VARCHAR(36),
                      REGDATE BIGINT,
                      LOGINDATE BIGINT
                    )
                    """);
            st.execute("INSERT INTO AUTH VALUES ('LimboKing', 'limboking', '" + limboHash
                    + "', 'JBSWY3DPEHPK3PXP', '127.0.0.1', '127.0.0.1', '" + limboUuid + "', '" + limboPremUuid
                    + "', 1700000000000, 1700000010000)");
        }

        // 2. Authy (raw 64-hex unsalted SHA-256)
        Path authyDir = tmp.resolve("Authy");
        Files.createDirectories(authyDir);
        Files.writeString(authyDir.resolve("config.yml"), """
                database:
                  type: sqlite
                """, StandardCharsets.UTF_8);
        Path authyDb = authyDir.resolve("data.db");
        String authyRawSha256 = shaHex("SHA-256", "AuthyPass7!");
        UUID authyUuid = UUID.randomUUID();

        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + authyDb);
             Statement st = conn.createStatement()) {
            st.execute("""
                    CREATE TABLE players (
                      uuid VARCHAR(36) PRIMARY KEY,
                      username VARCHAR(32),
                      ip VARCHAR(64),
                      password VARCHAR(128)
                    )
                    """);
            st.execute("INSERT INTO players VALUES ('" + authyUuid + "', 'AuthyHero', '9.8.7.6', '" + authyRawSha256 + "')");
        }

        List<MigrationScanner.DetectedSource> detected = MigrationScanner.scan(tmp);
        assertEquals(2, detected.size());
        assertEquals(MigrationScanner.SourceType.LIMBOAUTH, detected.get(0).type());
        assertEquals(MigrationScanner.SourceType.AUTHY, detected.get(1).type());

        ServerSecrets secrets = ServerSecrets.generateEphemeral();
        PasswordHasher hasher = new PasswordHasher(4096, 1, 1);
        try (Database db = new Database(DbConfig.memory())) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            AuditStore audit = new AuditStore(db);

            MigrationScanner.AutoMigrationSummary summary = MigrationScanner.importAll(
                    detected, accounts, audit, secrets, "Console", false, tmp, 1_700_000_000_000L).join();
            assertEquals(2, summary.totalImported());

            Account lAcc = accounts.findByNameLower("limboking").join().orElseThrow();
            assertEquals(limboUuid, lAcc.gameUuid());
            assertEquals(limboPremUuid, lAcc.premiumUuid());
            assertTrue(lAcc.isPremiumConfirmed());
            assertNotNull(lAcc.totpSecretEncrypted());
            assertEquals("JBSWY3DPEHPK3PXP", AesGcmCrypto.decrypt(secrets.totpKey(), lAcc.totpSecretEncrypted()));
            assertTrue(hasher.verify("LimboPass!".toCharArray(), lAcc.passwordHash(), lAcc.hashAlgo()).valid());

            Account aAcc = accounts.findByNameLower("authyhero").join().orElseThrow();
            assertEquals(authyUuid, aAcc.gameUuid());
            assertEquals(HashAlgorithm.AUTHME_SHA256, aAcc.hashAlgo());
            assertTrue(hasher.verify("AuthyPass7!".toCharArray(), aAcc.passwordHash(), aAcc.hashAlgo()).valid());
        }
    }

    private static String shaHex(String algo, String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algo);
        return HexFormat.of().formatHex(md.digest(input.getBytes(StandardCharsets.UTF_8)));
    }
}

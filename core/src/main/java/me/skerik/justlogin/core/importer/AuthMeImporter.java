package me.skerik.justlogin.core.importer;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;
import me.skerik.justlogin.core.crypto.AesGcmCrypto;
import me.skerik.justlogin.core.crypto.IpHmac;
import me.skerik.justlogin.core.crypto.PasswordHasher;
import me.skerik.justlogin.core.crypto.ServerSecrets;
import me.skerik.justlogin.core.model.HashAlgorithm;
import me.skerik.justlogin.core.security.UsernameValidator;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import org.jspecify.annotations.Nullable;

/**
 * Clean-room importer reading AuthMe Reloaded database tables (SQLite or MariaDB/MySQL) based solely on
 * AuthMe's public schema and hash string formats (MIT-compatible).
 */
public final class AuthMeImporter {

    public static final Pattern DEFAULT_USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_]{3,16}$");

    public record SkippedEntry(String username, String reason) {
    }

    public record ImportReport(
            int imported,
            int skippedExisting,
            int skippedInvalid,
            List<SkippedEntry> skippedDetails
    ) {
        public ImportReport(int imported, int skippedExisting, int skippedInvalid) {
            this(imported, skippedExisting, skippedInvalid, List.of());
        }
    }

    private AuthMeImporter() {
    }

    public static CompletableFuture<ImportReport> importFromSqlite(
            String sqlitePath, String tableName, AccountStore accounts, AuditStore audit,
            ServerSecrets secrets, String actor, long now) {
        return importFromSqlite(sqlitePath, tableName, accounts, audit, secrets, actor, false, now);
    }

    public static CompletableFuture<ImportReport> importFromSqlite(
            String sqlitePath, String tableName, AccountStore accounts, AuditStore audit,
            ServerSecrets secrets, String actor, boolean dryRun, long now) {
        return importFromJdbc(
                "jdbc:sqlite:" + sqlitePath, null, null, tableName,
                accounts, audit, secrets, actor, dryRun, now);
    }

    public static CompletableFuture<ImportReport> importFromSqlite(
            String sqlitePath, String tableName, AccountStore accounts, AuditStore audit,
            ServerSecrets secrets, String actor, long now, boolean dryRun) {
        return importFromSqlite(sqlitePath, tableName, accounts, audit, secrets, actor, dryRun, now);
    }

    public static CompletableFuture<ImportReport> importFromJdbc(
            String jdbcUrl, @Nullable String user, @Nullable String password, String tableName,
            AccountStore accounts, AuditStore audit, ServerSecrets secrets, String actor, long now) {
        return importFromJdbc(jdbcUrl, user, password, tableName, accounts, audit, secrets, actor, false, now);
    }

    public static CompletableFuture<ImportReport> importFromJdbc(
            String jdbcUrl, @Nullable String user, @Nullable String password, String tableName,
            AccountStore accounts, AuditStore audit, ServerSecrets secrets, String actor, long now, boolean dryRun) {
        return importFromJdbc(jdbcUrl, user, password, tableName, accounts, audit, secrets, actor, dryRun, now);
    }

    public static CompletableFuture<ImportReport> importFromJdbc(
            String jdbcUrl, @Nullable String user, @Nullable String password, String tableName,
            AccountStore accounts, AuditStore audit, ServerSecrets secrets, String actor, boolean dryRun, long now) {
        String safeTable = validateIdentifier(tableName);
        return CompletableFuture.supplyAsync(() -> {
            int imported = 0;
            int skippedExisting = 0;
            int skippedInvalid = 0;
            List<SkippedEntry> skippedDetails = new ArrayList<>();

            try (Connection conn = (user == null || user.isBlank())
                    ? DriverManager.getConnection(jdbcUrl)
                    : DriverManager.getConnection(jdbcUrl, user, password);
                 Statement st = conn.createStatement();
                 ResultSet rs = st.executeQuery("SELECT * FROM " + safeTable)) {

                Set<String> cols = columnNames(rs.getMetaData());
                while (rs.next()) {
                    String username = firstNonBlank(
                            getString(rs, cols, "username"),
                            getString(rs, cols, "name"),
                            getString(rs, cols, "nick"));
                    String realname = firstNonBlank(
                            getString(rs, cols, "realname"),
                            getString(rs, cols, "real_name"));
                    String passwordHash = firstNonBlank(
                            getString(rs, cols, "password"),
                            getString(rs, cols, "pass"),
                            getString(rs, cols, "hash"));
                    String rawSalt = getString(rs, cols, "salt");
                    if ((username == null || username.isBlank()) && (realname == null || realname.isBlank())) {
                        skippedInvalid++;
                        skippedDetails.add(new SkippedEntry("<blank>", "missing_username"));
                        continue;
                    }
                    String displayName = (realname != null && !realname.isBlank())
                            ? realname.strip()
                            : username.strip();
                    String nameKeySource = (username != null && !username.isBlank())
                            ? username.strip()
                            : displayName;
                    if (!UsernameValidator.isValid(displayName, DEFAULT_USERNAME_PATTERN)
                            || !UsernameValidator.isValid(nameKeySource, DEFAULT_USERNAME_PATTERN)) {
                        skippedInvalid++;
                        skippedDetails.add(new SkippedEntry(displayName, "invalid_username"));
                        continue;
                    }
                    String nameLower = UsernameValidator.normalizeLower(nameKeySource);

                    UUID premiumUuid = FastLoginImporter.parseFlexibleUuid(firstNonBlank(
                            getString(rs, cols, "premiumuuid"),
                            getString(rs, cols, "premium_uuid")));
                    Boolean isPremium = premiumUuid != null ? Boolean.TRUE : null;

                    String normalizedHash = null;
                    HashAlgorithm algo = HashAlgorithm.NONE;
                    if (passwordHash != null && !passwordHash.isBlank()) {
                        normalizedHash = PasswordHasher.normalizeLegacyHash(passwordHash.strip(), rawSalt, null);
                        algo = PasswordHasher.detectAlgorithm(normalizedHash, HashAlgorithm.NONE);
                        if (algo == HashAlgorithm.NONE) {
                            skippedInvalid++;
                            skippedDetails.add(new SkippedEntry(displayName, "unsupported_hash"));
                            continue;
                        }
                    } else if (premiumUuid == null) {
                        skippedInvalid++;
                        skippedDetails.add(new SkippedEntry(displayName, "missing_password"));
                        continue;
                    }

                    UUID explicitUuid = FastLoginImporter.parseFlexibleUuid(firstNonBlank(
                            getString(rs, cols, "uuid"),
                            getString(rs, cols, "playeruuid")));
                    UUID gameUuid;
                    if (explicitUuid != null) {
                        boolean isSyntheticOffline = explicitUuid.equals(offlineUuid(displayName))
                                || explicitUuid.equals(offlineUuid(nameLower));
                        gameUuid = (premiumUuid != null && isSyntheticOffline) ? premiumUuid : explicitUuid;
                    } else {
                        gameUuid = premiumUuid != null ? premiumUuid : offlineUuid(displayName);
                    }

                    long regDate = LibreLoginImporter.parseTimestamp(
                            rs, cols, cols.contains("regdate") ? "regdate" : "reg_date", now);
                    long lastLogin = LibreLoginImporter.parseTimestamp(
                            rs, cols, cols.contains("lastlogin") ? "lastlogin" : "last_login", regDate);
                    String rawIp = firstNonBlank(
                            getString(rs, cols, "ip"),
                            getString(rs, cols, "lastip"),
                            getString(rs, cols, "regip"));
                    String ipHash = (rawIp == null || rawIp.isBlank())
                            ? null
                            : IpHmac.hashIp(secrets.hmacKey(), rawIp.strip());

                    String email = normalizeEmail(firstNonBlank(
                            getString(rs, cols, "email"),
                            getString(rs, cols, "mail")));
                    String rawTotp = firstNonBlank(
                            getString(rs, cols, "totp"),
                            getString(rs, cols, "totpkey"),
                            getString(rs, cols, "secret"));
                    String encryptedTotp = (rawTotp != null && !rawTotp.isBlank())
                            ? AesGcmCrypto.encrypt(secrets.totpKey(), rawTotp.strip())
                            : null;

                    if (dryRun) {
                        boolean exists = accounts.findByNameLower(nameLower).join().isPresent()
                                || accounts.findByGameUuid(gameUuid).join().isPresent()
                                || (premiumUuid != null && accounts.findByPremiumUuid(premiumUuid).join().isPresent());
                        if (exists) {
                            skippedExisting++;
                            skippedDetails.add(new SkippedEntry(displayName, "already_exists"));
                        } else {
                            imported++;
                        }
                    } else {
                        boolean inserted = accounts.importIfAbsent(
                                nameLower, displayName, gameUuid, premiumUuid, normalizedHash, algo, isPremium,
                                encryptedTotp, email, regDate, lastLogin, ipHash, now).join();
                        if (inserted) {
                            imported++;
                        } else {
                            skippedExisting++;
                            skippedDetails.add(new SkippedEntry(displayName, "already_exists"));
                        }
                    }
                }
            } catch (SQLException e) {
                throw new RuntimeException("AuthMe import failed: " + e.getMessage(), e);
            }

            if (!dryRun) {
                audit.record(now, actor, "IMPORT_AUTHME", safeTable,
                        "imported=" + imported + ",skippedExisting=" + skippedExisting + ",skippedInvalid=" + skippedInvalid)
                        .join();
            }
            return new ImportReport(imported, skippedExisting, skippedInvalid, List.copyOf(skippedDetails));
        });
    }

    public static UUID offlineUuid(String name) {
        return UUID.nameUUIDFromBytes(("OfflinePlayer:" + name).getBytes(StandardCharsets.UTF_8));
    }

    static @Nullable String normalizeEmail(@Nullable String rawEmail) {
        if (rawEmail == null || rawEmail.isBlank()) return null;
        String trimmed = rawEmail.strip();
        if (trimmed.equalsIgnoreCase("your@email.com") || trimmed.equalsIgnoreCase("null")) {
            return null;
        }
        if (!trimmed.contains("@") || trimmed.length() > 254) {
            return null;
        }
        return trimmed;
    }

    static @Nullable String firstNonBlank(@Nullable String... candidates) {
        for (String c : candidates) {
            if (c != null && !c.isBlank()) {
                return c;
            }
        }
        return null;
    }

    private static Set<String> columnNames(ResultSetMetaData meta) throws SQLException {
        Set<String> cols = new HashSet<>();
        for (int i = 1; i <= meta.getColumnCount(); i++) {
            cols.add(meta.getColumnLabel(i).toLowerCase(Locale.ROOT));
        }
        return cols;
    }

    private static @Nullable String getString(ResultSet rs, Set<String> cols, String name) throws SQLException {
        return cols.contains(name) ? rs.getString(name) : null;
    }

    private static String validateIdentifier(String table) {
        if (table == null || !table.matches("^[a-zA-Z0-9_]{1,64}$")) {
            throw new IllegalArgumentException("Invalid table name: " + table);
        }
        return table;
    }
}

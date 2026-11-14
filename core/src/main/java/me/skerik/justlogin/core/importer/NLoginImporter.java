package me.skerik.justlogin.core.importer;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
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
import me.skerik.justlogin.core.crypto.IpHmac;
import me.skerik.justlogin.core.crypto.PasswordHasher;
import me.skerik.justlogin.core.crypto.ServerSecrets;
import me.skerik.justlogin.core.model.HashAlgorithm;
import me.skerik.justlogin.core.security.UsernameValidator;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import org.jspecify.annotations.Nullable;

/**
 * Clean-room importer reading nLogin's {@code nlogin} or {@code ai_accounts} table (SQLite or MariaDB/MySQL)
 * for standard compatible password hashes (Argon2, BCrypt, SHA-256, SHA-512, PBKDF2).
 */
public final class NLoginImporter {

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

    private NLoginImporter() {
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
            String effectiveTable = safeTable;

            try (Connection conn = (user == null || user.isBlank())
                    ? DriverManager.getConnection(jdbcUrl)
                    : DriverManager.getConnection(jdbcUrl, user, password);
                 Statement st = conn.createStatement()) {

                effectiveTable = resolveEffectiveTable(conn, safeTable);
                try (ResultSet rs = st.executeQuery("SELECT * FROM " + effectiveTable)) {
                    Set<String> cols = columnNames(rs.getMetaData());
                    while (rs.next()) {
                        String chosenName = firstNonBlank(
                                getString(rs, cols, "last_name"),
                                getString(rs, cols, "real_name"),
                                getString(rs, cols, "realname"),
                                getString(rs, cols, "name"));
                        if (chosenName == null) {
                            skippedInvalid++;
                            skippedDetails.add(new SkippedEntry("<blank>", "missing_username"));
                            continue;
                        }
                        String displayName = chosenName.strip();
                        if (!UsernameValidator.isValid(displayName, AuthMeImporter.DEFAULT_USERNAME_PATTERN)) {
                            skippedInvalid++;
                            skippedDetails.add(new SkippedEntry(displayName, "invalid_username"));
                            continue;
                        }
                        String nameLower = UsernameValidator.normalizeLower(displayName);

                        UUID premiumUuid = FastLoginImporter.parseFlexibleUuid(
                                firstNonBlank(getString(rs, cols, "mojang_id"), getString(rs, cols, "premium_id")));
                        UUID uniqueUuid = FastLoginImporter.parseFlexibleUuid(
                                firstNonBlank(getString(rs, cols, "unique_id"), getString(rs, cols, "uuid")));
                        UUID gameUuid;
                        if (uniqueUuid != null) {
                            boolean isSyntheticOffline = uniqueUuid.equals(AuthMeImporter.offlineUuid(displayName))
                                    || uniqueUuid.equals(AuthMeImporter.offlineUuid(nameLower));
                            gameUuid = (premiumUuid != null && isSyntheticOffline) ? premiumUuid : uniqueUuid;
                        } else {
                            gameUuid = premiumUuid != null ? premiumUuid : AuthMeImporter.offlineUuid(displayName);
                        }
                        Boolean premium = premiumUuid != null ? Boolean.TRUE : null;

                        String rawPassword = getString(rs, cols, "password");
                        String trimmedHash = null;
                        HashAlgorithm algo = HashAlgorithm.NONE;
                        if (rawPassword != null && !rawPassword.isBlank()) {
                            trimmedHash = PasswordHasher.normalizeLegacyHash(rawPassword.strip(), null, null);
                            algo = PasswordHasher.detectAlgorithm(trimmedHash, HashAlgorithm.NONE);
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

                        String regCol = cols.contains("creation_date") ? "creation_date" : "regdate";
                        long regDate = LibreLoginImporter.parseTimestamp(rs, cols, regCol, now);
                        String seenCol = cols.contains("last_seen")
                                ? "last_seen"
                                : (cols.contains("last_login") ? "last_login" : "lastlogin");
                        long lastLogin = LibreLoginImporter.parseTimestamp(rs, cols, seenCol, regDate);
                        String rawIp = firstNonBlank(
                                getString(rs, cols, "last_ip"),
                                getString(rs, cols, "ip"),
                                getString(rs, cols, "address"));
                        String ipHash = (rawIp == null || rawIp.isBlank())
                                ? null
                                : IpHmac.hashIp(secrets.hmacKey(), rawIp.strip());

                        String email = AuthMeImporter.normalizeEmail(getString(rs, cols, "email"));

                        if (dryRun) {
                            boolean conflict = accounts.findByNameLower(nameLower).join().isPresent()
                                    || accounts.findByGameUuid(gameUuid).join().isPresent()
                                    || (premiumUuid != null && accounts.findByPremiumUuid(premiumUuid).join().isPresent());
                            if (conflict) {
                                skippedExisting++;
                                skippedDetails.add(new SkippedEntry(displayName, "already_exists"));
                            } else {
                                imported++;
                            }
                        } else {
                            boolean inserted = accounts.importIfAbsent(
                                    nameLower, displayName, gameUuid, premiumUuid, trimmedHash, algo, premium,
                                    null, email, regDate, lastLogin, ipHash, now).join();
                            if (inserted) {
                                imported++;
                            } else {
                                skippedExisting++;
                                skippedDetails.add(new SkippedEntry(displayName, "already_exists"));
                            }
                        }
                    }
                }
            } catch (SQLException e) {
                throw new RuntimeException("nLogin import failed: " + e.getMessage(), e);
            }

            if (!dryRun) {
                audit.record(now, actor, "IMPORT_NLOGIN", effectiveTable,
                        "imported=" + imported + ",skippedExisting=" + skippedExisting + ",skippedInvalid=" + skippedInvalid)
                        .join();
            }
            return new ImportReport(imported, skippedExisting, skippedInvalid, List.copyOf(skippedDetails));
        });
    }

    private static String resolveEffectiveTable(Connection conn, String requestedTable) {
        try {
            if (tableExists(conn, requestedTable)) {
                return requestedTable;
            }
            for (String candidate : List.of("nlogin", "ai_accounts", "openlogin")) {
                if (!requestedTable.equalsIgnoreCase(candidate) && tableExists(conn, candidate)) {
                    return candidate;
                }
            }
        } catch (SQLException ignored) {
            // fall through to requestedTable
        }
        return requestedTable;
    }

    private static boolean tableExists(Connection conn, String tableName) throws SQLException {
        DatabaseMetaData meta = conn.getMetaData();
        try (ResultSet rs = meta.getTables(null, null, null, new String[] { "TABLE" })) {
            while (rs.next()) {
                String t = rs.getString("TABLE_NAME");
                if (t != null && t.equalsIgnoreCase(tableName)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static @Nullable String firstNonBlank(@Nullable String... candidates) {
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

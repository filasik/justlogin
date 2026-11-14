package me.skerik.justlogin.core.importer;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
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
 * Clean-room importer reading LibreLogin's {@code librelogin_data} table (SQLite or MariaDB/MySQL).
 * Preserves {@code uuid} as {@code game_uuid}, {@code premium_uuid} when present, and encrypts imported TOTP secrets.
 */
public final class LibreLoginImporter {

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

    private LibreLoginImporter() {
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
                        String nickname = getString(rs, cols, "last_nickname");
                        if (nickname == null || nickname.isBlank()) {
                            skippedInvalid++;
                            skippedDetails.add(new SkippedEntry("<blank>", "missing_username"));
                            continue;
                        }
                        String displayName = nickname.strip();
                        if (!UsernameValidator.isValid(displayName, AuthMeImporter.DEFAULT_USERNAME_PATTERN)) {
                            skippedInvalid++;
                            skippedDetails.add(new SkippedEntry(displayName, "invalid_username"));
                            continue;
                        }
                        String nameLower = UsernameValidator.normalizeLower(displayName);

                        UUID premiumUuid = FastLoginImporter.parseFlexibleUuid(getString(rs, cols, "premium_uuid"));
                        UUID gameUuid = FastLoginImporter.parseFlexibleUuid(getString(rs, cols, "uuid"));
                        if (gameUuid == null) {
                            gameUuid = premiumUuid != null ? premiumUuid : AuthMeImporter.offlineUuid(displayName);
                        }
                        boolean isPremium = premiumUuid != null;

                        String rawAlgo = getString(rs, cols, "algo");
                        String rawHash = getString(rs, cols, "hashed_password");
                        String rawSalt = getString(rs, cols, "salt");

                        String normalizedHash = null;
                        HashAlgorithm hashAlgo = HashAlgorithm.NONE;
                        if (rawHash != null && !rawHash.isBlank()) {
                            normalizedHash = normalizeLibreLoginHash(rawHash.strip(), rawSalt, rawAlgo);
                            hashAlgo = PasswordHasher.detectAlgorithm(normalizedHash, HashAlgorithm.NONE);
                            if (hashAlgo == HashAlgorithm.NONE) {
                                skippedInvalid++;
                                skippedDetails.add(new SkippedEntry(displayName, "unsupported_hash"));
                                continue;
                            }
                        } else if (!isPremium) {
                            skippedInvalid++;
                            skippedDetails.add(new SkippedEntry(displayName, "missing_password"));
                            continue;
                        }

                        long joinedAt = parseTimestamp(rs, cols, "joined", now);
                        long lastSeenAt = parseTimestamp(rs, cols, "last_seen", joinedAt);
                        String rawIp = getString(rs, cols, "ip");
                        String ipHash = (rawIp == null || rawIp.isBlank())
                                ? null
                                : IpHmac.hashIp(secrets.hmacKey(), rawIp.strip());

                        String rawSecret = getString(rs, cols, "secret");
                        String encryptedTotp = (rawSecret != null && !rawSecret.isBlank())
                                ? AesGcmCrypto.encrypt(secrets.totpKey(), rawSecret.strip())
                                : null;

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
                                    nameLower, displayName, gameUuid, premiumUuid, normalizedHash, hashAlgo, isPremium,
                                    encryptedTotp, email, joinedAt, lastSeenAt, ipHash, now).join();
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
                throw new RuntimeException("LibreLogin import failed: " + e.getMessage(), e);
            }

            if (!dryRun) {
                audit.record(now, actor, "IMPORT_LIBRELOGIN", effectiveTable,
                        "imported=" + imported + ",skippedExisting=" + skippedExisting + ",skippedInvalid=" + skippedInvalid)
                        .join();
            }
            return new ImportReport(imported, skippedExisting, skippedInvalid, List.copyOf(skippedDetails));
        });
    }

    static String normalizeLibreLoginHash(String rawHash, @Nullable String rawSalt, @Nullable String rawAlgo) {
        return PasswordHasher.normalizeLegacyHash(rawHash, rawSalt, rawAlgo);
    }

    private static String resolveEffectiveTable(Connection conn, String requestedTable) {
        try {
            if (tableExists(conn, requestedTable)) {
                return requestedTable;
            }
            if (!requestedTable.equalsIgnoreCase("librepremium_data") && tableExists(conn, "librepremium_data")) {
                return "librepremium_data";
            }
            if (!requestedTable.equalsIgnoreCase("librelogin_data") && tableExists(conn, "librelogin_data")) {
                return "librelogin_data";
            }
        } catch (SQLException ignored) {
            // fall through to requestedTable
        }
        return requestedTable;
    }

    static boolean tableExists(Connection conn, String tableName) throws SQLException {
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

    static long parseTimestamp(ResultSet rs, Set<String> cols, String name, long fallback) {
        if (!cols.contains(name)) return fallback;
        try {
            Object obj = rs.getObject(name);
            if (obj == null) return fallback;
            if (obj instanceof Number num) {
                long v = num.longValue();
                return v > 0 ? v : fallback;
            }
            if (obj instanceof Timestamp ts) {
                long v = ts.getTime();
                return v > 0 ? v : fallback;
            }
            String s = obj.toString().strip();
            if (s.isEmpty()) return fallback;
            try {
                long v = Long.parseLong(s);
                return v > 0 ? v : fallback;
            } catch (NumberFormatException ignored) {
                // try timestamp formats
            }
            try {
                return Instant.parse(s).toEpochMilli();
            } catch (Exception ignored) {
                // try SQL timestamp format "yyyy-MM-dd HH:mm:ss"
            }
            try {
                return Timestamp.valueOf(s).getTime();
            } catch (Exception ignored) {
                return fallback;
            }
        } catch (SQLException e) {
            return fallback;
        }
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

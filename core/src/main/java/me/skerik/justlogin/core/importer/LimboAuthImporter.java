package me.skerik.justlogin.core.importer;

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
 * Clean-room importer reading LimboAuth's {@code AUTH} table or Authy's {@code players} table
 * from SQLite or MariaDB/MySQL. Preserves {@code PREMIUMUUID}, encrypts {@code TOTPTOKEN}, and
 * normalizes BCrypt, SHA-256, SHA-512, and Argon2 hashes.
 */
public final class LimboAuthImporter {

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

    private LimboAuthImporter() {
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
                        String rawNick = AuthMeImporter.firstNonBlank(
                                getString(rs, cols, "nickname"),
                                getString(rs, cols, "username"),
                                getString(rs, cols, "lowercasenickname"),
                                getString(rs, cols, "lowercase_nickname"),
                                getString(rs, cols, "name"));
                        if (rawNick == null || rawNick.isBlank()) {
                            skippedInvalid++;
                            skippedDetails.add(new SkippedEntry("<blank>", "missing_username"));
                            continue;
                        }
                        String displayName = rawNick.strip();
                        if (!UsernameValidator.isValid(displayName, AuthMeImporter.DEFAULT_USERNAME_PATTERN)) {
                            skippedInvalid++;
                            skippedDetails.add(new SkippedEntry(displayName, "invalid_username"));
                            continue;
                        }
                        String nameLower = UsernameValidator.normalizeLower(displayName);

                        UUID premiumUuid = FastLoginImporter.parseFlexibleUuid(AuthMeImporter.firstNonBlank(
                                getString(rs, cols, "premiumuuid"),
                                getString(rs, cols, "premium_uuid")));
                        UUID explicitUuid = FastLoginImporter.parseFlexibleUuid(getString(rs, cols, "uuid"));
                        UUID gameUuid;
                        if (explicitUuid != null) {
                            boolean isSyntheticOffline = explicitUuid.equals(AuthMeImporter.offlineUuid(displayName))
                                    || explicitUuid.equals(AuthMeImporter.offlineUuid(nameLower));
                            gameUuid = (premiumUuid != null && isSyntheticOffline) ? premiumUuid : explicitUuid;
                        } else {
                            gameUuid = premiumUuid != null ? premiumUuid : AuthMeImporter.offlineUuid(displayName);
                        }
                        Boolean isPremium = premiumUuid != null ? Boolean.TRUE : null;

                        String rawPassword = AuthMeImporter.firstNonBlank(
                                getString(rs, cols, "hash"),
                                getString(rs, cols, "password"));
                        String normalizedHash = null;
                        HashAlgorithm hashAlgo = HashAlgorithm.NONE;
                        if (rawPassword != null && !rawPassword.isBlank()) {
                            normalizedHash = PasswordHasher.normalizeLegacyHash(rawPassword.strip(), null, null);
                            hashAlgo = PasswordHasher.detectAlgorithm(normalizedHash, HashAlgorithm.NONE);
                            if (hashAlgo == HashAlgorithm.NONE) {
                                skippedInvalid++;
                                skippedDetails.add(new SkippedEntry(displayName, "unsupported_hash"));
                                continue;
                            }
                        } else if (premiumUuid == null) {
                            skippedInvalid++;
                            skippedDetails.add(new SkippedEntry(displayName, "missing_password"));
                            continue;
                        }

                        long regDate = LibreLoginImporter.parseTimestamp(
                                rs, cols, cols.contains("regdate") ? "regdate" : "reg_date", now);
                        long loginDate = LibreLoginImporter.parseTimestamp(
                                rs, cols, cols.contains("logindate") ? "logindate" : "login_date", regDate);

                        String rawIp = AuthMeImporter.firstNonBlank(
                                getString(rs, cols, "loginip"),
                                getString(rs, cols, "login_ip"),
                                getString(rs, cols, "ip"));
                        String ipHash = (rawIp == null || rawIp.isBlank())
                                ? null
                                : IpHmac.hashIp(secrets.hmacKey(), rawIp.strip());

                        String rawTotp = AuthMeImporter.firstNonBlank(
                                getString(rs, cols, "totptoken"),
                                getString(rs, cols, "totp_token"),
                                getString(rs, cols, "totp"),
                                getString(rs, cols, "secret"));
                        String encryptedTotp = (rawTotp != null && !rawTotp.isBlank())
                                ? AesGcmCrypto.encrypt(secrets.totpKey(), rawTotp.strip())
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
                                    encryptedTotp, email, regDate, loginDate, ipHash, now).join();
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
                throw new RuntimeException("LimboAuth/Authy import failed: " + e.getMessage(), e);
            }

            if (!dryRun) {
                audit.record(now, actor, "IMPORT_LIMBOAUTH", effectiveTable,
                        "imported=" + imported + ",skippedExisting=" + skippedExisting + ",skippedInvalid=" + skippedInvalid)
                        .join();
            }
            return new ImportReport(imported, skippedExisting, skippedInvalid, List.copyOf(skippedDetails));
        });
    }

    private static String resolveEffectiveTable(Connection conn, String requestedTable) {
        try {
            if (LibreLoginImporter.tableExists(conn, requestedTable)) {
                return requestedTable;
            }
            for (String candidate : List.of("AUTH", "auth", "players")) {
                if (!requestedTable.equalsIgnoreCase(candidate) && LibreLoginImporter.tableExists(conn, candidate)) {
                    return candidate;
                }
            }
        } catch (SQLException ignored) {
            // fall through to requestedTable
        }
        return requestedTable;
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

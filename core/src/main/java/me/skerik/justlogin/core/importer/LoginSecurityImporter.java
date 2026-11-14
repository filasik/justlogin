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
import me.skerik.justlogin.core.crypto.IpHmac;
import me.skerik.justlogin.core.crypto.PasswordHasher;
import me.skerik.justlogin.core.crypto.ServerSecrets;
import me.skerik.justlogin.core.model.HashAlgorithm;
import me.skerik.justlogin.core.security.UsernameValidator;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import org.jspecify.annotations.Nullable;

/**
 * Clean-room importer reading LoginSecurity's {@code ls_players} table (SQLite or MariaDB/MySQL).
 */
public final class LoginSecurityImporter {

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

    private LoginSecurityImporter() {
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
                    String lastName = getString(rs, cols, "last_name");
                    if (lastName == null || lastName.isBlank()) {
                        skippedInvalid++;
                        skippedDetails.add(new SkippedEntry("<blank>", "missing_username"));
                        continue;
                    }
                    String displayName = lastName.strip();
                    if (!UsernameValidator.isValid(displayName, AuthMeImporter.DEFAULT_USERNAME_PATTERN)) {
                        skippedInvalid++;
                        skippedDetails.add(new SkippedEntry(displayName, "invalid_username"));
                        continue;
                    }
                    String nameLower = UsernameValidator.normalizeLower(displayName);

                    String rawPassword = getString(rs, cols, "password");
                    if (rawPassword == null || rawPassword.isBlank()) {
                        skippedInvalid++;
                        skippedDetails.add(new SkippedEntry(displayName, "missing_password"));
                        continue;
                    }
                    String rawAlgoId = getString(rs, cols, "hashing_algorithm");
                    String algoHint = mapLoginSecurityAlgoHint(rawAlgoId);
                    String trimmedHash = PasswordHasher.normalizeLegacyHash(rawPassword.strip(), null, algoHint);
                    HashAlgorithm algo = PasswordHasher.detectAlgorithm(trimmedHash, HashAlgorithm.NONE);
                    if (algo == HashAlgorithm.NONE) {
                        skippedInvalid++;
                        skippedDetails.add(new SkippedEntry(displayName, "unsupported_hash"));
                        continue;
                    }

                    UUID gameUuid = FastLoginImporter.parseFlexibleUuid(getString(rs, cols, "unique_user_id"));
                    if (gameUuid == null) {
                        gameUuid = AuthMeImporter.offlineUuid(displayName);
                    }

                    long regDate = LibreLoginImporter.parseTimestamp(rs, cols, "registration_date", now);
                    long lastLogin = LibreLoginImporter.parseTimestamp(rs, cols, "last_login", regDate);
                    String rawIp = getString(rs, cols, "ip_address");
                    String ipHash = (rawIp == null || rawIp.isBlank())
                            ? null
                            : IpHmac.hashIp(secrets.hmacKey(), rawIp.strip());

                    if (dryRun) {
                        boolean exists = accounts.findByNameLower(nameLower).join().isPresent()
                                || accounts.findByGameUuid(gameUuid).join().isPresent();
                        if (exists) {
                            skippedExisting++;
                            skippedDetails.add(new SkippedEntry(displayName, "already_exists"));
                        } else {
                            imported++;
                        }
                    } else {
                        boolean inserted = accounts.importIfAbsent(
                                nameLower, displayName, gameUuid, null, trimmedHash, algo, null,
                                null, null, regDate, lastLogin, ipHash, now).join();
                        if (inserted) {
                            imported++;
                        } else {
                            skippedExisting++;
                            skippedDetails.add(new SkippedEntry(displayName, "already_exists"));
                        }
                    }
                }
            } catch (SQLException e) {
                throw new RuntimeException("LoginSecurity import failed: " + e.getMessage(), e);
            }

            if (!dryRun) {
                audit.record(now, actor, "IMPORT_LOGINSECURITY", safeTable,
                        "imported=" + imported + ",skippedExisting=" + skippedExisting + ",skippedInvalid=" + skippedInvalid)
                        .join();
            }
            return new ImportReport(imported, skippedExisting, skippedInvalid, List.copyOf(skippedDetails));
        });
    }

    private static @Nullable String mapLoginSecurityAlgoHint(@Nullable String rawAlgo) {
        if (rawAlgo == null || rawAlgo.isBlank()) return null;
        return switch (rawAlgo.strip()) {
            case "6", "SHA512", "SHA-512" -> "SHA-512";
            case "5", "10", "30", "SHA256", "SHA-256" -> "SHA-256";
            case "7", "BCRYPT" -> "BCrypt-2A";
            default -> rawAlgo.strip();
        };
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

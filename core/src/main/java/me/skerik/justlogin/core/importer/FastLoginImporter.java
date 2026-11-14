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
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import me.skerik.justlogin.core.model.Account;
import me.skerik.justlogin.core.model.HashAlgorithm;
import me.skerik.justlogin.core.security.UsernameValidator;
import me.skerik.justlogin.core.service.MojangApiClient;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import org.jspecify.annotations.Nullable;

/**
 * Clean-room importer reading FastLogin's {@code premium} table from SQLite or MariaDB/MySQL.
 * Fixes P0-6: when upgrading an AuthMe-imported account whose {@code game_uuid} is still the synthetic
 * offline UUID, replaces {@code game_uuid} with the player's Mojang UUID so premium players keep their
 * pre-migration inventory and permissions.
 */
public final class FastLoginImporter {

    public record SkippedEntry(String username, String reason) {
    }

    public record ImportReport(
            int importedNew,
            int updatedExisting,
            int skipped,
            List<SkippedEntry> skippedDetails
    ) {
        public ImportReport(int importedNew, int updatedExisting, int skipped) {
            this(importedNew, updatedExisting, skipped, List.of());
        }
    }

    private FastLoginImporter() {
    }

    public static CompletableFuture<ImportReport> importFromSqlite(
            String sqlitePath, String tableName, AccountStore accounts, AuditStore audit, String actor, long now) {
        return importFromSqlite(sqlitePath, tableName, accounts, audit, actor, false, now);
    }

    public static CompletableFuture<ImportReport> importFromSqlite(
            String sqlitePath, String tableName, AccountStore accounts, AuditStore audit,
            String actor, boolean dryRun, long now) {
        return importFromJdbc("jdbc:sqlite:" + sqlitePath, null, null, tableName, accounts, audit, actor, dryRun, now);
    }

    public static CompletableFuture<ImportReport> importFromSqlite(
            String sqlitePath, String tableName, AccountStore accounts, AuditStore audit,
            String actor, long now, boolean dryRun) {
        return importFromSqlite(sqlitePath, tableName, accounts, audit, actor, dryRun, now);
    }

    public static CompletableFuture<ImportReport> importFromJdbc(
            String jdbcUrl, @Nullable String user, @Nullable String password, String tableName,
            AccountStore accounts, AuditStore audit, String actor, long now) {
        return importFromJdbc(jdbcUrl, user, password, tableName, accounts, audit, actor, false, now);
    }

    public static CompletableFuture<ImportReport> importFromJdbc(
            String jdbcUrl, @Nullable String user, @Nullable String password, String tableName,
            AccountStore accounts, AuditStore audit, String actor, long now, boolean dryRun) {
        return importFromJdbc(jdbcUrl, user, password, tableName, accounts, audit, actor, dryRun, now);
    }

    public static CompletableFuture<ImportReport> importFromJdbc(
            String jdbcUrl, @Nullable String user, @Nullable String password, String tableName,
            AccountStore accounts, AuditStore audit, String actor, boolean dryRun, long now) {
        String safeTable = validateIdentifier(tableName);
        return CompletableFuture.supplyAsync(() -> {
            int importedNew = 0;
            int updatedExisting = 0;
            int skipped = 0;
            List<SkippedEntry> skippedDetails = new ArrayList<>();

            try (Connection conn = (user == null || user.isBlank())
                    ? DriverManager.getConnection(jdbcUrl)
                    : DriverManager.getConnection(jdbcUrl, user, password);
                 Statement st = conn.createStatement();
                 ResultSet rs = st.executeQuery("SELECT * FROM " + safeTable)) {

                Set<String> cols = columnNames(rs.getMetaData());
                while (rs.next()) {
                    String name = getString(rs, cols, "name");
                    String uuidStr = getString(rs, cols, "uuid");
                    boolean isPremium = getBoolean(rs, cols, "premium");
                    boolean isFloodgate = cols.contains("floodgate") && getBoolean(rs, cols, "floodgate");
                    if (name == null || name.isBlank()) {
                        skipped++;
                        skippedDetails.add(new SkippedEntry("<blank>", "missing_username"));
                        continue;
                    }
                    String displayName = name.strip();
                    if (isFloodgate) {
                        skipped++;
                        skippedDetails.add(new SkippedEntry(displayName, "floodgate_entry"));
                        continue;
                    }
                    if (!UsernameValidator.isValid(displayName, AuthMeImporter.DEFAULT_USERNAME_PATTERN)) {
                        skipped++;
                        skippedDetails.add(new SkippedEntry(displayName, "invalid_username"));
                        continue;
                    }
                    String nameLower = UsernameValidator.normalizeLower(displayName);
                    UUID mojangUuid = parseFlexibleUuid(uuidStr);

                    Optional<Account> existing = accounts.findByNameLower(nameLower).join();
                    if (existing.isPresent()) {
                        Account acc = existing.get();
                        if (isPremium && mojangUuid != null && acc.premiumUuid() == null) {
                            boolean isOfflineUuid = acc.gameUuid().equals(AuthMeImporter.offlineUuid(acc.lastName()))
                                    || acc.gameUuid().equals(AuthMeImporter.offlineUuid(acc.nameLower()))
                                    || acc.gameUuid().equals(AuthMeImporter.offlineUuid(displayName));
                            if (dryRun) {
                                updatedExisting++;
                            } else {
                                boolean applied = accounts.applyImportedFastLoginPremium(
                                        acc.id(), mojangUuid, isOfflineUuid, nameLower, displayName, now).join();
                                if (applied) {
                                    updatedExisting++;
                                } else {
                                    skipped++;
                                    skippedDetails.add(new SkippedEntry(displayName, "premium_uuid_conflict"));
                                }
                            }
                        } else if (!isPremium && acc.premium() == null) {
                            if (!dryRun) {
                                accounts.setPremiumStatus(acc.id(), false, false, now).join();
                            }
                            updatedExisting++;
                        } else {
                            skipped++;
                            skippedDetails.add(new SkippedEntry(displayName, "already_configured"));
                        }
                    } else if (isPremium && mojangUuid != null) {
                        if (dryRun) {
                            boolean conflict = accounts.findByGameUuid(mojangUuid).join().isPresent()
                                    || accounts.findByPremiumUuid(mojangUuid).join().isPresent();
                            if (conflict) {
                                skipped++;
                                skippedDetails.add(new SkippedEntry(displayName, "uuid_conflict"));
                            } else {
                                importedNew++;
                            }
                        } else {
                            boolean ok = accounts.importIfAbsent(
                                    nameLower, displayName, mojangUuid, mojangUuid, null,
                                    HashAlgorithm.NONE, true, now, now, null, now).join();
                            if (ok) {
                                importedNew++;
                            } else {
                                skipped++;
                                skippedDetails.add(new SkippedEntry(displayName, "uuid_conflict"));
                            }
                        }
                    } else {
                        skipped++;
                        skippedDetails.add(new SkippedEntry(
                                displayName, isPremium ? "missing_mojang_uuid" : "cracked_without_account"));
                    }
                }
            } catch (SQLException e) {
                throw new RuntimeException("FastLogin import failed: " + e.getMessage(), e);
            }

            if (!dryRun) {
                audit.record(now, actor, "IMPORT_FASTLOGIN", safeTable,
                        "importedNew=" + importedNew + ",updatedExisting=" + updatedExisting + ",skipped=" + skipped)
                        .join();
            }
            return new ImportReport(importedNew, updatedExisting, skipped, List.copyOf(skippedDetails));
        });
    }

    static @Nullable UUID parseFlexibleUuid(@Nullable String raw) {
        if (raw == null || raw.isBlank()) return null;
        String s = raw.strip();
        try {
            if (s.length() == 32 && !s.contains("-")) return MojangApiClient.parseUndashedUuid(s);
            return UUID.fromString(s);
        } catch (IllegalArgumentException e) {
            return null;
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

    private static boolean getBoolean(ResultSet rs, Set<String> cols, String name) throws SQLException {
        return cols.contains(name) && rs.getBoolean(name);
    }

    private static String validateIdentifier(String table) {
        if (table == null || !table.matches("^[a-zA-Z0-9_]{1,64}$")) {
            throw new IllegalArgumentException("Invalid table name: " + table);
        }
        return table;
    }
}

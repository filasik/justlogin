package me.skerik.justlogin.core.storage;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.Predicate;

/** Single-use hashed 2FA backup codes stored in {@code justlogin_backup_codes}. */
public final class BackupCodeStore {

    private static final String TABLE = Migrations.table("backup_codes");

    private final Database db;

    public BackupCodeStore(Database db) {
        this.db = db;
    }

    public CompletableFuture<Void> replaceAll(long accountId, List<String> codeHashes, long now) {
        return db.supply(c -> Database.transaction(c, tx -> {
            try (PreparedStatement del = tx.prepareStatement("DELETE FROM " + TABLE + " WHERE account_id = ?")) {
                del.setLong(1, accountId);
                del.executeUpdate();
            }
            if (!codeHashes.isEmpty()) {
                try (PreparedStatement ins = tx.prepareStatement(
                        "INSERT INTO " + TABLE + " (account_id, code_hash, used, created_at) VALUES (?, ?, 0, ?)")) {
                    for (String hash : codeHashes) {
                        ins.setLong(1, accountId);
                        ins.setString(2, hash);
                        ins.setLong(3, now);
                        ins.addBatch();
                    }
                    ins.executeBatch();
                }
            }
            return null;
        }));
    }

    /** Atomically finds and consumes an unused backup code matching {@code matcher}. */
    public CompletableFuture<Boolean> consumeMatching(long accountId, Predicate<String> matcher) {
        return db.supply(c -> Database.transaction(c, tx -> {
            long matchedId = -1;
            try (PreparedStatement sel = tx.prepareStatement(
                    "SELECT id, code_hash FROM " + TABLE + " WHERE account_id = ? AND used = 0")) {
                sel.setLong(1, accountId);
                try (ResultSet rs = sel.executeQuery()) {
                    while (rs.next()) {
                        if (matcher.test(rs.getString("code_hash"))) {
                            matchedId = rs.getLong("id");
                            break;
                        }
                    }
                }
            }
            if (matchedId < 0) return false;
            try (PreparedStatement upd = tx.prepareStatement(
                    "UPDATE " + TABLE + " SET used = 1 WHERE id = ? AND used = 0")) {
                upd.setLong(1, matchedId);
                return upd.executeUpdate() > 0;
            }
        }));
    }

    public CompletableFuture<Integer> countUnused(long accountId) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT COUNT(*) FROM " + TABLE + " WHERE account_id = ? AND used = 0")) {
                ps.setLong(1, accountId);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getInt(1) : 0;
                }
            }
        });
    }
}

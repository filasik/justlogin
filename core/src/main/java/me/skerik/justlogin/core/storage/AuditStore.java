package me.skerik.justlogin.core.storage;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import me.skerik.justlogin.core.model.AuditEntry;
import org.jspecify.annotations.Nullable;

/** Append-only audit log for account administration and security events. */
public final class AuditStore {

    private static final String TABLE = Migrations.table("audit_log");

    private final Database db;

    public AuditStore(Database db) {
        this.db = db;
    }

    public CompletableFuture<Void> record(long timestamp, String actor, String action, String target, @Nullable String details) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "INSERT INTO " + TABLE + " (timestamp, actor, action, target, details) VALUES (?, ?, ?, ?, ?)")) {
                ps.setLong(1, timestamp);
                ps.setString(2, truncate(actor, 64));
                ps.setString(3, truncate(action, 64));
                ps.setString(4, truncate(target, 64));
                if (details == null || details.isBlank()) ps.setNull(5, Types.VARCHAR);
                else ps.setString(5, truncate(details, 255));
                ps.executeUpdate();
                return null;
            }
        });
    }

    public CompletableFuture<List<AuditEntry>> recent(int limit) {
        return db.supply(c -> {
            List<AuditEntry> out = new ArrayList<>();
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT id, timestamp, actor, action, target, details FROM " + TABLE + " ORDER BY id DESC LIMIT ?")) {
                ps.setInt(1, Math.max(1, Math.min(500, limit)));
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        out.add(new AuditEntry(
                                rs.getLong("id"),
                                rs.getLong("timestamp"),
                                rs.getString("actor"),
                                rs.getString("action"),
                                rs.getString("target"),
                                rs.getString("details")
                        ));
                    }
                }
            }
            return out;
        });
    }

    public CompletableFuture<Integer> pruneOlderThan(long cutoffTimestampMillis) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "DELETE FROM " + TABLE + " WHERE timestamp < ?")) {
                ps.setLong(1, cutoffTimestampMillis);
                return ps.executeUpdate();
            }
        });
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max);
    }
}

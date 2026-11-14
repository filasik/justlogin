package me.skerik.justlogin.core.storage;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import me.skerik.justlogin.core.model.Session;

/** Persists IP-bound resume sessions. */
public final class SessionStore {

    private static final String TABLE = Migrations.table("sessions");

    private final Database db;

    public SessionStore(Database db) {
        this.db = db;
    }

    public CompletableFuture<Optional<Session>> findValid(long accountId, String ipHash, long nowMillis) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT account_id, ip_hash, expires_at FROM " + TABLE + " WHERE account_id = ?")) {
                ps.setLong(1, accountId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) return Optional.empty();
                    Session s = new Session(rs.getLong("account_id"), rs.getString("ip_hash"), rs.getLong("expires_at"));
                    if (s.isExpired(nowMillis) || !s.ipHash().equals(ipHash)) {
                        return Optional.empty();
                    }
                    return Optional.of(s);
                }
            }
        });
    }

    public CompletableFuture<Void> upsert(long accountId, String ipHash, long expiresAt) {
        String sql = db.dialect() == DbConfig.Dialect.SQLITE
                ? "INSERT INTO " + TABLE + " (account_id, ip_hash, expires_at) VALUES (?, ?, ?) "
                        + "ON CONFLICT(account_id) DO UPDATE SET ip_hash = excluded.ip_hash, expires_at = excluded.expires_at"
                : "INSERT INTO " + TABLE + " (account_id, ip_hash, expires_at) VALUES (?, ?, ?) "
                        + "ON DUPLICATE KEY UPDATE ip_hash = VALUES(ip_hash), expires_at = VALUES(expires_at)";
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(sql)) {
                ps.setLong(1, accountId);
                ps.setString(2, ipHash);
                ps.setLong(3, expiresAt);
                ps.executeUpdate();
                return null;
            }
        });
    }

    public CompletableFuture<Void> invalidate(long accountId) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement("DELETE FROM " + TABLE + " WHERE account_id = ?")) {
                ps.setLong(1, accountId);
                ps.executeUpdate();
                return null;
            }
        });
    }

    public CompletableFuture<Integer> pruneExpired(long nowMillis) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement("DELETE FROM " + TABLE + " WHERE expires_at <= ?")) {
                ps.setLong(1, nowMillis);
                return ps.executeUpdate();
            }
        });
    }
}

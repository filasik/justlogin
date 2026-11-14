package me.skerik.justlogin.core.storage;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

/** Append-only versioned database schema across SQLite and MariaDB. */
public final class Migrations {

    public static final String PREFIX = "justlogin_";

    private Migrations() {
    }

    public static String table(String name) {
        return PREFIX + name;
    }

    private static final List<List<String>> VERSIONS = List.of(
            // v1 (0.1.0): accounts, backup_codes, sessions, audit_log
            List.of(
                    """
                    CREATE TABLE {P}accounts (
                      id {ID},
                      name_lower VARCHAR(32) NOT NULL UNIQUE,
                      last_name VARCHAR(32) NOT NULL,
                      game_uuid VARCHAR(36) NOT NULL UNIQUE,
                      premium_uuid VARCHAR(36) NULL UNIQUE,
                      password_hash VARCHAR(512) NULL,
                      hash_algo VARCHAR(32) NOT NULL,
                      premium INT NULL,
                      premium_pending INT NOT NULL DEFAULT 0,
                      totp_secret VARCHAR(512) NULL,
                      totp_last_step BIGINT NOT NULL DEFAULT -1,
                      force_password_change INT NOT NULL DEFAULT 0,
                      registered_at BIGINT NOT NULL,
                      last_login_at BIGINT NOT NULL,
                      last_ip_hash VARCHAR(128) NULL,
                      updated_at BIGINT NOT NULL
                    )""",
                    """
                    CREATE TABLE {P}backup_codes (
                      id {ID},
                      account_id BIGINT NOT NULL,
                      code_hash VARCHAR(128) NOT NULL,
                      used INT NOT NULL DEFAULT 0,
                      created_at BIGINT NOT NULL,
                      FOREIGN KEY (account_id) REFERENCES {P}accounts(id) ON DELETE CASCADE
                    )""",
                    "CREATE INDEX {P}backup_codes_acc ON {P}backup_codes (account_id)",
                    """
                    CREATE TABLE {P}sessions (
                      account_id BIGINT NOT NULL PRIMARY KEY,
                      ip_hash VARCHAR(128) NOT NULL,
                      expires_at BIGINT NOT NULL,
                      FOREIGN KEY (account_id) REFERENCES {P}accounts(id) ON DELETE CASCADE
                    )""",
                    "CREATE INDEX {P}sessions_expires ON {P}sessions (expires_at)",
                    """
                    CREATE TABLE {P}audit_log (
                      id {ID},
                      timestamp BIGINT NOT NULL,
                      actor VARCHAR(64) NOT NULL,
                      action VARCHAR(64) NOT NULL,
                      target VARCHAR(64) NOT NULL,
                      details VARCHAR(255) NULL
                    )""",
                    "CREATE INDEX {P}audit_log_ts ON {P}audit_log (timestamp)",
                    "CREATE INDEX {P}audit_log_target ON {P}audit_log (target)"
            ),
            // v2 (1.0.0): email recovery fields on accounts
            List.of(
                    "ALTER TABLE {P}accounts ADD COLUMN email VARCHAR(254) NULL",
                    "ALTER TABLE {P}accounts ADD COLUMN recovery_code_hash VARCHAR(128) NULL",
                    "ALTER TABLE {P}accounts ADD COLUMN recovery_expires_at BIGINT NOT NULL DEFAULT 0",
                    "CREATE INDEX {P}accounts_email ON {P}accounts (email)"
            ),
            // v3 (1.0.0): persistent custom skin textures on accounts
            List.of(
                    "ALTER TABLE {P}accounts ADD COLUMN skin_owner VARCHAR(32) NULL",
                    "ALTER TABLE {P}accounts ADD COLUMN skin_value TEXT NULL",
                    "ALTER TABLE {P}accounts ADD COLUMN skin_signature TEXT NULL",
                    "ALTER TABLE {P}accounts ADD COLUMN skin_updated_at BIGINT NOT NULL DEFAULT 0"
            )
    );

    public static int latestVersion() {
        return VERSIONS.size();
    }

    public static int migrate(Database db) throws SQLException {
        return migrate(db, VERSIONS.size());
    }

    public static int migrate(Database db, int target) throws SQLException {
        return db.call(c -> {
            ensureVersionTable(c);
            int current = currentVersion(c);
            for (int v = current + 1; v <= Math.min(target, VERSIONS.size()); v++) {
                int version = v;
                Database.transaction(c, tx -> {
                    for (String sql : VERSIONS.get(version - 1)) {
                        executeIdempotentDdl(tx, dialect(sql, db.dialect()));
                    }
                    try (PreparedStatement ps = tx.prepareStatement("INSERT INTO " + table("schema") + " (version) VALUES (?)")) {
                        ps.setInt(1, version);
                        ps.executeUpdate();
                    }
                    return null;
                });
            }
            return currentVersion(c);
        });
    }

    private static void ensureVersionTable(Connection c) throws SQLException {
        try (Statement st = c.createStatement()) {
            st.execute("CREATE TABLE IF NOT EXISTS " + table("schema") + " (version INT NOT NULL PRIMARY KEY)");
        }
    }

    private static int currentVersion(Connection c) throws SQLException {
        try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery("SELECT MAX(version) FROM " + table("schema"))) {
            return rs.next() ? rs.getInt(1) : 0;
        }
    }

    private static void executeIdempotentDdl(Connection tx, String sql) throws SQLException {
        try (Statement st = tx.createStatement()) {
            st.execute(sql);
        } catch (SQLException e) {
            String msg = e.getMessage() == null ? "" : e.getMessage().toLowerCase(java.util.Locale.ROOT);
            // MariaDB implicit DDL commit recovery: if a previous crash left a column/index/table already created, continue safely
            if (msg.contains("duplicate column") || msg.contains("duplicate key name") || msg.contains("already exists")) {
                return;
            }
            throw e;
        }
    }

    private static String dialect(String sql, DbConfig.Dialect dialect) {
        String withPrefix = sql.replace("{P}", PREFIX);
        return switch (dialect) {
            case SQLITE -> withPrefix.replace("{ID}", "INTEGER PRIMARY KEY AUTOINCREMENT").replace("{BLOB}", "BLOB");
            case MARIADB -> withPrefix.replace("{ID}", "BIGINT PRIMARY KEY AUTO_INCREMENT").replace("{BLOB}", "LONGBLOB");
        };
    }
}

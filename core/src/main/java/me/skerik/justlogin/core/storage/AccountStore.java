package me.skerik.justlogin.core.storage;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import me.skerik.justlogin.core.model.Account;
import me.skerik.justlogin.core.model.HashAlgorithm;
import org.jspecify.annotations.Nullable;

/** Asynchronous repository for {@code justlogin_accounts}. */
public final class AccountStore {

    private static final String TABLE = Migrations.table("accounts");
    private static final String SELECT_COLS = "id, name_lower, last_name, game_uuid, premium_uuid, password_hash, "
            + "hash_algo, premium, premium_pending, totp_secret, totp_last_step, force_password_change, "
            + "registered_at, last_login_at, last_ip_hash, updated_at, email, recovery_code_hash, recovery_expires_at, "
            + "skin_owner, skin_value, skin_signature, skin_updated_at";

    private final Database db;

    public AccountStore(Database db) {
        this.db = db;
    }

    public CompletableFuture<Optional<Account>> findById(long id) {
        return db.supply(c -> findOne(c, "SELECT " + SELECT_COLS + " FROM " + TABLE + " WHERE id = ?", ps -> ps.setLong(1, id)));
    }

    public CompletableFuture<Optional<Account>> findByNameLower(String nameLower) {
        return db.supply(c -> findOne(c, "SELECT " + SELECT_COLS + " FROM " + TABLE + " WHERE name_lower = ?",
                ps -> ps.setString(1, nameLower)));
    }

    public CompletableFuture<Optional<Account>> findByGameUuid(UUID gameUuid) {
        return db.supply(c -> findOne(c, "SELECT " + SELECT_COLS + " FROM " + TABLE + " WHERE game_uuid = ?",
                ps -> ps.setString(1, gameUuid.toString())));
    }

    public CompletableFuture<Optional<Account>> findByPremiumUuid(UUID premiumUuid) {
        return db.supply(c -> findOne(c, "SELECT " + SELECT_COLS + " FROM " + TABLE + " WHERE premium_uuid = ?",
                ps -> ps.setString(1, premiumUuid.toString())));
    }

    public CompletableFuture<Account> createAccount(
            String nameLower,
            String lastName,
            UUID gameUuid,
            @Nullable UUID premiumUuid,
            @Nullable String passwordHash,
            HashAlgorithm hashAlgo,
            @Nullable Boolean premium,
            boolean premiumPending,
            long now,
            @Nullable String lastIpHash
    ) {
        return db.supply(c -> insert(c, nameLower, lastName, gameUuid, premiumUuid, passwordHash, hashAlgo,
                premium, premiumPending, null, -1L, false, now, now, lastIpHash, now));
    }

    /** Inserts an account when importing from AuthMe/FastLogin; returns false if name_lower or game_uuid already exists. */
    public CompletableFuture<Boolean> importIfAbsent(
            String nameLower,
            String lastName,
            UUID gameUuid,
            @Nullable UUID premiumUuid,
            @Nullable String passwordHash,
            HashAlgorithm hashAlgo,
            @Nullable Boolean premium,
            long registeredAt,
            long lastLoginAt,
            @Nullable String lastIpHash,
            long now
    ) {
        return importIfAbsent(nameLower, lastName, gameUuid, premiumUuid, passwordHash, hashAlgo,
                premium, null, null, registeredAt, lastLoginAt, lastIpHash, now);
    }

    /** Inserts an account when importing with optional TOTP secret and email; returns false on collision. */
    public CompletableFuture<Boolean> importIfAbsent(
            String nameLower,
            String lastName,
            UUID gameUuid,
            @Nullable UUID premiumUuid,
            @Nullable String passwordHash,
            HashAlgorithm hashAlgo,
            @Nullable Boolean premium,
            @Nullable String encryptedTotpSecret,
            @Nullable String email,
            long registeredAt,
            long lastLoginAt,
            @Nullable String lastIpHash,
            long now
    ) {
        return db.supply(c -> {
            if (findOne(c, "SELECT " + SELECT_COLS + " FROM " + TABLE + " WHERE name_lower = ? OR game_uuid = ?", ps -> {
                ps.setString(1, nameLower);
                ps.setString(2, gameUuid.toString());
            }).isPresent()) {
                return false;
            }
            if (premiumUuid != null && findOne(c, "SELECT " + SELECT_COLS + " FROM " + TABLE + " WHERE premium_uuid = ?", ps -> {
                ps.setString(1, premiumUuid.toString());
            }).isPresent()) {
                return false;
            }
            Account created = insert(c, nameLower, lastName, gameUuid, premiumUuid, passwordHash, hashAlgo,
                    premium, false, encryptedTotpSecret, -1L, false, registeredAt, lastLoginAt, lastIpHash, now);
            if (email != null && !email.isBlank()) {
                try (PreparedStatement ps = c.prepareStatement(
                        "UPDATE " + TABLE + " SET email = ? WHERE id = ?")) {
                    ps.setString(1, email);
                    ps.setLong(2, created.id());
                    ps.executeUpdate();
                }
            }
            return true;
        });
    }

    /**
     * Used exclusively during FastLogin migration: attaches {@code mojangUuid} as {@code premium_uuid},
     * sets {@code premium = 1}, and (when {@code setGameUuidToMojang} is true and no other account uses
     * {@code mojangUuid} as {@code game_uuid}) sets {@code game_uuid = mojangUuid} so players migrating from
     * AuthMe + FastLogin keep the Mojang UUID they previously played under.
     */
    public CompletableFuture<Boolean> applyImportedFastLoginPremium(
            long id, UUID mojangUuid, boolean setGameUuidToMojang, String nameLower, String lastName, long now) {
        return db.supply(c -> Database.transaction(c, tx -> {
            Optional<Account> premCollision = findOne(tx,
                    "SELECT " + SELECT_COLS + " FROM " + TABLE + " WHERE premium_uuid = ?",
                    ps -> ps.setString(1, mojangUuid.toString()));
            if (premCollision.isPresent() && premCollision.get().id() != id) {
                return false;
            }
            boolean canSetGameUuid = setGameUuidToMojang;
            if (canSetGameUuid) {
                Optional<Account> gameCollision = findOne(tx,
                        "SELECT " + SELECT_COLS + " FROM " + TABLE + " WHERE game_uuid = ?",
                        ps -> ps.setString(1, mojangUuid.toString()));
                if (gameCollision.isPresent() && gameCollision.get().id() != id) {
                    canSetGameUuid = false;
                }
            }
            String sql = canSetGameUuid
                    ? "UPDATE " + TABLE + " SET premium = 1, premium_pending = 0, game_uuid = ?, premium_uuid = ?, name_lower = ?, last_name = ?, updated_at = ? WHERE id = ?"
                    : "UPDATE " + TABLE + " SET premium = 1, premium_pending = 0, premium_uuid = ?, name_lower = ?, last_name = ?, updated_at = ? WHERE id = ?";
            try (PreparedStatement ps = tx.prepareStatement(sql)) {
                int idx = 1;
                if (canSetGameUuid) {
                    ps.setString(idx++, mojangUuid.toString());
                }
                ps.setString(idx++, mojangUuid.toString());
                ps.setString(idx++, nameLower);
                ps.setString(idx++, lastName);
                ps.setLong(idx++, now);
                ps.setLong(idx, id);
                return ps.executeUpdate() > 0;
            }
        }));
    }

    public CompletableFuture<Void> updatePasswordAndClearForce(long id, String hash, HashAlgorithm algo, long now) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET password_hash = ?, hash_algo = ?, force_password_change = 0, updated_at = ? WHERE id = ?")) {
                ps.setString(1, hash);
                ps.setString(2, algo.name());
                ps.setLong(3, now);
                ps.setLong(4, id);
                ps.executeUpdate();
                return null;
            }
        });
    }

    /** Updates only password_hash and hash_algo during transparent rehash on login, preserving force_password_change (P1-1). */
    public CompletableFuture<Void> updatePasswordHashOnly(long id, String hash, HashAlgorithm algo, long now) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET password_hash = ?, hash_algo = ?, updated_at = ? WHERE id = ?")) {
                ps.setString(1, hash);
                ps.setString(2, algo.name());
                ps.setLong(3, now);
                ps.setLong(4, id);
                ps.executeUpdate();
                return null;
            }
        });
    }

    public CompletableFuture<Void> updateLoginSuccess(long id, String lastName, @Nullable String ipHash, long now) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET last_name = ?, last_login_at = ?, last_ip_hash = ?, updated_at = ? WHERE id = ?")) {
                ps.setString(1, lastName);
                ps.setLong(2, now);
                if (ipHash == null) ps.setNull(3, Types.VARCHAR);
                else ps.setString(3, ipHash);
                ps.setLong(4, now);
                ps.setLong(5, id);
                ps.executeUpdate();
                return null;
            }
        });
    }

    public CompletableFuture<Void> setPremiumPending(long id, boolean pending, long now) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET premium_pending = ?, updated_at = ? WHERE id = ?")) {
                ps.setInt(1, pending ? 1 : 0);
                ps.setLong(2, now);
                ps.setLong(3, id);
                ps.executeUpdate();
                return null;
            }
        });
    }

    public CompletableFuture<Void> confirmPremium(long id, UUID premiumUuid, String nameLower, String lastName, long now) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET premium = 1, premium_pending = 0, premium_uuid = ?, name_lower = ?, last_name = ?, updated_at = ? WHERE id = ?")) {
                ps.setString(1, premiumUuid.toString());
                ps.setString(2, nameLower);
                ps.setString(3, lastName);
                ps.setLong(4, now);
                ps.setLong(5, id);
                ps.executeUpdate();
                return null;
            }
        });
    }

    public CompletableFuture<Void> setPremiumStatus(long id, @Nullable Boolean premium, boolean pending, long now) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET premium = ?, premium_pending = ?, updated_at = ? WHERE id = ?")) {
                if (premium == null) ps.setNull(1, Types.INTEGER);
                else ps.setInt(1, premium ? 1 : 0);
                ps.setInt(2, pending ? 1 : 0);
                ps.setLong(3, now);
                ps.setLong(4, id);
                ps.executeUpdate();
                return null;
            }
        });
    }

    public CompletableFuture<Void> setTotpSecret(long id, @Nullable String encryptedSecret, long lastStep, long now) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET totp_secret = ?, totp_last_step = ?, updated_at = ? WHERE id = ?")) {
                if (encryptedSecret == null) ps.setNull(1, Types.VARCHAR);
                else ps.setString(1, encryptedSecret);
                ps.setLong(2, lastStep);
                ps.setLong(3, now);
                ps.setLong(4, id);
                ps.executeUpdate();
                return null;
            }
        });
    }

    public CompletableFuture<Void> updateTotpLastStep(long id, long step, long now) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET totp_last_step = ?, updated_at = ? WHERE id = ?")) {
                ps.setLong(1, step);
                ps.setLong(2, now);
                ps.setLong(3, id);
                ps.executeUpdate();
                return null;
            }
        });
    }

    /** Atomically advances totp_last_step only if the database still holds an older step (P1-2 replay protection). */
    public CompletableFuture<Boolean> tryAdvanceTotpStep(long id, long step, long now) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET totp_last_step = ?, updated_at = ? WHERE id = ? AND totp_last_step < ?")) {
                ps.setLong(1, step);
                ps.setLong(2, now);
                ps.setLong(3, id);
                ps.setLong(4, step);
                return ps.executeUpdate() == 1;
            }
        });
    }

    /** Atomically consumes a matching, non-expired recovery code hash (P1-2). */
    public CompletableFuture<Boolean> tryConsumeRecoveryCode(long id, String expectedCodeHash, long now) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET recovery_code_hash = NULL, recovery_expires_at = 0, updated_at = ? "
                            + "WHERE id = ? AND recovery_code_hash = ? AND recovery_expires_at >= ?")) {
                ps.setLong(1, now);
                ps.setLong(2, id);
                ps.setString(3, expectedCodeHash);
                ps.setLong(4, now);
                return ps.executeUpdate() == 1;
            }
        });
    }

    /** Returns true if at least one confirmed premium account exists in the database (used by P0-7 rename check). */
    public CompletableFuture<Boolean> hasAnyPremiumAccount() {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT 1 FROM " + TABLE + " WHERE premium = 1 AND premium_uuid IS NOT NULL LIMIT 1");
                 ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        });
    }

    /** Counts accounts whose last_ip_hash matches the given HMAC (used by P1-11 max-accounts-per-ip). */
    public CompletableFuture<Integer> countByIpHash(String ipHash) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT COUNT(*) FROM " + TABLE + " WHERE last_ip_hash = ?")) {
                ps.setString(1, ipHash);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getInt(1) : 0;
                }
            }
        });
    }

    public CompletableFuture<Void> setForcePasswordChange(long id, boolean force, long now) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET force_password_change = ?, updated_at = ? WHERE id = ?")) {
                ps.setInt(1, force ? 1 : 0);
                ps.setLong(2, now);
                ps.setLong(3, id);
                ps.executeUpdate();
                return null;
            }
        });
    }

    public CompletableFuture<Boolean> deleteById(long id) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement("DELETE FROM " + TABLE + " WHERE id = ?")) {
                ps.setLong(1, id);
                return ps.executeUpdate() > 0;
            }
        });
    }

    /** Optimistic-concurrency update from web editor: returns true if updated, false if account was modified or deleted. */
    public CompletableFuture<Boolean> applyEditorUpdateIfUnchanged(
            long id, @Nullable Boolean premium, boolean forcePasswordChange, long expectedUpdatedAt, long newUpdatedAt) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET premium = ?, premium_pending = 0, force_password_change = ?, updated_at = ? "
                            + "WHERE id = ? AND updated_at = ?")) {
                if (premium == null) ps.setNull(1, Types.INTEGER);
                else ps.setInt(1, premium ? 1 : 0);
                ps.setInt(2, forcePasswordChange ? 1 : 0);
                ps.setLong(3, newUpdatedAt);
                ps.setLong(4, id);
                ps.setLong(5, expectedUpdatedAt);
                return ps.executeUpdate() > 0;
            }
        });
    }

    public CompletableFuture<Boolean> deleteIfUnchanged(long id, long expectedUpdatedAt) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement("DELETE FROM " + TABLE + " WHERE id = ? AND updated_at = ?")) {
                ps.setLong(1, id);
                ps.setLong(2, expectedUpdatedAt);
                return ps.executeUpdate() > 0;
            }
        });
    }

    public CompletableFuture<List<Account>> listAccounts(int offset, int limit) {
        return db.supply(c -> {
            List<Account> list = new ArrayList<>();
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT " + SELECT_COLS + " FROM " + TABLE + " ORDER BY id ASC LIMIT ? OFFSET ?")) {
                ps.setInt(1, Math.max(1, limit));
                ps.setInt(2, Math.max(0, offset));
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) list.add(map(rs));
                }
            }
            return list;
        });
    }

    public CompletableFuture<Long> countAccounts() {
        return db.supply(c -> {
            try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM " + TABLE)) {
                return rs.next() ? rs.getLong(1) : 0L;
            }
        });
    }

    public CompletableFuture<List<String>> suggestNames(String prefixLower, int limit) {
        String safePrefix = prefixLower == null ? "" : prefixLower.trim().toLowerCase(java.util.Locale.ROOT);
        int safeLimit = Math.max(1, Math.min(100, limit));
        return db.supply(c -> {
            List<String> names = new ArrayList<>();
            String sql = safePrefix.isEmpty()
                    ? "SELECT last_name FROM " + TABLE + " ORDER BY name_lower ASC LIMIT ?"
                    : "SELECT last_name FROM " + TABLE + " WHERE name_lower LIKE ? ORDER BY name_lower ASC LIMIT ?";
            try (PreparedStatement ps = c.prepareStatement(sql)) {
                if (safePrefix.isEmpty()) {
                    ps.setInt(1, safeLimit);
                } else {
                    ps.setString(1, safePrefix + "%");
                    ps.setInt(2, safeLimit);
                }
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        String n = rs.getString(1);
                        if (n != null && n.toLowerCase(java.util.Locale.ROOT).startsWith(safePrefix)) {
                            names.add(n);
                        }
                    }
                }
            }
            return names;
        });
    }

    public CompletableFuture<Void> setEmail(long id, @Nullable String email, long now) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET email = ?, recovery_code_hash = NULL, recovery_expires_at = 0, updated_at = ? WHERE id = ?")) {
                if (email == null) ps.setNull(1, Types.VARCHAR);
                else ps.setString(1, email);
                ps.setLong(2, now);
                ps.setLong(3, id);
                ps.executeUpdate();
                return null;
            }
        });
    }

    public CompletableFuture<Void> setRecoveryCode(long id, @Nullable String codeHash, long expiresAt, long now) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET recovery_code_hash = ?, recovery_expires_at = ?, updated_at = ? WHERE id = ?")) {
                if (codeHash == null) ps.setNull(1, Types.VARCHAR);
                else ps.setString(1, codeHash);
                ps.setLong(2, expiresAt);
                ps.setLong(3, now);
                ps.setLong(4, id);
                ps.executeUpdate();
                return null;
            }
        });
    }

    /** Renames an account without mutating its persistent {@code game_uuid}; returns false if target name collides. */
    public CompletableFuture<Boolean> renameAccount(long id, String newNameLower, String newLastName, long now) {
        return db.supply(c -> Database.transaction(c, tx -> {
            Optional<Account> collision = findOne(tx,
                    "SELECT " + SELECT_COLS + " FROM " + TABLE + " WHERE name_lower = ?",
                    ps -> ps.setString(1, newNameLower));
            if (collision.isPresent() && collision.get().id() != id) {
                return false;
            }
            int updated;
            try (PreparedStatement ps = tx.prepareStatement(
                    "UPDATE " + TABLE + " SET name_lower = ?, last_name = ?, updated_at = ? WHERE id = ?")) {
                ps.setString(1, newNameLower);
                ps.setString(2, newLastName);
                ps.setLong(3, now);
                ps.setLong(4, id);
                updated = ps.executeUpdate();
            }
            try (PreparedStatement ps = tx.prepareStatement(
                    "DELETE FROM " + Migrations.table("sessions") + " WHERE account_id = ?")) {
                ps.setLong(1, id);
                ps.executeUpdate();
            }
            return updated > 0;
        }));
    }

    /**
     * Merges missing credentials/premium/2FA/email from {@code sourceId} into surviving {@code targetId}
     * without changing {@code target.game_uuid}, then deletes {@code sourceId} atomically.
     */
    public CompletableFuture<Optional<Account>> mergeAccounts(long sourceId, long targetId, long now) {
        if (sourceId == targetId) return CompletableFuture.completedFuture(Optional.empty());
        return db.supply(c -> Database.transaction(c, tx -> {
            Optional<Account> srcOpt = findOne(tx, "SELECT " + SELECT_COLS + " FROM " + TABLE + " WHERE id = ?", ps -> ps.setLong(1, sourceId));
            Optional<Account> dstOpt = findOne(tx, "SELECT " + SELECT_COLS + " FROM " + TABLE + " WHERE id = ?", ps -> ps.setLong(1, targetId));
            if (srcOpt.isEmpty() || dstOpt.isEmpty()) return Optional.empty();

            Account src = srcOpt.get();
            Account dst = dstOpt.get();
            UUID mergedPremiumUuid = dst.premiumUuid() != null ? dst.premiumUuid() : src.premiumUuid();
            Boolean mergedPremium = Boolean.TRUE.equals(dst.premium())
                    ? Boolean.TRUE
                    : (Boolean.TRUE.equals(src.premium()) ? Boolean.TRUE : dst.premium());
            boolean mergedPending = mergedPremium == null && (dst.premiumPending() || src.premiumPending());
            String mergedPwHash = dst.hasPassword() ? dst.passwordHash() : src.passwordHash();
            HashAlgorithm mergedAlgo = dst.hasPassword() ? dst.hashAlgo() : src.hashAlgo();
            boolean transferTotp = !dst.hasTotp() && src.hasTotp();
            String mergedTotp = transferTotp ? src.totpSecretEncrypted() : dst.totpSecretEncrypted();
            long mergedTotpStep = transferTotp ? src.totpLastStep() : dst.totpLastStep();
            String mergedEmail = dst.email() != null ? dst.email() : src.email();
            boolean transferSkin = !dst.hasCustomSkin() && src.hasCustomSkin();
            String mergedSkinOwner = transferSkin ? src.skinOwner() : dst.skinOwner();
            String mergedSkinValue = transferSkin ? src.skinValue() : dst.skinValue();
            String mergedSkinSig = transferSkin ? src.skinSignature() : dst.skinSignature();
            long mergedSkinAt = transferSkin ? src.skinUpdatedAt() : dst.skinUpdatedAt();
            long earliestReg = Math.min(dst.registeredAt(), src.registeredAt());
            long latestLogin = Math.max(dst.lastLoginAt(), src.lastLoginAt());

            if (transferTotp) {
                try (PreparedStatement ps = tx.prepareStatement(
                        "UPDATE " + Migrations.table("backup_codes") + " SET account_id = ? WHERE account_id = ?")) {
                    ps.setLong(1, targetId);
                    ps.setLong(2, sourceId);
                    ps.executeUpdate();
                }
            }
            try (PreparedStatement ps = tx.prepareStatement("DELETE FROM " + TABLE + " WHERE id = ?")) {
                ps.setLong(1, sourceId);
                ps.executeUpdate();
            }
            try (PreparedStatement ps = tx.prepareStatement(
                    "UPDATE " + TABLE + " SET premium_uuid = ?, password_hash = ?, hash_algo = ?, "
                            + "premium = ?, premium_pending = ?, totp_secret = ?, totp_last_step = ?, "
                            + "email = ?, skin_owner = ?, skin_value = ?, skin_signature = ?, skin_updated_at = ?, "
                            + "registered_at = ?, last_login_at = ?, updated_at = ? WHERE id = ?")) {
                if (mergedPremiumUuid == null) ps.setNull(1, Types.VARCHAR);
                else ps.setString(1, mergedPremiumUuid.toString());
                if (mergedPwHash == null) ps.setNull(2, Types.VARCHAR);
                else ps.setString(2, mergedPwHash);
                ps.setString(3, mergedAlgo.name());
                if (mergedPremium == null) ps.setNull(4, Types.INTEGER);
                else ps.setInt(4, mergedPremium ? 1 : 0);
                ps.setInt(5, mergedPending ? 1 : 0);
                if (mergedTotp == null) ps.setNull(6, Types.VARCHAR);
                else ps.setString(6, mergedTotp);
                ps.setLong(7, mergedTotpStep);
                if (mergedEmail == null) ps.setNull(8, Types.VARCHAR);
                else ps.setString(8, mergedEmail);
                if (mergedSkinOwner == null) ps.setNull(9, Types.VARCHAR);
                else ps.setString(9, mergedSkinOwner);
                if (mergedSkinValue == null) ps.setNull(10, Types.VARCHAR);
                else ps.setString(10, mergedSkinValue);
                if (mergedSkinSig == null) ps.setNull(11, Types.VARCHAR);
                else ps.setString(11, mergedSkinSig);
                ps.setLong(12, mergedSkinAt);
                ps.setLong(13, earliestReg);
                ps.setLong(14, latestLogin);
                ps.setLong(15, now);
                ps.setLong(16, targetId);
                ps.executeUpdate();
            }
            return findOne(tx, "SELECT " + SELECT_COLS + " FROM " + TABLE + " WHERE id = ?", ps -> ps.setLong(1, targetId));
        }));
    }

    public CompletableFuture<Void> updateCustomSkin(
            long id, String skinOwner, String skinValue, String skinSignature, long now) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET skin_owner = ?, skin_value = ?, skin_signature = ?, skin_updated_at = ?, updated_at = ? WHERE id = ?")) {
                ps.setString(1, skinOwner);
                ps.setString(2, skinValue);
                ps.setString(3, skinSignature);
                ps.setLong(4, now);
                ps.setLong(5, now);
                ps.setLong(6, id);
                ps.executeUpdate();
                return null;
            }
        });
    }

    public CompletableFuture<Void> clearCustomSkin(long id, long now) {
        return db.supply(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET skin_owner = NULL, skin_value = NULL, skin_signature = NULL, skin_updated_at = ?, updated_at = ? WHERE id = ?")) {
                ps.setLong(1, now);
                ps.setLong(2, now);
                ps.setLong(3, id);
                ps.executeUpdate();
                return null;
            }
        });
    }

    @FunctionalInterface
    private interface Binder {
        void bind(PreparedStatement ps) throws SQLException;
    }

    private static Optional<Account> findOne(Connection c, String sql, Binder binder) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            binder.bind(ps);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(map(rs)) : Optional.empty();
            }
        }
    }

    private static Account insert(
            Connection c, String nameLower, String lastName, UUID gameUuid, @Nullable UUID premiumUuid,
            @Nullable String passwordHash, HashAlgorithm hashAlgo, @Nullable Boolean premium, boolean premiumPending,
            @Nullable String totpSecret, long totpLastStep, boolean forcePasswordChange,
            long registeredAt, long lastLoginAt, @Nullable String lastIpHash, long updatedAt) throws SQLException {
        String sql = "INSERT INTO " + TABLE + " (name_lower, last_name, game_uuid, premium_uuid, password_hash, "
                + "hash_algo, premium, premium_pending, totp_secret, totp_last_step, force_password_change, "
                + "registered_at, last_login_at, last_ip_hash, updated_at) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement ps = c.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, nameLower);
            ps.setString(2, lastName);
            ps.setString(3, gameUuid.toString());
            if (premiumUuid == null) ps.setNull(4, Types.VARCHAR);
            else ps.setString(4, premiumUuid.toString());
            if (passwordHash == null) ps.setNull(5, Types.VARCHAR);
            else ps.setString(5, passwordHash);
            ps.setString(6, hashAlgo.name());
            if (premium == null) ps.setNull(7, Types.INTEGER);
            else ps.setInt(7, premium ? 1 : 0);
            ps.setInt(8, premiumPending ? 1 : 0);
            if (totpSecret == null) ps.setNull(9, Types.VARCHAR);
            else ps.setString(9, totpSecret);
            ps.setLong(10, totpLastStep);
            ps.setInt(11, forcePasswordChange ? 1 : 0);
            ps.setLong(12, registeredAt);
            ps.setLong(13, lastLoginAt);
            if (lastIpHash == null) ps.setNull(14, Types.VARCHAR);
            else ps.setString(14, lastIpHash);
            ps.setLong(15, updatedAt);
            ps.executeUpdate();
            long id;
            try (ResultSet keys = ps.getGeneratedKeys()) {
                if (!keys.next()) throw new SQLException("Failed to retrieve generated account id");
                id = keys.getLong(1);
            }
            return new Account(id, nameLower, lastName, gameUuid, premiumUuid, passwordHash, hashAlgo, premium,
                    premiumPending, totpSecret, totpLastStep, forcePasswordChange, registeredAt, lastLoginAt, lastIpHash, updatedAt);
        }
    }

    private static Account map(ResultSet rs) throws SQLException {
        int premInt = rs.getInt("premium");
        Boolean premium = rs.wasNull() ? null : premInt != 0;
        String premUuidStr = rs.getString("premium_uuid");
        return new Account(
                rs.getLong("id"),
                rs.getString("name_lower"),
                rs.getString("last_name"),
                UUID.fromString(rs.getString("game_uuid")),
                premUuidStr == null ? null : UUID.fromString(premUuidStr),
                rs.getString("password_hash"),
                HashAlgorithm.fromDb(rs.getString("hash_algo")),
                premium,
                rs.getInt("premium_pending") != 0,
                rs.getString("totp_secret"),
                rs.getLong("totp_last_step"),
                rs.getInt("force_password_change") != 0,
                rs.getLong("registered_at"),
                rs.getLong("last_login_at"),
                rs.getString("last_ip_hash"),
                rs.getLong("updated_at"),
                rs.getString("email"),
                rs.getString("recovery_code_hash"),
                rs.getLong("recovery_expires_at"),
                rs.getString("skin_owner"),
                rs.getString("skin_value"),
                rs.getString("skin_signature"),
                rs.getLong("skin_updated_at")
        );
    }
}

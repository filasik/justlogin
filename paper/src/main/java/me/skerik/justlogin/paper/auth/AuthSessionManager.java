package me.skerik.justlogin.paper.auth;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import me.skerik.justlogin.core.model.Account;
import me.skerik.justlogin.core.security.UsernameValidator;
import org.bukkit.Location;
import org.jspecify.annotations.Nullable;

/**
 * Thread-safe registry tracking configuration-phase pending auth dialogs, post-configure pre-auth grants,
 * active PLAY sessions, and temporary TOTP setup challenges.
 */
public final class AuthSessionManager {

    public enum AuthState {
        AUTHENTICATED,
        AWAITING_REGISTER,
        AWAITING_LOGIN,
        AWAITING_2FA,
        AWAITING_PROXY,
        AWAITING_FORCED_PW_CHANGE
    }

    public enum ConfigPhase {
        REGISTER,
        LOGIN,
        TOTP,
        FORCED_PW_CHANGE
    }

    public record ConfigOutcome(boolean authenticated, @Nullable Account account, String reason) {
        public static ConfigOutcome ok(Account account) {
            return new ConfigOutcome(true, account, "");
        }

        public static ConfigOutcome failed(String reason) {
            return new ConfigOutcome(false, null, reason);
        }
    }

    public static final class PendingConfigAuth {
        private final String nonce;
        private final String username;
        private final String nameLower;
        private final @Nullable UUID profileUuid;
        private final String ip;
        private final Object connection;
        private final CompletableFuture<ConfigOutcome> future = new CompletableFuture<>();
        private volatile ConfigPhase phase;
        private volatile @Nullable Account account;
        private volatile boolean authenticating;

        public PendingConfigAuth(
                String nonce, String username, @Nullable UUID profileUuid,
                String ip, Object connection, ConfigPhase initialPhase, @Nullable Account account) {
            this.nonce = nonce;
            this.username = username;
            this.nameLower = UsernameValidator.normalizeLower(username);
            this.profileUuid = profileUuid;
            this.ip = ip;
            this.connection = connection;
            this.phase = initialPhase;
            this.account = account;
        }

        public String nonce() { return nonce; }
        public String username() { return username; }
        public String nameLower() { return nameLower; }
        public @Nullable UUID profileUuid() { return profileUuid; }
        public String ip() { return ip; }
        public Object connection() { return connection; }
        public CompletableFuture<ConfigOutcome> future() { return future; }
        public ConfigPhase phase() { return phase; }
        public void setPhase(ConfigPhase phase) { this.phase = phase; }
        public @Nullable Account account() { return account; }
        public void setAccount(@Nullable Account account) { this.account = account; }

        public boolean tryBeginOp() {
            synchronized (this) {
                if (authenticating) return false;
                authenticating = true;
                return true;
            }
        }

        public void endOp() {
            authenticating = false;
        }
    }

    public record PreAuthGrant(
            String nameLower,
            @Nullable UUID uuid,
            String ip,
            AuthState state,
            @Nullable Account account,
            boolean sessionResumed,
            boolean standalonePremium,
            boolean pendingConfirmed,
            long createdAt
    ) {
    }

    public static final class PlayerSession {
        private final UUID uuid;
        private final String username;
        private final String nameLower;
        private final String ip;
        private volatile AuthState state;
        private volatile @Nullable Account account;
        private volatile @Nullable Location anchorLocation;
        private volatile @Nullable String activeDialogNonce;
        private volatile @Nullable Runnable reminderCancel;
        private volatile boolean authenticating;

        public PlayerSession(UUID uuid, String username, String ip, AuthState state,
                             @Nullable Account account, @Nullable Location anchorLocation) {
            this.uuid = uuid;
            this.username = username;
            this.nameLower = UsernameValidator.normalizeLower(username);
            this.ip = ip;
            this.state = state;
            this.account = account;
            this.anchorLocation = anchorLocation;
        }

        public UUID uuid() { return uuid; }
        public String username() { return username; }
        public String nameLower() { return nameLower; }
        public String ip() { return ip; }
        public AuthState state() { return state; }
        public void setState(AuthState state) { this.state = state; }
        public @Nullable Account account() { return account; }
        public void setAccount(@Nullable Account account) { this.account = account; }
        public @Nullable Location anchorLocation() { return anchorLocation; }
        public void setAnchorLocation(@Nullable Location anchorLocation) { this.anchorLocation = anchorLocation; }
        public @Nullable String activeDialogNonce() { return activeDialogNonce; }
        public void setActiveDialogNonce(@Nullable String nonce) { this.activeDialogNonce = nonce; }
        public void setReminderCancel(@Nullable Runnable cancel) {
            Runnable prev = this.reminderCancel;
            this.reminderCancel = cancel;
            if (prev != null) prev.run();
        }
        public boolean isAuthenticated() { return state == AuthState.AUTHENTICATED; }
        public boolean tryBeginOp() {
            synchronized (this) {
                if (authenticating) return false;
                authenticating = true;
                return true;
            }
        }
        public void endOp() {
            authenticating = false;
        }
    }

    public record PendingTotpSetup(String base32Secret, long expiresAt) {
    }

    public static final long PRE_AUTH_GRANT_TTL_MS = 30_000L;

    private static final SecureRandom RNG = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    private final Map<String, PendingConfigAuth> configByNonce = new ConcurrentHashMap<>();
    private final Map<String, PendingConfigAuth> configByName = new ConcurrentHashMap<>();
    private final Map<String, PreAuthGrant> preAuthGrantsByName = new ConcurrentHashMap<>();
    private final Map<String, java.util.concurrent.atomic.AtomicInteger> rejectedDuplicatesByName = new ConcurrentHashMap<>();
    private final Map<UUID, PlayerSession> sessionsByUuid = new ConcurrentHashMap<>();
    private final Map<String, PlayerSession> sessionsByName = new ConcurrentHashMap<>();
    private final Map<UUID, PendingTotpSetup> pendingTotpSetups = new ConcurrentHashMap<>();
    private final Map<String, UUID> nonceToPlayerUuid = new ConcurrentHashMap<>();

    public String newNonce() {
        byte[] bytes = new byte[8];
        RNG.nextBytes(bytes);
        return HEX.formatHex(bytes);
    }

    public boolean hasActiveConfigAuth(String username) {
        PendingConfigAuth existing = configByName.get(UsernameValidator.normalizeLower(username));
        return existing != null && !existing.future().isDone();
    }

    public void recordRejectedDuplicate(String username) {
        String lower = UsernameValidator.normalizeLower(username);
        rejectedDuplicatesByName.computeIfAbsent(lower, k -> new java.util.concurrent.atomic.AtomicInteger()).incrementAndGet();
    }

    public boolean consumeRejectedDuplicate(@Nullable String username) {
        if (username == null) return false;
        String lower = UsernameValidator.normalizeLower(username);
        var counter = rejectedDuplicatesByName.get(lower);
        if (counter == null) return false;
        int prev = counter.getAndUpdate(v -> v > 0 ? v - 1 : 0);
        if (prev <= 1) {
            rejectedDuplicatesByName.remove(lower, counter);
        }
        return prev > 0;
    }

    public PendingConfigAuth createConfigAuth(
            String username, @Nullable UUID profileUuid, String ip,
            Object connection, ConfigPhase phase, @Nullable Account account) {
        String nonce = newNonce();
        String lower = UsernameValidator.normalizeLower(username);
        PendingConfigAuth pending = new PendingConfigAuth(nonce, username, profileUuid, ip, connection, phase, account);
        PendingConfigAuth previous = configByName.put(lower, pending);
        if (previous != null) {
            configByNonce.remove(previous.nonce());
            previous.future().complete(ConfigOutcome.failed("replaced"));
        }
        configByNonce.put(nonce, pending);
        return pending;
    }

    public @Nullable PendingConfigAuth getConfigByNonce(String nonce) {
        return configByNonce.get(nonce);
    }

    public @Nullable PendingConfigAuth getConfigByName(String username) {
        return configByName.get(UsernameValidator.normalizeLower(username));
    }

    public void finishConfigAuth(PendingConfigAuth pending, ConfigOutcome outcome) {
        configByNonce.remove(pending.nonce());
        configByName.remove(pending.nameLower(), pending);
        pending.future().complete(outcome);
    }

    public void onConnectionClosed(@Nullable String username, @Nullable UUID uuid) {
        if (consumeRejectedDuplicate(username)) {
            return;
        }
        if (username != null && isOnlineAuthenticated(username)) {
            return;
        }
        cancelConfigAuthByIdentity(username, uuid);
        if (username != null) {
            preAuthGrantsByName.remove(UsernameValidator.normalizeLower(username));
        }
    }

    public void cancelConfigAuthByIdentity(@Nullable String username, @Nullable UUID uuid) {
        if (username != null) {
            String lower = UsernameValidator.normalizeLower(username);
            PendingConfigAuth pending = configByName.get(lower);
            if (pending != null && (uuid == null || pending.profileUuid() == null || uuid.equals(pending.profileUuid()))) {
                if (configByName.remove(lower, pending)) {
                    configByNonce.remove(pending.nonce());
                    pending.future().complete(ConfigOutcome.failed("disconnected"));
                }
            }
        }
        if (uuid != null) {
            for (PendingConfigAuth p : Set.copyOf(configByNonce.values())) {
                if (uuid.equals(p.profileUuid())) {
                    configByNonce.remove(p.nonce());
                    configByName.remove(p.nameLower(), p);
                    p.future().complete(ConfigOutcome.failed("disconnected"));
                }
            }
        }
    }

    public void grantPreAuth(
            String username, @Nullable UUID uuid, String ip, AuthState state,
            @Nullable Account account, boolean sessionResumed) {
        grantPreAuth(username, uuid, ip, state, account, sessionResumed, false, false);
    }

    public void grantPreAuth(
            String username, @Nullable UUID uuid, String ip, AuthState state,
            @Nullable Account account, boolean sessionResumed,
            boolean standalonePremium, boolean pendingConfirmed) {
        String lower = UsernameValidator.normalizeLower(username);
        preAuthGrantsByName.put(lower, new PreAuthGrant(
                lower, uuid, ip, state, account, sessionResumed, standalonePremium, pendingConfirmed,
                System.currentTimeMillis()));
    }

    public @Nullable PreAuthGrant consumePreAuthGrant(String username) {
        return consumePreAuthGrant(username, null, null);
    }

    public @Nullable PreAuthGrant consumePreAuthGrant(String username, @Nullable UUID uuid, @Nullable String ip) {
        PreAuthGrant grant = preAuthGrantsByName.remove(UsernameValidator.normalizeLower(username));
        if (grant == null) return null;
        if (System.currentTimeMillis() - grant.createdAt() > PRE_AUTH_GRANT_TTL_MS) {
            return null;
        }
        if (ip != null && grant.ip() != null && !grant.ip().equals(ip)) {
            return null;
        }
        if (uuid != null && grant.uuid() != null && !grant.uuid().equals(uuid)) {
            return null;
        }
        return grant;
    }

    public void pruneExpired() {
        long now = System.currentTimeMillis();
        preAuthGrantsByName.entrySet().removeIf(e -> now - e.getValue().createdAt() > PRE_AUTH_GRANT_TTL_MS);
        pendingTotpSetups.entrySet().removeIf(e -> now > e.getValue().expiresAt());
    }

    public PlayerSession registerPlayerSession(
            UUID uuid, String username, String ip, AuthState state,
            @Nullable Account account, @Nullable Location anchor) {
        PlayerSession session = new PlayerSession(uuid, username, ip, state, account, anchor);
        sessionsByUuid.put(uuid, session);
        sessionsByName.put(session.nameLower(), session);
        return session;
    }

    public @Nullable PlayerSession getSession(@Nullable UUID uuid) {
        return uuid == null ? null : sessionsByUuid.get(uuid);
    }

    public @Nullable PlayerSession getSessionByName(@Nullable String username) {
        return username == null ? null : sessionsByName.get(UsernameValidator.normalizeLower(username));
    }

    public void bindPlayDialogNonce(UUID uuid, String nonce) {
        PlayerSession s = sessionsByUuid.get(uuid);
        if (s != null) {
            String prev = s.activeDialogNonce();
            if (prev != null) nonceToPlayerUuid.remove(prev);
            s.setActiveDialogNonce(nonce);
            nonceToPlayerUuid.put(nonce, uuid);
        }
    }

    public @Nullable PlayerSession getSessionByNonce(String nonce) {
        UUID uuid = nonceToPlayerUuid.get(nonce);
        return uuid == null ? null : sessionsByUuid.get(uuid);
    }

    public void removePlayerSession(UUID uuid) {
        PlayerSession removed = sessionsByUuid.remove(uuid);
        if (removed != null) {
            removed.setReminderCancel(null);
            sessionsByName.remove(removed.nameLower(), removed);
            String nonce = removed.activeDialogNonce();
            if (nonce != null) nonceToPlayerUuid.remove(nonce, uuid);
        }
        pendingTotpSetups.remove(uuid);
    }

    public boolean isAuthenticated(@Nullable UUID uuid) {
        PlayerSession s = getSession(uuid);
        return s != null && s.isAuthenticated();
    }

    public boolean isOnlineAuthenticated(String username) {
        PlayerSession s = getSessionByName(username);
        return s != null && s.isAuthenticated();
    }

    public void putPendingTotpSetup(UUID uuid, String secret, long expiresAt) {
        pendingTotpSetups.put(uuid, new PendingTotpSetup(secret, expiresAt));
    }

    public @Nullable PendingTotpSetup consumePendingTotpSetup(UUID uuid, long nowMillis) {
        PendingTotpSetup setup = pendingTotpSetups.get(uuid);
        if (setup == null) return null;
        if (nowMillis > setup.expiresAt()) {
            pendingTotpSetups.remove(uuid, setup);
            return null;
        }
        pendingTotpSetups.remove(uuid, setup);
        return setup;
    }

    public void clearAll() {
        for (PendingConfigAuth p : configByNonce.values()) {
            p.future().complete(ConfigOutcome.failed("shutdown"));
        }
        configByNonce.clear();
        configByName.clear();
        preAuthGrantsByName.clear();
        rejectedDuplicatesByName.clear();
        for (PlayerSession s : sessionsByUuid.values()) {
            s.setReminderCancel(null);
        }
        sessionsByUuid.clear();
        sessionsByName.clear();
        pendingTotpSetups.clear();
        nonceToPlayerUuid.clear();
    }
}

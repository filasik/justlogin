package me.skerik.justlogin.core.service;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import me.skerik.justlogin.core.crypto.IpHmac;
import me.skerik.justlogin.core.crypto.ProxyTokenSigner;
import me.skerik.justlogin.core.crypto.ServerSecrets;
import me.skerik.justlogin.core.model.Account;
import me.skerik.justlogin.core.model.CoreSettings;
import me.skerik.justlogin.core.model.HashAlgorithm;
import me.skerik.justlogin.core.security.UsernameValidator;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import org.jspecify.annotations.Nullable;

/**
 * Shared Mojang pre-login decision, online-mode verification, immutable {@code game_uuid} resolution,
 * {@code /premium} rollback, and HMAC backend token signing used by Velocity, BungeeCord, and standalone Paper.
 */
public final class ProxyAuthService {

    public enum PreLoginAction {
        FORCE_ONLINE,
        FORCE_OFFLINE,
        ALLOW_OFFLINE,
        DENY_INVALID_USERNAME,
        DENY_MOJANG_UNAVAILABLE
    }

    public enum DenyReason {
        PREMIUM_REQUIRED("proxy.deny-premium-required", "This account requires Mojang online authentication."),
        MISSING_MOJANG_UUID("proxy.deny-missing-uuid", "Missing Mojang profile UUID."),
        MOJANG_ALREADY_LINKED("proxy.deny-mojang-already-linked", "That Mojang account is already linked to another player."),
        REGISTERED_AS_OFFLINE("proxy.deny-registered-offline", "Username is registered as offline-mode. Use /premium after logging in."),
        MOJANG_UUID_MISMATCH_RENAME_CONFLICT("proxy.deny-uuid-mismatch",
                "This username is bound to a previously registered Mojang account that renamed. Contact an admin (/jl rename)."),
        MOJANG_UNAVAILABLE("proxy.deny-mojang-unavailable",
                "Mojang authentication servers are temporarily unavailable. Please try again in a moment."),
        INVALID_USERNAME("general.invalid-username", "Invalid username.");

        private final String messageKey;
        private final String fallbackText;

        DenyReason(String messageKey, String fallbackText) {
            this.messageKey = messageKey;
            this.fallbackText = fallbackText;
        }

        public String messageKey() {
            return messageKey;
        }

        public String fallbackText() {
            return fallbackText;
        }
    }

    public record PreLoginDecision(PreLoginAction action, @Nullable Account existingAccount) {
    }

    public record JoinResolution(
            boolean allowed,
            @Nullable String denyReason,
            @Nullable DenyReason denyCode,
            @Nullable UUID targetGameUuid,
            long accountId,
            boolean onlineAuthenticated,
            boolean pendingConfirmed,
            @Nullable String customSkinValue,
            @Nullable String customSkinSignature
    ) {
        public JoinResolution(
                boolean allowed,
                @Nullable String denyReason,
                @Nullable DenyReason denyCode,
                @Nullable UUID targetGameUuid,
                long accountId,
                boolean onlineAuthenticated,
                boolean pendingConfirmed
        ) {
            this(allowed, denyReason, denyCode, targetGameUuid, accountId,
                    onlineAuthenticated, pendingConfirmed, null, null);
        }

        public JoinResolution(
                boolean allowed,
                @Nullable String denyReason,
                @Nullable UUID targetGameUuid,
                long accountId,
                boolean onlineAuthenticated,
                boolean pendingConfirmed
        ) {
            this(allowed, denyReason, null, targetGameUuid, accountId,
                    onlineAuthenticated, pendingConfirmed, null, null);
        }

        public JoinResolution(
                boolean allowed,
                @Nullable String denyReason,
                @Nullable UUID targetGameUuid,
                long accountId,
                boolean onlineAuthenticated
        ) {
            this(allowed, denyReason, null, targetGameUuid, accountId,
                    onlineAuthenticated, false, null, null);
        }

        public boolean hasCustomSkin() {
            return customSkinValue != null && !customSkinValue.isBlank()
                    && customSkinSignature != null && !customSkinSignature.isBlank();
        }

        public JoinResolution withCustomSkin(@Nullable Account account) {
            if (account == null || !account.hasCustomSkin()) {
                return this;
            }
            return new JoinResolution(allowed, denyReason, denyCode, targetGameUuid, accountId,
                    onlineAuthenticated, pendingConfirmed, account.skinValue(), account.skinSignature());
        }

        public static JoinResolution offline(@Nullable UUID targetGameUuid, long accountId) {
            return new JoinResolution(true, null, null, targetGameUuid, accountId, false, false, null, null);
        }

        public static JoinResolution online(UUID targetGameUuid, long accountId) {
            return new JoinResolution(true, null, null, targetGameUuid, accountId, true, false, null, null);
        }

        public static JoinResolution onlinePendingConfirmed(UUID targetGameUuid, long accountId) {
            return new JoinResolution(true, null, null, targetGameUuid, accountId, true, true, null, null);
        }

        public static JoinResolution deny(String reason) {
            return new JoinResolution(false, reason, null, null, -1L, false, false, null, null);
        }

        public static JoinResolution deny(DenyReason code) {
            return new JoinResolution(false, code.fallbackText(), code, null, -1L, false, false, null, null);
        }
    }

    private record ArmedPending(Account account, long expiresAt) {
    }

    private record PendingToken(ProxyTokenSigner.MessageType type, long accountId, String nameLower, UUID gameUuid, long expiresAt) {
    }

    private final AccountStore accounts;
    private final AuditStore audit;
    private final MojangApiClient mojangApi;
    private final ServerSecrets secrets;
    private final Supplier<CoreSettings> settingsSupplier;
    private final LongSupplier clock;
    private final Map<String, ArmedPending> armedPendingByName = new ConcurrentHashMap<>();
    private final Map<String, PendingToken> pendingTokens = new ConcurrentHashMap<>();

    public ProxyAuthService(
            AccountStore accounts,
            AuditStore audit,
            MojangApiClient mojangApi,
            ServerSecrets secrets,
            Supplier<CoreSettings> settingsSupplier,
            LongSupplier clock
    ) {
        this.accounts = accounts;
        this.audit = audit;
        this.mojangApi = mojangApi;
        this.secrets = secrets;
        this.settingsSupplier = settingsSupplier;
        this.clock = clock;
    }

    public CompletableFuture<PreLoginDecision> decidePreLogin(String username, boolean floodgateClient) {
        CoreSettings s = settingsSupplier.get();
        if (!UsernameValidator.isValid(username, s.usernamePattern(), floodgateClient)) {
            return CompletableFuture.completedFuture(new PreLoginDecision(PreLoginAction.DENY_INVALID_USERNAME, null));
        }
        String nameLower = UsernameValidator.normalizeLower(username);

        return accounts.findByNameLower(nameLower).thenCompose(opt -> {
            if (opt.isPresent()) {
                Account acc = opt.get();
                if (acc.isPremiumConfirmed()) {
                    return CompletableFuture.completedFuture(new PreLoginDecision(PreLoginAction.FORCE_ONLINE, acc));
                }
                if (acc.premiumPending()) {
                    long now = clock.getAsLong();
                    // Single-shot consume + automatic rollback in DB BEFORE encryption challenge so failed joins never soft-lock
                    return accounts.setPremiumPending(acc.id(), false, now).thenApply(v -> {
                        armedPendingByName.put(nameLower, new ArmedPending(acc, now + 30_000L));
                        return new PreLoginDecision(PreLoginAction.FORCE_ONLINE, acc);
                    });
                }
                return CompletableFuture.completedFuture(new PreLoginDecision(PreLoginAction.FORCE_OFFLINE, acc));
            }

            if (floodgateClient) {
                return CompletableFuture.completedFuture(new PreLoginDecision(PreLoginAction.ALLOW_OFFLINE, null));
            }

            if (s.premiumAutoDetect()) {
                return mojangApi.lookup(username).thenApply(lookup -> switch (lookup.status()) {
                    case PREMIUM -> new PreLoginDecision(PreLoginAction.FORCE_ONLINE, null);
                    case NOT_FOUND -> new PreLoginDecision(PreLoginAction.ALLOW_OFFLINE, null);
                    // P1-7: fail closed when Mojang lookup is rate-limited or errors out so attackers cannot claim premium names offline
                    case RATE_LIMITED, ERROR -> new PreLoginDecision(PreLoginAction.DENY_MOJANG_UNAVAILABLE, null);
                });
            }

            // P0-7: Even with auto-detect-mojang: false, if the server has at least one confirmed premium account,
            // check if this unknown username belongs to an existing premium player who renamed their Mojang account.
            return accounts.hasAnyPremiumAccount().thenCompose(hasAnyPremium -> {
                if (!hasAnyPremium) {
                    return CompletableFuture.completedFuture(new PreLoginDecision(PreLoginAction.ALLOW_OFFLINE, null));
                }
                return mojangApi.lookup(username).thenCompose(lookup -> switch (lookup.status()) {
                    case NOT_FOUND -> CompletableFuture.completedFuture(
                            new PreLoginDecision(PreLoginAction.ALLOW_OFFLINE, null));
                    case RATE_LIMITED, ERROR -> CompletableFuture.completedFuture(
                            new PreLoginDecision(PreLoginAction.DENY_MOJANG_UNAVAILABLE, null));
                    case PREMIUM -> {
                        UUID mojangUuid = lookup.uuid();
                        if (mojangUuid == null) {
                            yield CompletableFuture.completedFuture(
                                    new PreLoginDecision(PreLoginAction.ALLOW_OFFLINE, null));
                        }
                        yield accounts.findByPremiumUuid(mojangUuid).thenApply(byMojang -> byMojang.isPresent()
                                ? new PreLoginDecision(PreLoginAction.FORCE_ONLINE, byMojang.get())
                                : new PreLoginDecision(PreLoginAction.ALLOW_OFFLINE, null));
                    }
                });
            });
        });
    }

    public CompletableFuture<JoinResolution> resolveJoinProfile(
            String username, @Nullable UUID connectionUuid, boolean onlineMode, String ip) {
        String nameLower = UsernameValidator.normalizeLower(username);
        long now = clock.getAsLong();
        ArmedPending armed = armedPendingByName.remove(nameLower);

        if (!onlineMode) {
            return accounts.findByNameLower(nameLower).thenApply(opt -> {
                if (opt.isEmpty()) {
                    return JoinResolution.offline(null, -1L);
                }
                Account acc = opt.get();
                if (acc.isPremiumConfirmed()) {
                    return JoinResolution.deny(DenyReason.PREMIUM_REQUIRED);
                }
                // Preserve immutable game_uuid across /premium -> /unpremium switches
                return JoinResolution.offline(acc.gameUuid(), acc.id()).withCustomSkin(acc);
            });
        }

        if (connectionUuid == null) {
            return CompletableFuture.completedFuture(JoinResolution.deny(DenyReason.MISSING_MOJANG_UUID));
        }

        if (armed != null && now <= armed.expiresAt()) {
            Account pendingAcc = armed.account();
            return accounts.findByPremiumUuid(connectionUuid).thenCompose(conflict -> {
                if (conflict.isPresent() && conflict.get().id() != pendingAcc.id()) {
                    return CompletableFuture.completedFuture(
                            JoinResolution.deny(DenyReason.MOJANG_ALREADY_LINKED));
                }
                return accounts.confirmPremium(pendingAcc.id(), connectionUuid, nameLower, username, now)
                        .thenCompose(v -> audit.record(now, nameLower, "PREMIUM_VERIFIED", nameLower, connectionUuid.toString()))
                        .thenApply(v -> {
                            queueBackendToken(ProxyTokenSigner.MessageType.PREMIUM_VERIFIED,
                                    pendingAcc.id(), nameLower, pendingAcc.gameUuid(), now);
                            return JoinResolution.onlinePendingConfirmed(pendingAcc.gameUuid(), pendingAcc.id())
                                    .withCustomSkin(pendingAcc);
                        });
            });
        }

        return accounts.findByNameLower(nameLower).thenCompose(byName -> {
            if (byName.isPresent()) {
                Account acc = byName.get();
                if (!acc.isPremiumConfirmed()) {
                    return CompletableFuture.completedFuture(
                            JoinResolution.deny(DenyReason.REGISTERED_AS_OFFLINE));
                }
                if (acc.premiumUuid() != null && !acc.premiumUuid().equals(connectionUuid)) {
                    // Section 5 reverse collision: old premium owner renamed away and another Mojang account took the name
                    return audit.record(now, nameLower, "PREMIUM_UUID_COLLISION", nameLower,
                            "expected=" + acc.premiumUuid() + ",actual=" + connectionUuid)
                            .thenApply(v -> JoinResolution.deny(DenyReason.MOJANG_UUID_MISMATCH_RENAME_CONFLICT));
                }
                CompletableFuture<Void> sync = acc.premiumUuid() == null
                        ? accounts.confirmPremium(acc.id(), connectionUuid, nameLower, username, now)
                        : CompletableFuture.completedFuture(null);
                return sync.thenApply(v -> {
                    queueBackendToken(ProxyTokenSigner.MessageType.AUTH_OK, acc.id(), nameLower, acc.gameUuid(), now);
                    return JoinResolution.online(acc.gameUuid(), acc.id()).withCustomSkin(acc);
                });
            }

            // Check Mojang rename via premiumUuid -> keeps immutable game_uuid!
            return accounts.findByPremiumUuid(connectionUuid).thenCompose(byMojang -> {
                if (byMojang.isPresent()) {
                    Account existing = byMojang.get();
                    return accounts.confirmPremium(existing.id(), connectionUuid, nameLower, username, now)
                            .thenCompose(v -> audit.record(now, nameLower, "MOJANG_RENAME", existing.lastName() + "->" + username, null))
                            .thenApply(v -> {
                                queueBackendToken(ProxyTokenSigner.MessageType.AUTH_OK,
                                        existing.id(), nameLower, existing.gameUuid(), now);
                                return JoinResolution.online(existing.gameUuid(), existing.id()).withCustomSkin(existing);
                            });
                }

                String ipHash = IpHmac.hashIp(secrets.hmacKey(), ip);
                return accounts.createAccount(
                        nameLower, username, connectionUuid, connectionUuid, null,
                        HashAlgorithm.NONE, true, false, now, ipHash
                ).thenCompose(created -> audit.record(now, nameLower, "AUTO_REGISTER_PREMIUM", nameLower, null)
                        .thenApply(v -> {
                            queueBackendToken(ProxyTokenSigner.MessageType.AUTH_OK,
                                    created.id(), nameLower, created.gameUuid(), now);
                            return JoinResolution.online(created.gameUuid(), created.id());
                        }));
            });
        });
    }

    public byte @Nullable [] signBackendMessageIfOnline(ProxyTokenSigner signer, String username, UUID gameUuid) {
        String lower = UsernameValidator.normalizeLower(username);
        PendingToken tok = pendingTokens.get(lower);
        long now = clock.getAsLong();
        if (tok == null || now > tok.expiresAt() || !tok.gameUuid().equals(gameUuid)) {
            pendingTokens.remove(lower, tok);
            return null;
        }
        return signer.sign(tok.type(), tok.accountId(), lower, gameUuid, now);
    }

    public void onDisconnect(String username) {
        String lower = UsernameValidator.normalizeLower(username);
        armedPendingByName.remove(lower);
        pendingTokens.remove(lower);
    }

    public void pruneExpired() {
        long now = clock.getAsLong();
        armedPendingByName.entrySet().removeIf(e -> now > e.getValue().expiresAt());
        pendingTokens.entrySet().removeIf(e -> now > e.getValue().expiresAt());
    }

    private void queueBackendToken(
            ProxyTokenSigner.MessageType type, long accountId, String nameLower, UUID gameUuid, long now) {
        pendingTokens.put(nameLower, new PendingToken(type, accountId, nameLower, gameUuid, now + 300_000L));
    }
}

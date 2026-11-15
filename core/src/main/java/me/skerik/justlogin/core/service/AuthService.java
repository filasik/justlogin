package me.skerik.justlogin.core.service;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import me.skerik.justlogin.core.crypto.AesGcmCrypto;
import me.skerik.justlogin.core.crypto.HashingExecutor;
import me.skerik.justlogin.core.crypto.IpHmac;
import me.skerik.justlogin.core.crypto.PasswordHasher;
import me.skerik.justlogin.core.crypto.ServerSecrets;
import me.skerik.justlogin.core.crypto.TotpService;
import me.skerik.justlogin.core.model.Account;
import me.skerik.justlogin.core.model.CoreSettings;
import me.skerik.justlogin.core.model.HashAlgorithm;
import me.skerik.justlogin.core.security.LoginRateLimiter;
import me.skerik.justlogin.core.security.PasswordPolicy;
import me.skerik.justlogin.core.security.UsernameValidator;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import me.skerik.justlogin.core.storage.BackupCodeStore;
import me.skerik.justlogin.core.storage.SessionStore;
import org.jspecify.annotations.Nullable;

/**
 * Core authentication, registration, password management, TOTP 2FA, sessions, and premium flag orchestration.
 * All DB and Argon2 operations are non-blocking and never touch platform main threads.
 */
public final class AuthService {

    public enum Status {
        SUCCESS,
        NEEDS_2FA,
        NEEDS_PASSWORD_CHANGE,
        ALREADY_REGISTERED,
        NOT_REGISTERED,
        INVALID_USERNAME,
        INVALID_CREDENTIALS,
        INVALID_CODE,
        PASSWORD_POLICY_VIOLATION,
        RATE_LIMITED,
        HASHING_BUSY,
        TOTP_ALREADY_ENABLED,
        TOTP_NOT_ENABLED,
        TOTP_DECRYPT_ERROR,
        ALREADY_PREMIUM,
        PASSWORD_REQUIRED_FOR_CRACKED,
        PASSWORD_ALREADY_SET,
        PREMIUM_CANNOT_UNREGISTER_WITHOUT_PASSWORD,
        TARGET_ALREADY_EXISTS,
        CANNOT_MERGE_SELF,
        TOO_MANY_ACCOUNTS_PER_IP
    }

    public record PreAuthCheck(
            Decision decision,
            @Nullable Account account,
            long retryAfterSeconds
    ) {
        public enum Decision {
            INVALID_USERNAME,
            RATE_LIMITED,
            SESSION_RESUMED,
            REQUIRE_REGISTER,
            REQUIRE_LOGIN,
            REQUIRE_PREMIUM_ONLINE
        }
    }

    public record RegisterResult(
            Status status,
            @Nullable Account account,
            PasswordPolicy.@Nullable Violation policyViolation,
            long retryAfterSeconds
    ) {
    }

    public record LoginResult(
            Status status,
            @Nullable Account account,
            long retryAfterSeconds
    ) {
    }

    public record SimpleResult(
            Status status,
            PasswordPolicy.@Nullable Violation policyViolation,
            long retryAfterSeconds
    ) {
        public SimpleResult(Status status, PasswordPolicy.@Nullable Violation policyViolation) {
            this(status, policyViolation, 0L);
        }

        public static SimpleResult ok() {
            return new SimpleResult(Status.SUCCESS, null, 0L);
        }

        public static SimpleResult of(Status status) {
            return new SimpleResult(status, null, 0L);
        }

        public static SimpleResult rateLimited(long retryAfterSeconds) {
            return new SimpleResult(Status.RATE_LIMITED, null, retryAfterSeconds);
        }
    }

    public record TotpSetupData(Status status, @Nullable String base32Secret, @Nullable String otpauthUri) {
    }

    public record TotpConfirmResult(Status status, List<String> backupCodes) {
    }

    private final AccountStore accounts;
    private final SessionStore sessions;
    private final BackupCodeStore backupCodes;
    private final AuditStore audit;
    private final ServerSecrets secrets;
    private final HashingExecutor hashing;
    private final LoginRateLimiter rateLimiter;
    private final Supplier<CoreSettings> settingsSupplier;
    private final LongSupplier clock;

    public AuthService(
            AccountStore accounts,
            SessionStore sessions,
            BackupCodeStore backupCodes,
            AuditStore audit,
            ServerSecrets secrets,
            HashingExecutor hashing,
            LoginRateLimiter rateLimiter,
            Supplier<CoreSettings> settingsSupplier,
            LongSupplier clock
    ) {
        this.accounts = accounts;
        this.sessions = sessions;
        this.backupCodes = backupCodes;
        this.audit = audit;
        this.secrets = secrets;
        this.hashing = hashing;
        this.rateLimiter = rateLimiter;
        this.settingsSupplier = settingsSupplier;
        this.clock = clock;
    }

    public String hashIp(String ip) {
        return IpHmac.hashIp(secrets.hmacKey(), ip);
    }

    public CompletableFuture<PreAuthCheck> checkPreAuth(String username, String ip) {
        return checkPreAuth(username, ip, false);
    }

    public CompletableFuture<PreAuthCheck> checkPreAuth(String username, String ip, boolean floodgateClient) {
        CoreSettings s = settingsSupplier.get();
        if (!UsernameValidator.isValid(username, s.usernamePattern(), floodgateClient)) {
            return CompletableFuture.completedFuture(new PreAuthCheck(PreAuthCheck.Decision.INVALID_USERNAME, null, 0));
        }
        String nameLower = UsernameValidator.normalizeLower(username);
        boolean unknownIp = IpHmac.isUnknownIp(ip);
        String ipHash = hashIp(ip);
        LoginRateLimiter.Decision rl = rateLimiter.check(nameLower, ipHash, s);
        if (!rl.allowed()) {
            return CompletableFuture.completedFuture(
                    new PreAuthCheck(PreAuthCheck.Decision.RATE_LIMITED, null, rl.retryAfterSeconds()));
        }

        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) {
                return CompletableFuture.completedFuture(
                        new PreAuthCheck(PreAuthCheck.Decision.REQUIRE_REGISTER, null, 0));
            }
            Account acc = found.get();
            if (acc.isPremiumConfirmed()) {
                return CompletableFuture.completedFuture(
                        new PreAuthCheck(PreAuthCheck.Decision.REQUIRE_PREMIUM_ONLINE, acc, 0));
            }
            if (!s.sessionsEnabled() || unknownIp || acc.forcePasswordChange()) {
                return CompletableFuture.completedFuture(
                        new PreAuthCheck(PreAuthCheck.Decision.REQUIRE_LOGIN, acc, 0));
            }
            long now = clock.getAsLong();
            return sessions.findValid(acc.id(), ipHash, now).thenApply(sessionOpt -> sessionOpt.isPresent()
                    ? new PreAuthCheck(PreAuthCheck.Decision.SESSION_RESUMED, acc, 0)
                    : new PreAuthCheck(PreAuthCheck.Decision.REQUIRE_LOGIN, acc, 0));
        });
    }

    public CompletableFuture<RegisterResult> register(
            String username, UUID gameUuid, char[] rawPassword, String ip, String actor) {
        return register(username, gameUuid, rawPassword, ip, actor, false);
    }

    public CompletableFuture<RegisterResult> register(
            String username, UUID gameUuid, char[] rawPassword, String ip, String actor, boolean floodgateClient) {
        CoreSettings s = settingsSupplier.get();
        if (!UsernameValidator.isValid(username, s.usernamePattern(), floodgateClient)) {
            clearChars(rawPassword);
            return CompletableFuture.completedFuture(new RegisterResult(Status.INVALID_USERNAME, null, null, 0));
        }
        String nameLower = UsernameValidator.normalizeLower(username);
        boolean unknownIp = IpHmac.isUnknownIp(ip);
        String ipHash = hashIp(ip);
        LoginRateLimiter.Decision rl = rateLimiter.check(nameLower, ipHash, s);
        if (!rl.allowed()) {
            clearChars(rawPassword);
            return CompletableFuture.completedFuture(
                    new RegisterResult(Status.RATE_LIMITED, null, null, rl.retryAfterSeconds()));
        }

        PasswordPolicy.Violation violation = PasswordPolicy.validate(rawPassword, username, s);
        if (violation != null) {
            clearChars(rawPassword);
            return CompletableFuture.completedFuture(
                    new RegisterResult(Status.PASSWORD_POLICY_VIOLATION, null, violation, 0));
        }

        char[] pwCopy = rawPassword.clone();
        clearChars(rawPassword);

        return accounts.findByNameLower(nameLower).thenCompose(existing -> {
            if (existing.isPresent()) {
                clearChars(pwCopy);
                return CompletableFuture.completedFuture(new RegisterResult(Status.ALREADY_REGISTERED, null, null, 0));
            }
            CompletableFuture<Integer> ipCountFuture = (s.maxAccountsPerIp() > 0 && !unknownIp)
                    ? accounts.countByIpHash(ipHash)
                    : CompletableFuture.completedFuture(0);
            return ipCountFuture.thenCompose(ipCount -> {
                if (s.maxAccountsPerIp() > 0 && !unknownIp && ipCount >= s.maxAccountsPerIp()) {
                    clearChars(pwCopy);
                    return CompletableFuture.completedFuture(
                            new RegisterResult(Status.TOO_MANY_ACCOUNTS_PER_IP, null, null, 0));
                }
                PasswordHasher hasher = new PasswordHasher(s);
                return hashing.submitForKey(ipHash, () -> {
                    try {
                        return hasher.hash(pwCopy);
                    } finally {
                        clearChars(pwCopy);
                    }
                }).thenCompose(hashed -> {
                    long now = clock.getAsLong();
                    String storedIpHash = unknownIp ? null : ipHash;
                    return accounts.createAccount(
                            nameLower, username, gameUuid, null, hashed.hash(), hashed.algorithm(),
                            null, false, now, storedIpHash
                    ).thenCompose(created -> {
                        CompletableFuture<Void> sessionFuture = (s.sessionsEnabled() && !unknownIp)
                                ? sessions.upsert(created.id(), ipHash, now + s.sessionDurationSeconds() * 1000L)
                                : CompletableFuture.completedFuture(null);
                        CompletableFuture<Void> auditFuture = audit.record(now, actor, "REGISTER", nameLower, null);
                        return CompletableFuture.allOf(sessionFuture, auditFuture)
                                .thenApply(v -> new RegisterResult(Status.SUCCESS, created, null, 0));
                    });
                }).exceptionally(ex -> {
                    if (isBusy(ex)) {
                        return new RegisterResult(Status.HASHING_BUSY, null, null, 2);
                    }
                    if (ex instanceof RuntimeException re) throw re;
                    throw new RuntimeException(ex);
                });
            });
        });
    }

    public CompletableFuture<LoginResult> login(String username, char[] rawPassword, String ip) {
        return login(username, rawPassword, ip, false);
    }

    public CompletableFuture<LoginResult> login(String username, char[] rawPassword, String ip, boolean floodgateClient) {
        CoreSettings s = settingsSupplier.get();
        if (!UsernameValidator.isValid(username, s.usernamePattern(), floodgateClient)) {
            clearChars(rawPassword);
            return CompletableFuture.completedFuture(new LoginResult(Status.INVALID_USERNAME, null, 0));
        }
        String nameLower = UsernameValidator.normalizeLower(username);
        boolean unknownIp = IpHmac.isUnknownIp(ip);
        String ipHash = hashIp(ip);

        // Threat model #6 & P0-4: reserve attempt in rate-limiter BEFORE password hashing
        LoginRateLimiter.Decision rl = rateLimiter.tryAcquire(nameLower, ipHash, s);
        if (!rl.allowed()) {
            clearChars(rawPassword);
            return CompletableFuture.completedFuture(new LoginResult(Status.RATE_LIMITED, null, rl.retryAfterSeconds()));
        }

        char[] pwCopy = rawPassword.clone();
        clearChars(rawPassword);

        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) {
                clearChars(pwCopy);
                rateLimiter.recordFailure(nameLower, ipHash, s);
                return CompletableFuture.completedFuture(new LoginResult(Status.NOT_REGISTERED, null, 0));
            }
            Account acc = found.get();
            if (!acc.hasPassword()) {
                clearChars(pwCopy);
                rateLimiter.recordFailure(nameLower, ipHash, s);
                return CompletableFuture.completedFuture(new LoginResult(Status.INVALID_CREDENTIALS, null, 0));
            }
            PasswordHasher hasher = new PasswordHasher(s);
            return hashing.submitForKey(ipHash, () -> {
                try {
                    PasswordHasher.VerifyResult vr = hasher.verify(pwCopy, acc.passwordHash(), acc.hashAlgo());
                    String upgradedHash = vr.valid() && vr.needsRehash() ? hasher.hash(pwCopy).hash() : null;
                    return new VerificationOutcome(vr.valid(), upgradedHash);
                } finally {
                    clearChars(pwCopy);
                }
            }).thenCompose(outcome -> {
                if (!outcome.valid()) {
                    boolean lockedOut = rateLimiter.recordFailure(nameLower, ipHash, s);
                    if (lockedOut) {
                        LoginRateLimiter.Decision post = rateLimiter.check(nameLower, ipHash, s);
                        if (!post.allowed()) {
                            return CompletableFuture.completedFuture(new LoginResult(Status.RATE_LIMITED, null, post.retryAfterSeconds()));
                        }
                    }
                    return CompletableFuture.completedFuture(new LoginResult(Status.INVALID_CREDENTIALS, null, 0));
                }

                rateLimiter.recordSuccess(nameLower, ipHash);
                long now = clock.getAsLong();
                // P1-1: updatePasswordHashOnly preserves force_password_change during transparent rehash
                CompletableFuture<Void> rehashFuture = outcome.upgradedHash() != null
                        ? accounts.updatePasswordHashOnly(acc.id(), outcome.upgradedHash(), HashAlgorithm.ARGON2ID, now)
                        : CompletableFuture.completedFuture(null);

                return rehashFuture.thenCompose(v -> {
                    if (acc.hasTotp()) {
                        return CompletableFuture.completedFuture(new LoginResult(Status.NEEDS_2FA, acc, 0));
                    }
                    if (acc.forcePasswordChange()) {
                        return CompletableFuture.completedFuture(new LoginResult(Status.NEEDS_PASSWORD_CHANGE, acc, 0));
                    }
                    return completeLoginSuccess(acc, username, unknownIp ? null : ipHash, s, now)
                            .thenApply(v2 -> new LoginResult(Status.SUCCESS, acc, 0));
                });
            }).exceptionally(ex -> {
                rateLimiter.releaseInFlight(nameLower, ipHash);
                if (isBusy(ex)) {
                    return new LoginResult(Status.HASHING_BUSY, null, 2);
                }
                if (ex instanceof RuntimeException re) throw re;
                throw new RuntimeException(ex);
            });
        }).exceptionally(ex -> {
            rateLimiter.releaseInFlight(nameLower, ipHash);
            if (ex instanceof RuntimeException re) throw re;
            throw new RuntimeException(ex);
        });
    }

    public CompletableFuture<LoginResult> verifyTotp(String username, String codeOrBackup, String ip) {
        CoreSettings s = settingsSupplier.get();
        String nameLower = UsernameValidator.normalizeLower(username);
        boolean unknownIp = IpHmac.isUnknownIp(ip);
        String ipHash = hashIp(ip);

        LoginRateLimiter.Decision rl = rateLimiter.check(nameLower, ipHash, s);
        if (!rl.allowed()) {
            return CompletableFuture.completedFuture(new LoginResult(Status.RATE_LIMITED, null, rl.retryAfterSeconds()));
        }

        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) {
                return CompletableFuture.completedFuture(new LoginResult(Status.NOT_REGISTERED, null, 0));
            }
            Account acc = found.get();
            if (!acc.hasTotp() || acc.totpSecretEncrypted() == null) {
                return CompletableFuture.completedFuture(new LoginResult(Status.TOTP_NOT_ENABLED, acc, 0));
            }

            final String secret;
            try {
                secret = AesGcmCrypto.decrypt(secrets.totpKey(), acc.totpSecretEncrypted());
            } catch (RuntimeException e) {
                return CompletableFuture.completedFuture(new LoginResult(Status.TOTP_DECRYPT_ERROR, acc, 0));
            }
            long now = clock.getAsLong();
            TotpService.VerifyResult tr = TotpService.verifyCode(
                    secret, codeOrBackup, now / 1000L, acc.totpLastStep(), s.totpWindowSteps());

            if (tr.valid()) {
                // P1-2: Atomically consume the matched TOTP step in DB so concurrent requests cannot replay it
                return accounts.tryAdvanceTotpStep(acc.id(), tr.matchedStep(), now).thenCompose(advanced -> {
                    if (!advanced) {
                        rateLimiter.recordFailure(nameLower, ipHash, s);
                        return CompletableFuture.completedFuture(new LoginResult(Status.INVALID_CODE, null, 0));
                    }
                    rateLimiter.recordSuccess(nameLower, ipHash);
                    if (acc.forcePasswordChange()) {
                        return CompletableFuture.completedFuture(new LoginResult(Status.NEEDS_PASSWORD_CHANGE, acc, 0));
                    }
                    return completeLoginSuccess(acc, username, unknownIp ? null : ipHash, s, now)
                            .thenApply(v2 -> new LoginResult(Status.SUCCESS, acc, 0));
                });
            }

            // Try single-use backup code
            return backupCodes.consumeMatching(acc.id(),
                    storedHash -> TotpService.matchesBackupCode(secrets.hmacKey(), codeOrBackup, storedHash))
                    .thenCompose(consumed -> {
                        if (!consumed) {
                            rateLimiter.recordFailure(nameLower, ipHash, s);
                            LoginRateLimiter.Decision post = rateLimiter.check(nameLower, ipHash, s);
                            return CompletableFuture.completedFuture(post.allowed()
                                    ? new LoginResult(Status.INVALID_CODE, null, 0)
                                    : new LoginResult(Status.RATE_LIMITED, null, post.retryAfterSeconds()));
                        }
                        rateLimiter.recordSuccess(nameLower, ipHash);
                        return audit.record(now, nameLower, "TOTP_BACKUP_USED", nameLower, null).thenCompose(v -> {
                            if (acc.forcePasswordChange()) {
                                return CompletableFuture.completedFuture(new LoginResult(Status.NEEDS_PASSWORD_CHANGE, acc, 0));
                            }
                            return completeLoginSuccess(acc, username, unknownIp ? null : ipHash, s, now)
                                    .thenApply(v2 -> new LoginResult(Status.SUCCESS, acc, 0));
                        });
                    });
        });
    }

    public CompletableFuture<SimpleResult> changePassword(
            String username, char[] oldPassword, char[] newPassword, String actor, boolean skipOldCheck) {
        return changePassword(username, oldPassword, newPassword, "local", actor, skipOldCheck);
    }

    public CompletableFuture<SimpleResult> changePassword(
            String username, char[] oldPassword, char[] newPassword, String ip, String actor, boolean skipOldCheck) {
        CoreSettings s = settingsSupplier.get();
        String nameLower = UsernameValidator.normalizeLower(username);
        String ipHash = hashIp(ip);

        if (!skipOldCheck) {
            LoginRateLimiter.Decision rl = rateLimiter.tryAcquire(nameLower, ipHash, s);
            if (!rl.allowed()) {
                clearChars(oldPassword);
                clearChars(newPassword);
                return CompletableFuture.completedFuture(SimpleResult.rateLimited(rl.retryAfterSeconds()));
            }
        }

        PasswordPolicy.Violation violation = PasswordPolicy.validate(newPassword, username, s);
        if (violation != null) {
            if (!skipOldCheck) rateLimiter.releaseInFlight(nameLower, ipHash);
            clearChars(oldPassword);
            clearChars(newPassword);
            return CompletableFuture.completedFuture(new SimpleResult(Status.PASSWORD_POLICY_VIOLATION, violation));
        }

        char[] oldCopy = oldPassword == null ? null : oldPassword.clone();
        char[] newCopy = newPassword.clone();
        clearChars(oldPassword);
        clearChars(newPassword);

        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) {
                if (!skipOldCheck) rateLimiter.releaseInFlight(nameLower, ipHash);
                clearChars(oldCopy);
                clearChars(newCopy);
                return CompletableFuture.completedFuture(SimpleResult.of(Status.NOT_REGISTERED));
            }
            Account acc = found.get();
            PasswordHasher hasher = new PasswordHasher(s);
            return hashing.submitForKey(skipOldCheck ? null : ipHash, () -> {
                try {
                    if (!skipOldCheck) {
                        if (oldCopy == null || !acc.hasPassword()) return null;
                        PasswordHasher.VerifyResult vr = hasher.verify(oldCopy, acc.passwordHash(), acc.hashAlgo());
                        if (!vr.valid()) return null;
                    }
                    return hasher.hash(newCopy);
                } finally {
                    clearChars(oldCopy);
                    clearChars(newCopy);
                }
            }).thenCompose(hashed -> {
                if (hashed == null) {
                    if (!skipOldCheck) rateLimiter.recordFailure(nameLower, ipHash, s);
                    return CompletableFuture.completedFuture(SimpleResult.of(Status.INVALID_CREDENTIALS));
                }
                if (!skipOldCheck) rateLimiter.recordSuccess(nameLower, ipHash);
                long now = clock.getAsLong();
                return accounts.updatePasswordAndClearForce(acc.id(), hashed.hash(), hashed.algorithm(), now)
                        .thenCompose(v -> sessions.invalidate(acc.id()))
                        .thenCompose(v -> audit.record(now, actor, skipOldCheck ? "ADMIN_CHANGE_PASSWORD" : "CHANGE_PASSWORD", nameLower, null))
                        .thenApply(v -> SimpleResult.ok());
            }).exceptionally(ex -> {
                if (!skipOldCheck) rateLimiter.releaseInFlight(nameLower, ipHash);
                if (isBusy(ex)) return SimpleResult.of(Status.HASHING_BUSY);
                if (ex instanceof RuntimeException re) throw re;
                throw new RuntimeException(ex);
            });
        });
    }

    public CompletableFuture<SimpleResult> unregister(String username, char[] password, String actor) {
        return unregister(username, password, "local", actor);
    }

    public CompletableFuture<SimpleResult> unregister(String username, char[] password, String ip, String actor) {
        CoreSettings s = settingsSupplier.get();
        String nameLower = UsernameValidator.normalizeLower(username);
        String ipHash = hashIp(ip);
        LoginRateLimiter.Decision rl = rateLimiter.tryAcquire(nameLower, ipHash, s);
        if (!rl.allowed()) {
            clearChars(password);
            return CompletableFuture.completedFuture(SimpleResult.rateLimited(rl.retryAfterSeconds()));
        }

        char[] pwCopy = password.clone();
        clearChars(password);

        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) {
                rateLimiter.releaseInFlight(nameLower, ipHash);
                clearChars(pwCopy);
                return CompletableFuture.completedFuture(SimpleResult.of(Status.NOT_REGISTERED));
            }
            Account acc = found.get();
            if (!acc.hasPassword()) {
                rateLimiter.releaseInFlight(nameLower, ipHash);
                clearChars(pwCopy);
                return CompletableFuture.completedFuture(SimpleResult.of(Status.PREMIUM_CANNOT_UNREGISTER_WITHOUT_PASSWORD));
            }
            PasswordHasher hasher = new PasswordHasher(s);
            return hashing.submitForKey(ipHash, () -> {
                try {
                    return hasher.verify(pwCopy, acc.passwordHash(), acc.hashAlgo()).valid();
                } finally {
                    clearChars(pwCopy);
                }
            }).thenCompose(ok -> {
                if (!ok) {
                    rateLimiter.recordFailure(nameLower, ipHash, s);
                    return CompletableFuture.completedFuture(SimpleResult.of(Status.INVALID_CREDENTIALS));
                }
                rateLimiter.recordSuccess(nameLower, ipHash);
                long now = clock.getAsLong();
                return accounts.deleteById(acc.id())
                        .thenCompose(d -> audit.record(now, actor, "UNREGISTER", nameLower, null))
                        .thenApply(v -> SimpleResult.ok());
            }).exceptionally(ex -> {
                rateLimiter.releaseInFlight(nameLower, ipHash);
                if (isBusy(ex)) return SimpleResult.of(Status.HASHING_BUSY);
                if (ex instanceof RuntimeException re) throw re;
                throw new RuntimeException(ex);
            });
        });
    }

    public CompletableFuture<SimpleResult> adminUnregister(String username, String actor) {
        String nameLower = UsernameValidator.normalizeLower(username);
        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) return CompletableFuture.completedFuture(SimpleResult.of(Status.NOT_REGISTERED));
            long now = clock.getAsLong();
            return accounts.deleteById(found.get().id())
                    .thenCompose(d -> audit.record(now, actor, "ADMIN_UNREGISTER", nameLower, null))
                    .thenApply(v -> SimpleResult.ok());
        });
    }

    public CompletableFuture<Void> logout(String username, String actor) {
        String nameLower = UsernameValidator.normalizeLower(username);
        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) return CompletableFuture.completedFuture(null);
            long now = clock.getAsLong();
            return sessions.invalidate(found.get().id())
                    .thenCompose(v -> audit.record(now, actor, "LOGOUT", nameLower, null));
        });
    }

    public CompletableFuture<TotpSetupData> beginTotpSetup(String username) {
        CoreSettings s = settingsSupplier.get();
        String nameLower = UsernameValidator.normalizeLower(username);
        return accounts.findByNameLower(nameLower).thenApply(found -> {
            if (found.isEmpty()) return new TotpSetupData(Status.NOT_REGISTERED, null, null);
            Account acc = found.get();
            if (acc.hasTotp()) return new TotpSetupData(Status.TOTP_ALREADY_ENABLED, null, null);
            String secret = TotpService.generateSecret();
            String uri = TotpService.provisioningUri(s.totpIssuer(), acc.lastName(), secret);
            return new TotpSetupData(Status.SUCCESS, secret, uri);
        });
    }

    public CompletableFuture<TotpConfirmResult> confirmTotpSetup(String username, String secret, String code, String actor) {
        CoreSettings s = settingsSupplier.get();
        String nameLower = UsernameValidator.normalizeLower(username);
        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) return CompletableFuture.completedFuture(new TotpConfirmResult(Status.NOT_REGISTERED, List.of()));
            Account acc = found.get();
            if (acc.hasTotp()) return CompletableFuture.completedFuture(new TotpConfirmResult(Status.TOTP_ALREADY_ENABLED, List.of()));

            long now = clock.getAsLong();
            TotpService.VerifyResult tr = TotpService.verifyCode(secret, code, now / 1000L, -1L, s.totpWindowSteps());
            if (!tr.valid()) {
                return CompletableFuture.completedFuture(new TotpConfirmResult(Status.INVALID_CODE, List.of()));
            }
            String encrypted = AesGcmCrypto.encrypt(secrets.totpKey(), secret);
            List<String> backup = TotpService.generateBackupCodes(8);
            List<String> hashes = backup.stream().map(c -> TotpService.hashBackupCode(secrets.hmacKey(), c)).toList();

            return accounts.setTotpSecret(acc.id(), encrypted, tr.matchedStep(), now)
                    .thenCompose(v -> backupCodes.replaceAll(acc.id(), hashes, now))
                    .thenCompose(v -> audit.record(now, actor, "TOTP_ENABLE", nameLower, null))
                    .thenApply(v -> new TotpConfirmResult(Status.SUCCESS, backup));
        });
    }

    public CompletableFuture<SimpleResult> disableTotp(String username, String codeOrBackup, String actor) {
        return disableTotp(username, codeOrBackup, "local", actor);
    }

    public CompletableFuture<SimpleResult> disableTotp(String username, String codeOrBackup, String ip, String actor) {
        CoreSettings s = settingsSupplier.get();
        String nameLower = UsernameValidator.normalizeLower(username);
        String ipHash = hashIp(ip);
        LoginRateLimiter.Decision rl = rateLimiter.check(nameLower, ipHash, s);
        if (!rl.allowed()) {
            return CompletableFuture.completedFuture(SimpleResult.rateLimited(rl.retryAfterSeconds()));
        }

        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) return CompletableFuture.completedFuture(SimpleResult.of(Status.NOT_REGISTERED));
            Account acc = found.get();
            if (!acc.hasTotp() || acc.totpSecretEncrypted() == null) {
                return CompletableFuture.completedFuture(SimpleResult.of(Status.TOTP_NOT_ENABLED));
            }
            final String secret;
            try {
                secret = AesGcmCrypto.decrypt(secrets.totpKey(), acc.totpSecretEncrypted());
            } catch (RuntimeException e) {
                return CompletableFuture.completedFuture(SimpleResult.of(Status.TOTP_DECRYPT_ERROR));
            }
            long now = clock.getAsLong();
            TotpService.VerifyResult tr = TotpService.verifyCode(
                    secret, codeOrBackup, now / 1000L, acc.totpLastStep(), s.totpWindowSteps());

            CompletableFuture<Boolean> verified = tr.valid()
                    ? accounts.tryAdvanceTotpStep(acc.id(), tr.matchedStep(), now)
                    : backupCodes.consumeMatching(acc.id(),
                            h -> TotpService.matchesBackupCode(secrets.hmacKey(), codeOrBackup, h));

            return verified.thenCompose(ok -> {
                if (!ok) {
                    rateLimiter.recordFailure(nameLower, ipHash, s);
                    return CompletableFuture.completedFuture(SimpleResult.of(Status.INVALID_CODE));
                }
                rateLimiter.recordSuccess(nameLower, ipHash);
                return accounts.setTotpSecret(acc.id(), null, -1L, now)
                        .thenCompose(v -> backupCodes.replaceAll(acc.id(), List.of(), now))
                        .thenCompose(v -> audit.record(now, actor, "TOTP_DISABLE", nameLower, null))
                        .thenApply(v -> SimpleResult.ok());
            });
        });
    }

    public CompletableFuture<SimpleResult> adminResetTotp(String username, String actor) {
        String nameLower = UsernameValidator.normalizeLower(username);
        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) return CompletableFuture.completedFuture(SimpleResult.of(Status.NOT_REGISTERED));
            Account acc = found.get();
            long now = clock.getAsLong();
            return accounts.setTotpSecret(acc.id(), null, -1L, now)
                    .thenCompose(v -> backupCodes.replaceAll(acc.id(), List.of(), now))
                    .thenCompose(v -> audit.record(now, actor, "ADMIN_RESET_2FA", nameLower, null))
                    .thenApply(v -> SimpleResult.ok());
        });
    }

    public CompletableFuture<SimpleResult> requestPremium(String username, String actor) {
        String nameLower = UsernameValidator.normalizeLower(username);
        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) return CompletableFuture.completedFuture(SimpleResult.of(Status.NOT_REGISTERED));
            Account acc = found.get();
            if (acc.isPremiumConfirmed()) {
                return CompletableFuture.completedFuture(SimpleResult.of(Status.ALREADY_PREMIUM));
            }
            long now = clock.getAsLong();
            return accounts.setPremiumPending(acc.id(), true, now)
                    .thenCompose(v -> audit.record(now, actor, "REQUEST_PREMIUM", nameLower, null))
                    .thenApply(v -> SimpleResult.ok());
        });
    }

    public CompletableFuture<SimpleResult> setCracked(String username, String actor) {
        String nameLower = UsernameValidator.normalizeLower(username);
        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) return CompletableFuture.completedFuture(SimpleResult.of(Status.NOT_REGISTERED));
            Account acc = found.get();
            if (!acc.hasPassword()) {
                return CompletableFuture.completedFuture(SimpleResult.of(Status.PASSWORD_REQUIRED_FOR_CRACKED));
            }
            long now = clock.getAsLong();
            return accounts.setPremiumStatus(acc.id(), false, false, now)
                    .thenCompose(v -> audit.record(now, actor, "SET_CRACKED", nameLower, null))
                    .thenApply(v -> SimpleResult.ok());
        });
    }

    /**
     * P0-2 fix: {@code /unpremium <newPassword>} is ONLY permitted when the account does not yet have a password
     * (e.g., an auto-registered premium account switching to password login). If the account already has a password,
     * returns {@link Status#PASSWORD_ALREADY_SET} so an attacker cannot overwrite the password without knowing the old one.
     */
    public CompletableFuture<SimpleResult> setCrackedWithInitialPassword(
            String username, char[] newPassword, String ip, String actor) {
        CoreSettings s = settingsSupplier.get();
        String nameLower = UsernameValidator.normalizeLower(username);
        String ipHash = hashIp(ip);

        PasswordPolicy.Violation violation = PasswordPolicy.validate(newPassword, username, s);
        if (violation != null) {
            clearChars(newPassword);
            return CompletableFuture.completedFuture(new SimpleResult(Status.PASSWORD_POLICY_VIOLATION, violation));
        }

        char[] pwCopy = newPassword.clone();
        clearChars(newPassword);

        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) {
                clearChars(pwCopy);
                return CompletableFuture.completedFuture(SimpleResult.of(Status.NOT_REGISTERED));
            }
            Account acc = found.get();
            if (acc.hasPassword()) {
                clearChars(pwCopy);
                return CompletableFuture.completedFuture(SimpleResult.of(Status.PASSWORD_ALREADY_SET));
            }
            PasswordHasher hasher = new PasswordHasher(s);
            return hashing.submitForKey(ipHash, () -> {
                try {
                    return hasher.hash(pwCopy);
                } finally {
                    clearChars(pwCopy);
                }
            }).thenCompose(hashed -> {
                long now = clock.getAsLong();
                return accounts.updatePasswordAndClearForce(acc.id(), hashed.hash(), hashed.algorithm(), now)
                        .thenCompose(v -> accounts.setPremiumStatus(acc.id(), false, false, now))
                        .thenCompose(v -> sessions.invalidate(acc.id()))
                        .thenCompose(v -> audit.record(now, actor, "SET_CRACKED", nameLower, "initial_password_set"))
                        .thenApply(v -> SimpleResult.ok());
            }).exceptionally(ex -> {
                if (isBusy(ex)) return SimpleResult.of(Status.HASHING_BUSY);
                if (ex instanceof RuntimeException re) throw re;
                throw new RuntimeException(ex);
            });
        });
    }

    public CompletableFuture<SimpleResult> adminSetPremium(String username, boolean premium, String actor) {
        String nameLower = UsernameValidator.normalizeLower(username);
        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) return CompletableFuture.completedFuture(SimpleResult.of(Status.NOT_REGISTERED));
            long now = clock.getAsLong();
            return accounts.setPremiumStatus(found.get().id(), premium, false, now)
                    .thenCompose(v -> audit.record(now, actor, "ADMIN_SET_PREMIUM", nameLower, "premium=" + premium))
                    .thenApply(v -> SimpleResult.ok());
        });
    }

    public CompletableFuture<SimpleResult> adminSetForcePasswordChange(String username, boolean force, String actor) {
        String nameLower = UsernameValidator.normalizeLower(username);
        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) return CompletableFuture.completedFuture(SimpleResult.of(Status.NOT_REGISTERED));
            long now = clock.getAsLong();
            return accounts.setForcePasswordChange(found.get().id(), force, now)
                    .thenCompose(v -> audit.record(now, actor, "FORCE_PW_CHANGE", nameLower, "force=" + force))
                    .thenApply(v -> SimpleResult.ok());
        });
    }

    public CompletableFuture<SimpleResult> renameAccount(String oldName, String newName, String actor) {
        CoreSettings s = settingsSupplier.get();
        if (!UsernameValidator.isValid(newName, s.usernamePattern())) {
            return CompletableFuture.completedFuture(SimpleResult.of(Status.INVALID_USERNAME));
        }
        String oldLower = UsernameValidator.normalizeLower(oldName);
        String newLower = UsernameValidator.normalizeLower(newName);
        if (oldLower.equals(newLower)) {
            return CompletableFuture.completedFuture(SimpleResult.of(Status.TARGET_ALREADY_EXISTS));
        }
        return accounts.findByNameLower(oldLower).thenCompose(found -> {
            if (found.isEmpty()) return CompletableFuture.completedFuture(SimpleResult.of(Status.NOT_REGISTERED));
            long now = clock.getAsLong();
            return accounts.renameAccount(found.get().id(), newLower, newName, now).thenCompose(renamed -> {
                if (!renamed) return CompletableFuture.completedFuture(SimpleResult.of(Status.TARGET_ALREADY_EXISTS));
                return audit.record(now, actor, "ADMIN_RENAME", newLower, "from=" + oldLower)
                        .thenApply(v -> SimpleResult.ok());
            });
        });
    }

    public CompletableFuture<SimpleResult> mergeAccounts(String sourceName, String targetName, String actor) {
        String srcLower = UsernameValidator.normalizeLower(sourceName);
        String dstLower = UsernameValidator.normalizeLower(targetName);
        if (srcLower.equals(dstLower)) {
            return CompletableFuture.completedFuture(SimpleResult.of(Status.CANNOT_MERGE_SELF));
        }
        return accounts.findByNameLower(srcLower).thenCompose(srcOpt -> {
            if (srcOpt.isEmpty()) return CompletableFuture.completedFuture(SimpleResult.of(Status.NOT_REGISTERED));
            return accounts.findByNameLower(dstLower).thenCompose(dstOpt -> {
                if (dstOpt.isEmpty()) return CompletableFuture.completedFuture(SimpleResult.of(Status.NOT_REGISTERED));
                long now = clock.getAsLong();
                return accounts.mergeAccounts(srcOpt.get().id(), dstOpt.get().id(), now).thenCompose(merged -> {
                    if (merged.isEmpty()) return CompletableFuture.completedFuture(SimpleResult.of(Status.NOT_REGISTERED));
                    return audit.record(now, actor, "ADMIN_MERGE", dstLower, "absorbed=" + srcLower)
                            .thenApply(v -> SimpleResult.ok());
                });
            });
        });
    }

    public CompletableFuture<Void> recordSuccessfulSession(Account acc, String lastName, String ip) {
        CoreSettings s = settingsSupplier.get();
        boolean unknownIp = IpHmac.isUnknownIp(ip);
        String ipHash = unknownIp ? null : hashIp(ip);
        long now = clock.getAsLong();
        return completeLoginSuccess(acc, lastName, ipHash, s, now);
    }

    public CompletableFuture<Integer> maintenanceCleanup() {
        rateLimiter.pruneExpired(300_000L);
        long now = clock.getAsLong();
        CoreSettings s = settingsSupplier.get();
        CompletableFuture<Integer> auditClean = s.auditRetentionDays() > 0
                ? audit.pruneOlderThan(now - s.auditRetentionDays() * 86_400_000L)
                : CompletableFuture.completedFuture(0);
        return sessions.pruneExpired(now).thenCombine(auditClean, Integer::sum);
    }

    private CompletableFuture<Void> completeLoginSuccess(
            Account acc, String lastName, @Nullable String ipHash, CoreSettings s, long now) {
        CompletableFuture<Void> upd = accounts.updateLoginSuccess(acc.id(), lastName, ipHash, now);
        if (!s.sessionsEnabled() || ipHash == null) return upd;
        return upd.thenCompose(v -> sessions.upsert(acc.id(), ipHash, now + s.sessionDurationSeconds() * 1000L));
    }

    private static boolean isBusy(Throwable ex) {
        Throwable cur = ex;
        while (cur != null) {
            if (cur instanceof HashingExecutor.HashingBusyException) return true;
            cur = cur.getCause();
        }
        return false;
    }

    private static void clearChars(char[] chars) {
        if (chars != null) Arrays.fill(chars, '\0');
    }

    private record VerificationOutcome(boolean valid, @Nullable String upgradedHash) {
    }
}

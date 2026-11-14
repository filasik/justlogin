package me.skerik.justlogin.core.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import me.skerik.justlogin.core.crypto.HashingExecutor;
import me.skerik.justlogin.core.crypto.IpHmac;
import me.skerik.justlogin.core.crypto.PasswordHasher;
import me.skerik.justlogin.core.crypto.ServerSecrets;
import me.skerik.justlogin.core.model.Account;
import me.skerik.justlogin.core.model.CoreSettings;
import me.skerik.justlogin.core.model.HashAlgorithm;
import me.skerik.justlogin.core.model.SmtpConfig;
import me.skerik.justlogin.core.security.LoginRateLimiter;
import me.skerik.justlogin.core.security.PasswordPolicy;
import me.skerik.justlogin.core.security.UsernameValidator;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import me.skerik.justlogin.core.storage.SessionStore;
import org.jspecify.annotations.Nullable;

/** Manages optional email address binding and single-use HMAC-protected recovery codes. */
public final class EmailRecoveryService {

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)+$");
    private static final char[] CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();
    private static final SecureRandom RNG = new SecureRandom();

    public enum Status {
        SUCCESS,
        CONFIRMATION_SENT,
        DISABLED,
        INVALID_EMAIL,
        INVALID_CREDENTIALS,
        NO_PASSWORD_SET,
        NOT_REGISTERED,
        NO_EMAIL,
        COOLDOWN,
        RATE_LIMITED,
        INVALID_OR_EXPIRED_CODE,
        PASSWORD_POLICY_VIOLATION,
        HASHING_BUSY,
        SEND_FAILED
    }

    private record PendingEmailConfirmation(String email, String codeHash, long expiresAt) {
    }

    public record RecoveryResult(Status status, PasswordPolicy.@Nullable Violation violation, long waitSeconds) {
        public static RecoveryResult of(Status status) {
            return new RecoveryResult(status, null, 0L);
        }

        public static RecoveryResult wait(Status status, long seconds) {
            return new RecoveryResult(status, null, seconds);
        }
    }

    private final AccountStore accounts;
    private final SessionStore sessions;
    private final AuditStore audit;
    private final ServerSecrets secrets;
    private final HashingExecutor hashing;
    private final LoginRateLimiter rateLimiter;
    private final EmailSender sender;
    private final Supplier<CoreSettings> coreSupplier;
    private final Supplier<SmtpConfig> smtpSupplier;
    private final LongSupplier clock;
    private final Map<Long, Long> cooldownUntil = new ConcurrentHashMap<>();
    private final Map<Long, PendingEmailConfirmation> pendingConfirmations = new ConcurrentHashMap<>();

    public EmailRecoveryService(
            AccountStore accounts,
            SessionStore sessions,
            AuditStore audit,
            ServerSecrets secrets,
            HashingExecutor hashing,
            LoginRateLimiter rateLimiter,
            EmailSender sender,
            Supplier<CoreSettings> coreSupplier,
            Supplier<SmtpConfig> smtpSupplier,
            LongSupplier clock
    ) {
        this.accounts = accounts;
        this.sessions = sessions;
        this.audit = audit;
        this.secrets = secrets;
        this.hashing = hashing;
        this.rateLimiter = rateLimiter;
        this.sender = sender;
        this.coreSupplier = coreSupplier;
        this.smtpSupplier = smtpSupplier;
        this.clock = clock;
    }

    public static boolean isValidEmail(String raw) {
        if (raw == null) return false;
        String trimmed = raw.trim();
        if (trimmed.isEmpty() || trimmed.length() > 254) return false;
        if (trimmed.indexOf('\r') >= 0 || trimmed.indexOf('\n') >= 0) return false;
        return EMAIL_PATTERN.matcher(trimmed).matches();
    }

    public static String maskEmail(@Nullable String email) {
        if (email == null || email.isBlank()) return "-";
        int at = email.indexOf('@');
        if (at <= 1) return "***" + (at >= 0 ? email.substring(at) : "");
        return email.charAt(0) + "***" + email.substring(at);
    }

    public CompletableFuture<RecoveryResult> setEmail(String username, String rawEmail, String actor) {
        SmtpConfig cfg = smtpSupplier.get();
        if (!cfg.enabled()) return CompletableFuture.completedFuture(RecoveryResult.of(Status.DISABLED));
        if (!isValidEmail(rawEmail)) return CompletableFuture.completedFuture(RecoveryResult.of(Status.INVALID_EMAIL));
        String normalized = rawEmail.trim().toLowerCase(Locale.ROOT);
        String nameLower = UsernameValidator.normalizeLower(username);
        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) return CompletableFuture.completedFuture(RecoveryResult.of(Status.NOT_REGISTERED));
            long now = clock.getAsLong();
            return accounts.setEmail(found.get().id(), normalized, now)
                    .thenCompose(v -> audit.record(now, actor, "EMAIL_SET", nameLower, maskEmail(normalized)))
                    .thenApply(v -> RecoveryResult.of(Status.SUCCESS));
        });
    }

    /**
     * P0-3 fix: {@code /email set <address> <password>} requires the player's current password, sends a single-use
     * confirmation code to {@code rawEmail} (activated only after {@code /email confirm <code>}), and notifies
     * the previous email address if one was already bound.
     */
    public CompletableFuture<RecoveryResult> requestSetEmail(
            String username, String rawEmail, char[] currentPassword, String ip, String actor) {
        SmtpConfig cfg = smtpSupplier.get();
        if (!cfg.enabled()) {
            Arrays.fill(currentPassword, '\0');
            return CompletableFuture.completedFuture(RecoveryResult.of(Status.DISABLED));
        }
        if (!isValidEmail(rawEmail)) {
            Arrays.fill(currentPassword, '\0');
            return CompletableFuture.completedFuture(RecoveryResult.of(Status.INVALID_EMAIL));
        }
        CoreSettings cs = coreSupplier.get();
        String nameLower = UsernameValidator.normalizeLower(username);
        String ipHash = IpHmac.hashIp(secrets.hmacKey(), ip);
        LoginRateLimiter.Decision rl = rateLimiter.tryAcquire(nameLower, ipHash, cs);
        if (!rl.allowed()) {
            Arrays.fill(currentPassword, '\0');
            return CompletableFuture.completedFuture(RecoveryResult.wait(Status.RATE_LIMITED, rl.retryAfterSeconds()));
        }
        char[] pwCopy = currentPassword.clone();
        Arrays.fill(currentPassword, '\0');
        String normalized = rawEmail.trim().toLowerCase(Locale.ROOT);

        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) {
                rateLimiter.releaseInFlight(nameLower, ipHash);
                Arrays.fill(pwCopy, '\0');
                return CompletableFuture.completedFuture(RecoveryResult.of(Status.NOT_REGISTERED));
            }
            Account acc = found.get();
            if (!acc.hasPassword()) {
                rateLimiter.releaseInFlight(nameLower, ipHash);
                Arrays.fill(pwCopy, '\0');
                return CompletableFuture.completedFuture(RecoveryResult.of(Status.NO_PASSWORD_SET));
            }
            long now = clock.getAsLong();
            Long until = cooldownUntil.get(acc.id());
            if (until != null && until > now) {
                rateLimiter.releaseInFlight(nameLower, ipHash);
                Arrays.fill(pwCopy, '\0');
                return CompletableFuture.completedFuture(
                        RecoveryResult.wait(Status.COOLDOWN, Math.max(1L, (until - now + 999L) / 1000L)));
            }
            return hashing.submitForKey(ipHash, () -> {
                try {
                    return new PasswordHasher(cs).verify(pwCopy, acc.passwordHash(), acc.hashAlgo()).valid();
                } finally {
                    Arrays.fill(pwCopy, '\0');
                }
            }).thenCompose(validPw -> {
                if (!validPw) {
                    rateLimiter.recordFailure(nameLower, ipHash, cs);
                    return CompletableFuture.completedFuture(RecoveryResult.of(Status.INVALID_CREDENTIALS));
                }
                rateLimiter.recordSuccess(nameLower, ipHash);
                String code = generateCode(8);
                String codeHash = hashCode(acc.id(), "confirm:" + normalized + ":" + code);
                long expiresAt = now + Math.max(60L, cfg.codeTtlSeconds()) * 1000L;
                cooldownUntil.put(acc.id(), now + Math.max(10L, cfg.cooldownSeconds()) * 1000L);
                pendingConfirmations.put(acc.id(), new PendingEmailConfirmation(normalized, codeHash, expiresAt));

                String subject = "[" + cfg.serverDisplayName() + "] Confirm Your Email Address";
                String body = "Hello " + acc.lastName() + ",\n\n"
                        + "Please confirm your email address on " + cfg.serverDisplayName() + ".\n"
                        + "Your confirmation code: " + code + "\n"
                        + "Use in-game: /email confirm " + code + "\n"
                        + "This code expires in " + Math.max(1, cfg.codeTtlSeconds() / 60) + " minute(s).\n\n"
                        + "If you did not request this, you can safely ignore this message.\n";

                String oldEmail = acc.email();
                CompletableFuture<Void> notifyOld = (oldEmail != null && !oldEmail.isBlank() && !oldEmail.equalsIgnoreCase(normalized))
                        ? sender.send(oldEmail,
                                "[" + cfg.serverDisplayName() + "] Security Notice: Email Change Requested",
                                "Hello " + acc.lastName() + ",\n\nA request was made to change the recovery email on your account to "
                                        + maskEmail(normalized) + ".\nIf this was not you, change your password immediately.\n")
                                .exceptionally(ex -> null)
                        : CompletableFuture.completedFuture(null);

                return sender.send(normalized, subject, body)
                        .thenCompose(v -> notifyOld)
                        .thenCompose(v -> audit.record(now, actor, "EMAIL_SET_REQUESTED", nameLower, maskEmail(normalized)))
                        .thenApply(v -> RecoveryResult.of(Status.CONFIRMATION_SENT))
                        .exceptionally(ex -> {
                            pendingConfirmations.remove(acc.id());
                            return RecoveryResult.of(Status.SEND_FAILED);
                        });
            }).exceptionally(ex -> {
                rateLimiter.releaseInFlight(nameLower, ipHash);
                Throwable cur = ex;
                while (cur != null) {
                    if (cur instanceof HashingExecutor.HashingBusyException) {
                        return RecoveryResult.of(Status.HASHING_BUSY);
                    }
                    cur = cur.getCause();
                }
                throw ex instanceof RuntimeException re ? re : new RuntimeException(ex);
            });
        });
    }

    public CompletableFuture<RecoveryResult> confirmEmail(String username, String rawCode, String ip, String actor) {
        SmtpConfig cfg = smtpSupplier.get();
        if (!cfg.enabled()) return CompletableFuture.completedFuture(RecoveryResult.of(Status.DISABLED));
        CoreSettings cs = coreSupplier.get();
        String nameLower = UsernameValidator.normalizeLower(username);
        String ipHash = IpHmac.hashIp(secrets.hmacKey(), ip);
        LoginRateLimiter.Decision rl = rateLimiter.check(nameLower, ipHash, cs);
        if (!rl.allowed()) {
            return CompletableFuture.completedFuture(RecoveryResult.wait(Status.RATE_LIMITED, rl.retryAfterSeconds()));
        }
        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) return CompletableFuture.completedFuture(RecoveryResult.of(Status.NOT_REGISTERED));
            Account acc = found.get();
            long now = clock.getAsLong();
            PendingEmailConfirmation pending = pendingConfirmations.get(acc.id());
            if (pending == null || pending.expiresAt() < now || rawCode == null || rawCode.isBlank()) {
                if (pending != null && pending.expiresAt() < now) pendingConfirmations.remove(acc.id(), pending);
                rateLimiter.recordFailure(nameLower, ipHash, cs);
                return CompletableFuture.completedFuture(RecoveryResult.of(Status.INVALID_OR_EXPIRED_CODE));
            }
            String actualHash = hashCode(acc.id(), "confirm:" + pending.email() + ":" + rawCode.trim().toUpperCase(Locale.ROOT));
            if (!MessageDigest.isEqual(
                    pending.codeHash().getBytes(StandardCharsets.UTF_8),
                    actualHash.getBytes(StandardCharsets.UTF_8))) {
                rateLimiter.recordFailure(nameLower, ipHash, cs);
                return CompletableFuture.completedFuture(RecoveryResult.of(Status.INVALID_OR_EXPIRED_CODE));
            }
            if (!pendingConfirmations.remove(acc.id(), pending)) {
                return CompletableFuture.completedFuture(RecoveryResult.of(Status.INVALID_OR_EXPIRED_CODE));
            }
            rateLimiter.recordSuccess(nameLower, ipHash);
            return accounts.setEmail(acc.id(), pending.email(), now)
                    .thenCompose(v -> audit.record(now, actor, "EMAIL_SET", nameLower, maskEmail(pending.email())))
                    .thenApply(v -> RecoveryResult.of(Status.SUCCESS));
        });
    }

    public CompletableFuture<RecoveryResult> clearEmail(String username, String actor) {
        String nameLower = UsernameValidator.normalizeLower(username);
        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) return CompletableFuture.completedFuture(RecoveryResult.of(Status.NOT_REGISTERED));
            long now = clock.getAsLong();
            return accounts.setEmail(found.get().id(), null, now)
                    .thenCompose(v -> audit.record(now, actor, "EMAIL_CLEAR", nameLower, null))
                    .thenApply(v -> RecoveryResult.of(Status.SUCCESS));
        });
    }

    public CompletableFuture<RecoveryResult> requestRecovery(String username, String ip) {
        SmtpConfig cfg = smtpSupplier.get();
        if (!cfg.enabled()) return CompletableFuture.completedFuture(RecoveryResult.of(Status.DISABLED));
        CoreSettings cs = coreSupplier.get();
        String nameLower = UsernameValidator.normalizeLower(username);
        String ipHash = IpHmac.hashIp(secrets.hmacKey(), ip);
        LoginRateLimiter.Decision rl = rateLimiter.check(nameLower, ipHash, cs);
        if (!rl.allowed()) {
            return CompletableFuture.completedFuture(RecoveryResult.wait(Status.RATE_LIMITED, rl.retryAfterSeconds()));
        }
        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) return CompletableFuture.completedFuture(RecoveryResult.of(Status.NOT_REGISTERED));
            Account acc = found.get();
            if (acc.email() == null || acc.email().isBlank()) {
                return CompletableFuture.completedFuture(RecoveryResult.of(Status.NO_EMAIL));
            }
            long now = clock.getAsLong();
            Long until = cooldownUntil.get(acc.id());
            if (until != null && until > now) {
                return CompletableFuture.completedFuture(
                        RecoveryResult.wait(Status.COOLDOWN, Math.max(1L, (until - now + 999L) / 1000L)));
            }
            String code = generateCode(8);
            String hash = hashCode(acc.id(), code);
            long expiresAt = now + Math.max(60L, cfg.codeTtlSeconds()) * 1000L;
            cooldownUntil.put(acc.id(), now + Math.max(10L, cfg.cooldownSeconds()) * 1000L);

            String subject = "[" + cfg.serverDisplayName() + "] Password Recovery Code";
            String body = "Hello " + acc.lastName() + ",\n\n"
                    + "Someone requested a password reset on " + cfg.serverDisplayName() + ".\n"
                    + "Your single-use recovery code: " + code + "\n"
                    + "Use in-game: /email recover " + acc.lastName() + " " + code + " <newPassword>\n"
                    + "This code expires in " + Math.max(1, cfg.codeTtlSeconds() / 60) + " minute(s).\n\n"
                    + "If you did not request this, you can safely ignore this message.\n";

            return accounts.setRecoveryCode(acc.id(), hash, expiresAt, now)
                    .thenCompose(v -> sender.send(acc.email(), subject, body)
                            .thenCompose(ignored -> audit.record(now, "recovery", "EMAIL_RECOVERY_SENT", nameLower, null))
                            .thenApply(ignored -> RecoveryResult.of(Status.SUCCESS))
                            .exceptionallyCompose(ex -> accounts.setRecoveryCode(acc.id(), null, 0L, clock.getAsLong())
                                    .thenApply(ignored2 -> RecoveryResult.of(Status.SEND_FAILED))));
        });
    }

    public CompletableFuture<RecoveryResult> completeRecovery(
            String username, String rawCode, char[] newPassword, String ip) {
        SmtpConfig cfg = smtpSupplier.get();
        if (!cfg.enabled()) {
            Arrays.fill(newPassword, '\0');
            return CompletableFuture.completedFuture(RecoveryResult.of(Status.DISABLED));
        }
        CoreSettings cs = coreSupplier.get();
        String nameLower = UsernameValidator.normalizeLower(username);
        String ipHash = IpHmac.hashIp(secrets.hmacKey(), ip);
        LoginRateLimiter.Decision rl = rateLimiter.check(nameLower, ipHash, cs);
        if (!rl.allowed()) {
            Arrays.fill(newPassword, '\0');
            return CompletableFuture.completedFuture(RecoveryResult.wait(Status.RATE_LIMITED, rl.retryAfterSeconds()));
        }
        PasswordPolicy.Violation violation = PasswordPolicy.validate(newPassword, username, cs);
        if (violation != null) {
            Arrays.fill(newPassword, '\0');
            return CompletableFuture.completedFuture(new RecoveryResult(Status.PASSWORD_POLICY_VIOLATION, violation, 0L));
        }
        char[] pwCopy = newPassword.clone();
        Arrays.fill(newPassword, '\0');

        return accounts.findByNameLower(nameLower).thenCompose(found -> {
            if (found.isEmpty()) {
                Arrays.fill(pwCopy, '\0');
                return CompletableFuture.completedFuture(RecoveryResult.of(Status.NOT_REGISTERED));
            }
            Account acc = found.get();
            long now = clock.getAsLong();
            if (acc.recoveryCodeHash() == null || acc.recoveryExpiresAt() < now || rawCode == null || rawCode.isBlank()) {
                Arrays.fill(pwCopy, '\0');
                rateLimiter.recordFailure(nameLower, ipHash, cs);
                return CompletableFuture.completedFuture(RecoveryResult.of(Status.INVALID_OR_EXPIRED_CODE));
            }
            String actualHash = hashCode(acc.id(), rawCode.trim().toUpperCase(Locale.ROOT));
            if (!MessageDigest.isEqual(
                    acc.recoveryCodeHash().getBytes(StandardCharsets.UTF_8),
                    actualHash.getBytes(StandardCharsets.UTF_8))) {
                Arrays.fill(pwCopy, '\0');
                rateLimiter.recordFailure(nameLower, ipHash, cs);
                return CompletableFuture.completedFuture(RecoveryResult.of(Status.INVALID_OR_EXPIRED_CODE));
            }
            // P1-2: Atomically consume the recovery code so concurrent requests cannot both succeed
            return accounts.tryConsumeRecoveryCode(acc.id(), actualHash, now).thenCompose(consumed -> {
                if (!consumed) {
                    Arrays.fill(pwCopy, '\0');
                    rateLimiter.recordFailure(nameLower, ipHash, cs);
                    return CompletableFuture.completedFuture(RecoveryResult.of(Status.INVALID_OR_EXPIRED_CODE));
                }
                CompletableFuture<String> hashed = hashing.submitForKey(ipHash, () -> {
                    try {
                        return new PasswordHasher(cs).hash(pwCopy).hash();
                    } finally {
                        Arrays.fill(pwCopy, '\0');
                    }
                });
                return hashed.thenCompose(newHash -> accounts.updatePasswordAndClearForce(acc.id(), newHash, HashAlgorithm.ARGON2ID, now)
                        .thenCompose(v2 -> sessions.invalidate(acc.id()))
                        .thenCompose(v2 -> audit.record(now, username, "EMAIL_RECOVERY_USED", nameLower, null))
                        .thenApply(v2 -> {
                            rateLimiter.recordSuccess(nameLower, ipHash);
                            cooldownUntil.remove(acc.id());
                            return RecoveryResult.of(Status.SUCCESS);
                        }))
                        .exceptionally(ex -> {
                            Throwable cur = ex;
                            while (cur != null) {
                                if (cur instanceof HashingExecutor.HashingBusyException) {
                                    return RecoveryResult.of(Status.HASHING_BUSY);
                                }
                                cur = cur.getCause();
                            }
                            throw ex instanceof RuntimeException re ? re : new RuntimeException(ex);
                        });
            });
        });
    }

    private String hashCode(long accountId, String code) {
        byte[] mac = IpHmac.hmacSha256(secrets.hmacKey(), ("recovery:" + accountId + ":" + code).getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(mac);
    }

    private static String generateCode(int len) {
        char[] out = new char[len];
        for (int i = 0; i < len; i++) {
            out[i] = CODE_ALPHABET[RNG.nextInt(CODE_ALPHABET.length)];
        }
        return new String(out);
    }
}

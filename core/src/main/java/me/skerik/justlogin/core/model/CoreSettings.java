package me.skerik.justlogin.core.model;

import java.util.regex.Pattern;

/** Platform-independent core configuration used by {@code AuthService}, crypto, and proxy components. */
public record CoreSettings(
        Pattern usernamePattern,
        int minPasswordLength,
        int maxPasswordLength,
        boolean rejectUsernameAsPassword,
        boolean rejectCommonPasswords,
        int argon2MemoryKib,
        int argon2Iterations,
        int argon2Parallelism,
        int maxConcurrentHashes,
        int maxQueuedHashes,
        int maxLoginAttemptsPerAccountIp,
        int maxLoginAttemptsPerIp,
        long baseBackoffMillis,
        long lockoutSeconds,
        boolean sessionsEnabled,
        long sessionDurationSeconds,
        String totpIssuer,
        int totpWindowSteps,
        boolean premiumAutoDetect,
        long mojangCacheSeconds,
        int maxAccountsPerIp,
        int auditRetentionDays,
        boolean skinsEnabled,
        boolean skinsRestoreCrackedByName,
        long skinsCacheSeconds
) {

    /** Backwards-compatible 22-arg constructor. */
    public CoreSettings(
            Pattern usernamePattern,
            int minPasswordLength,
            int maxPasswordLength,
            boolean rejectUsernameAsPassword,
            boolean rejectCommonPasswords,
            int argon2MemoryKib,
            int argon2Iterations,
            int argon2Parallelism,
            int maxConcurrentHashes,
            int maxQueuedHashes,
            int maxLoginAttemptsPerAccountIp,
            int maxLoginAttemptsPerIp,
            long baseBackoffMillis,
            long lockoutSeconds,
            boolean sessionsEnabled,
            long sessionDurationSeconds,
            String totpIssuer,
            int totpWindowSteps,
            boolean premiumAutoDetect,
            long mojangCacheSeconds,
            int maxAccountsPerIp,
            int auditRetentionDays
    ) {
        this(
                usernamePattern,
                minPasswordLength,
                maxPasswordLength,
                rejectUsernameAsPassword,
                rejectCommonPasswords,
                argon2MemoryKib,
                argon2Iterations,
                argon2Parallelism,
                maxConcurrentHashes,
                maxQueuedHashes,
                maxLoginAttemptsPerAccountIp,
                maxLoginAttemptsPerIp,
                baseBackoffMillis,
                lockoutSeconds,
                sessionsEnabled,
                sessionDurationSeconds,
                totpIssuer,
                totpWindowSteps,
                premiumAutoDetect,
                mojangCacheSeconds,
                maxAccountsPerIp,
                auditRetentionDays,
                true,
                true,
                600L
        );
    }

    public CoreSettings(
            Pattern usernamePattern,
            int minPasswordLength,
            int maxPasswordLength,
            boolean rejectUsernameAsPassword,
            boolean rejectCommonPasswords,
            int argon2MemoryKib,
            int argon2Iterations,
            int argon2Parallelism,
            int maxConcurrentHashes,
            int maxQueuedHashes,
            int maxLoginAttemptsPerAccountIp,
            int maxLoginAttemptsPerIp,
            long baseBackoffMillis,
            long lockoutSeconds,
            boolean sessionsEnabled,
            long sessionDurationSeconds,
            String totpIssuer,
            int totpWindowSteps,
            boolean premiumAutoDetect,
            long mojangCacheSeconds
    ) {
        this(
                usernamePattern,
                minPasswordLength,
                maxPasswordLength,
                rejectUsernameAsPassword,
                rejectCommonPasswords,
                argon2MemoryKib,
                argon2Iterations,
                argon2Parallelism,
                maxConcurrentHashes,
                maxQueuedHashes,
                maxLoginAttemptsPerAccountIp,
                maxLoginAttemptsPerIp,
                baseBackoffMillis,
                lockoutSeconds,
                sessionsEnabled,
                sessionDurationSeconds,
                totpIssuer,
                totpWindowSteps,
                premiumAutoDetect,
                mojangCacheSeconds,
                5,
                90,
                true,
                true,
                600L
        );
    }

    public static CoreSettings defaults() {
        return new CoreSettings(
                Pattern.compile("^[a-zA-Z0-9_]{3,16}$"),
                8,
                128,
                true,
                true,
                19456,
                2,
                1,
                Math.max(2, Math.min(8, Runtime.getRuntime().availableProcessors())),
                64,
                5,
                20,
                1000L,
                300L,
                false, // Disabled by default per threat model #4
                3600L,
                "JustLogin",
                1,
                false, // Disabled by default per threat model #3
                300L,
                5,
                90,
                true,
                true,
                600L
        );
    }
}

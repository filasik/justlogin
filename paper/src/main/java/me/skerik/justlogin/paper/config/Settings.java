package me.skerik.justlogin.paper.config;

import java.nio.file.Path;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import me.skerik.justlogin.core.model.CoreSettings;
import me.skerik.justlogin.core.model.SmtpConfig;
import me.skerik.justlogin.core.storage.DbConfig;
import org.bukkit.configuration.ConfigurationSection;

/**
 * Typed Paper configuration loaded from {@code config.yml}. Immutable snapshot swapped atomically on reload.
 */
public record Settings(
        String language,
        UiMode loginUi,
        int timeoutSeconds,
        boolean kickDuplicateOnline,
        boolean fallbackForLegacyClients,
        boolean titleReminder,
        boolean dialogSinglePassword,
        boolean bedrockCumulusForms,
        boolean captchaEnabled,
        boolean captchaRequireOnRegister,
        int captchaTriggerAfterFailures,
        int captchaLength,
        int captchaExpireSeconds,
        CoreSettings core,
        boolean standalonePremiumEnabled,
        boolean standalonePreventProxyConnections,
        boolean premiumFallbackToPassword,
        boolean proxyEnabled,
        ProxyMode proxyMode,
        String proxySharedSecret,
        boolean requireForwardingConfig,
        DbConfig dbConfig,
        SmtpConfig smtpConfig,
        String editorWebUrl,
        String editorRelayUrl,
        int editorPageSize,
        int editorTtlSeconds,
        boolean editorLocalHttpEnabled,
        String editorLocalHttpBind,
        int editorLocalHttpPort,
        boolean checkUpdates,
        boolean metrics,
        boolean skinsCommandEnabled,
        long skinCooldownSeconds
) {

    /** Backwards-compatible 32-arg constructor. */
    public Settings(
            String language,
            UiMode loginUi,
            int timeoutSeconds,
            boolean kickDuplicateOnline,
            boolean fallbackForLegacyClients,
            boolean titleReminder,
            boolean dialogSinglePassword,
            boolean bedrockCumulusForms,
            boolean captchaEnabled,
            boolean captchaRequireOnRegister,
            int captchaTriggerAfterFailures,
            int captchaLength,
            int captchaExpireSeconds,
            CoreSettings core,
            boolean standalonePremiumEnabled,
            boolean standalonePreventProxyConnections,
            boolean premiumFallbackToPassword,
            boolean proxyEnabled,
            ProxyMode proxyMode,
            String proxySharedSecret,
            boolean requireForwardingConfig,
            DbConfig dbConfig,
            SmtpConfig smtpConfig,
            String editorWebUrl,
            String editorRelayUrl,
            int editorPageSize,
            int editorTtlSeconds,
            boolean editorLocalHttpEnabled,
            String editorLocalHttpBind,
            int editorLocalHttpPort,
            boolean checkUpdates,
            boolean metrics
    ) {
        this(language, loginUi, timeoutSeconds, kickDuplicateOnline, fallbackForLegacyClients, titleReminder,
                dialogSinglePassword, bedrockCumulusForms, captchaEnabled, captchaRequireOnRegister,
                captchaTriggerAfterFailures, captchaLength, captchaExpireSeconds,
                core, standalonePremiumEnabled, standalonePreventProxyConnections, premiumFallbackToPassword,
                proxyEnabled, proxyMode, proxySharedSecret, requireForwardingConfig,
                dbConfig, smtpConfig, editorWebUrl, editorRelayUrl, editorPageSize, editorTtlSeconds,
                editorLocalHttpEnabled, editorLocalHttpBind, editorLocalHttpPort, checkUpdates, metrics,
                true, 60L);
    }

    /** Backwards-compatible 31-arg constructor. */
    public Settings(
            String language,
            UiMode loginUi,
            int timeoutSeconds,
            boolean kickDuplicateOnline,
            boolean fallbackForLegacyClients,
            boolean titleReminder,
            boolean dialogSinglePassword,
            boolean bedrockCumulusForms,
            boolean captchaEnabled,
            boolean captchaRequireOnRegister,
            int captchaTriggerAfterFailures,
            int captchaLength,
            int captchaExpireSeconds,
            CoreSettings core,
            boolean standalonePremiumEnabled,
            boolean standalonePreventProxyConnections,
            boolean proxyEnabled,
            ProxyMode proxyMode,
            String proxySharedSecret,
            boolean requireForwardingConfig,
            DbConfig dbConfig,
            SmtpConfig smtpConfig,
            String editorWebUrl,
            String editorRelayUrl,
            int editorPageSize,
            int editorTtlSeconds,
            boolean editorLocalHttpEnabled,
            String editorLocalHttpBind,
            int editorLocalHttpPort,
            boolean checkUpdates,
            boolean metrics
    ) {
        this(language, loginUi, timeoutSeconds, kickDuplicateOnline, fallbackForLegacyClients, titleReminder,
                dialogSinglePassword, bedrockCumulusForms, captchaEnabled, captchaRequireOnRegister,
                captchaTriggerAfterFailures, captchaLength, captchaExpireSeconds,
                core, standalonePremiumEnabled, standalonePreventProxyConnections, false,
                proxyEnabled, proxyMode, proxySharedSecret, requireForwardingConfig,
                dbConfig, smtpConfig, editorWebUrl, editorRelayUrl, editorPageSize, editorTtlSeconds,
                editorLocalHttpEnabled, editorLocalHttpBind, editorLocalHttpPort, checkUpdates, metrics);
    }

    /** Backwards-compatible constructor used by unit tests. */
    public Settings(
            String language,
            UiMode loginUi,
            int timeoutSeconds,
            boolean kickDuplicateOnline,
            boolean fallbackForLegacyClients,
            boolean titleReminder,
            CoreSettings core,
            boolean standalonePremiumEnabled,
            boolean standalonePreventProxyConnections,
            boolean proxyEnabled,
            ProxyMode proxyMode,
            String proxySharedSecret,
            boolean requireForwardingConfig,
            DbConfig dbConfig,
            String editorWebUrl,
            String editorRelayUrl,
            int editorPageSize,
            int editorTtlSeconds,
            boolean checkUpdates,
            boolean metrics
    ) {
        this(language, loginUi, timeoutSeconds, kickDuplicateOnline, fallbackForLegacyClients, titleReminder,
                true, true, true, false, 3, 5, 120,
                core, standalonePremiumEnabled, standalonePreventProxyConnections, false,
                proxyEnabled, proxyMode, proxySharedSecret, requireForwardingConfig,
                dbConfig, SmtpConfig.disabled(),
                editorWebUrl, editorRelayUrl, editorPageSize, editorTtlSeconds,
                false, "127.0.0.1", 8787, checkUpdates, metrics);
    }

    public enum UiMode { DIALOG, COMMAND }

    public enum ProxyMode { STANDALONE, VELOCITY, BUNGEE }

    public static Settings load(ConfigurationSection cfg, Path dataFolder) {
        String language = cfg.getString("locale", cfg.getString("language", "en"));
        UiMode ui = "command".equalsIgnoreCase(cfg.getString("login.ui", "dialog"))
                ? UiMode.COMMAND : UiMode.DIALOG;
        int timeoutSeconds = Math.max(10, Math.min(600, cfg.getInt("login.timeout-seconds", 60)));
        boolean kickDup = cfg.getBoolean("login.kick-duplicate-online", true);
        boolean legacyFallback = cfg.getBoolean("login.fallback-for-legacy-clients", true);
        boolean titleReminder = cfg.getBoolean("login.title-reminder", true);
        boolean dialogSinglePassword = cfg.getBoolean("login.dialog-single-password", true);
        boolean bedrockCumulusForms = cfg.getBoolean("bedrock.cumulus-forms", true);

        boolean captchaEnabled = cfg.getBoolean("captcha.enabled", true);
        boolean captchaRequireOnRegister = cfg.getBoolean("captcha.require-on-register", false);
        int captchaTriggerAfterFailures = Math.max(0, cfg.getInt("captcha.trigger-after-failures", 3));
        int captchaLength = Math.max(4, Math.min(10, cfg.getInt("captcha.length", 5)));
        int captchaExpireSeconds = Math.max(30, cfg.getInt("captcha.expire-seconds", 120));

        Pattern usernamePattern;
        String rawRegex = cfg.getString("username.regex", "^[a-zA-Z0-9_]{3,16}$");
        try {
            usernamePattern = Pattern.compile(rawRegex);
        } catch (PatternSyntaxException e) {
            usernamePattern = Pattern.compile("^[a-zA-Z0-9_]{3,16}$");
        }

        int minLen = Math.max(4, cfg.getInt("password.min-length", 8));
        int maxLen = Math.max(minLen, cfg.getInt("password.max-length", 128));
        boolean rejectUserPw = cfg.getBoolean("password.reject-username-as-password", true);
        boolean rejectCommonPw = cfg.getBoolean("password.reject-common-passwords", true);

        int argonMem = Math.max(4096, cfg.getInt("password.argon2.memory-kib", 19456));
        int argonIter = Math.max(1, cfg.getInt("password.argon2.iterations", 2));
        int argonPar = Math.max(1, cfg.getInt("password.argon2.parallelism", 1));
        int maxConcurrent = Math.max(1, cfg.getInt("password.hashing.max-concurrent", 4));
        int maxQueued = Math.max(4, cfg.getInt("password.hashing.max-queued", 64));

        int maxAccIp = Math.max(1, cfg.getInt("rate-limit.max-attempts-per-account-ip", 5));
        int maxIp = Math.max(maxAccIp, cfg.getInt("rate-limit.max-attempts-per-ip", 20));
        long backoff = Math.max(0L, cfg.getLong("rate-limit.base-backoff-millis", 1000L));
        long lockout = Math.max(5L, cfg.getLong("rate-limit.lockout-seconds", 300L));

        boolean sessionsEnabled = cfg.getBoolean("sessions.enabled", false);
        long sessionDuration = Math.max(60L, cfg.getLong("sessions.duration-seconds", 3600L));

        String totpIssuer = cfg.getString("totp.issuer", "JustLogin");
        int totpWindow = Math.max(0, Math.min(3, cfg.getInt("totp.window-steps", 1)));

        boolean standalonePremiumEnabled = cfg.getBoolean("premium.standalone-enabled", true);
        boolean standalonePreventProxy = cfg.getBoolean("premium.prevent-proxy-connections", false);
        boolean premiumFallbackToPassword = cfg.getBoolean("premium.fallback-to-password", false);
        boolean autoDetectMojang = cfg.contains("premium.auto-detect-mojang")
                ? cfg.getBoolean("premium.auto-detect-mojang", false)
                : cfg.getBoolean("proxy.auto-detect-mojang", false);
        long mojangCache = Math.max(10L, cfg.contains("premium.mojang-cache-seconds")
                ? cfg.getLong("premium.mojang-cache-seconds", 300L)
                : cfg.getLong("proxy.mojang-cache-seconds", 300L));
        boolean skinsEnabled = cfg.getBoolean("skins.enabled", true);
        boolean skinsRestoreCracked = cfg.getBoolean("skins.restore-cracked-by-name", true);
        boolean skinsCommandEnabled = cfg.getBoolean("skins.command-enabled", true);
        long skinCooldownSeconds = Math.max(0L, cfg.getLong("skins.cooldown-seconds", 60L));
        long skinsCacheSeconds = Math.max(10L, cfg.getLong("skins.cache-seconds", 600L));

        int maxAccountsPerIp = Math.max(0, cfg.getInt("registration.max-accounts-per-ip", 5));
        int auditRetentionDays = Math.max(0, cfg.getInt("audit.retention-days", 90));

        boolean proxyEnabled = cfg.getBoolean("proxy.enabled", false);
        ProxyMode proxyMode = parseProxyMode(cfg.getString("proxy.mode", "standalone"));
        String sharedSecret = cfg.getString("proxy.shared-secret", "");
        boolean requireFwd = cfg.getBoolean("proxy.require-forwarding-config", true);

        String dbPrefix = cfg.contains("storage.type") || cfg.isConfigurationSection("storage")
                ? "storage" : "database";
        String dbType = cfg.getString(dbPrefix + ".type", "sqlite").toLowerCase(Locale.ROOT);
        DbConfig dbConfig;
        if ("mariadb".equals(dbType) || "mysql".equals(dbType)) {
            dbConfig = new DbConfig(
                    DbConfig.Dialect.MARIADB,
                    null,
                    cfg.getString(dbPrefix + ".mariadb.host", "localhost"),
                    cfg.getInt(dbPrefix + ".mariadb.port", 3306),
                    cfg.getString(dbPrefix + ".mariadb.database", "justlogin"),
                    cfg.getString(dbPrefix + ".mariadb.user", "root"),
                    cfg.getString(dbPrefix + ".mariadb.password", ""),
                    Math.max(2, cfg.getInt(dbPrefix + ".mariadb.pool-size", 10)),
                    cfg.getString(dbPrefix + ".mariadb.ssl-mode", "")
            );
        } else {
            String fileRel = cfg.getString(dbPrefix + ".sqlite.file", "data/justlogin.db");
            Path sqlitePath = dataFolder.resolve(fileRel).normalize();
            dbConfig = DbConfig.sqlite(sqlitePath, Math.max(1, cfg.getInt(dbPrefix + ".sqlite.pool-size", 4)));
        }

        String webUrl = cfg.getString("editor.web-url", "https://justlogin.net");
        String relayUrl = cfg.getString("editor.relay-url", "https://bytebin.lucko.me");
        int pageSize = Math.max(10, Math.min(2000, cfg.getInt("editor.page-size", 500)));
        int ttlSeconds = Math.max(60, cfg.getInt("editor.ttl-seconds", 1800));
        boolean localHttpEnabled = cfg.getBoolean("editor.local-http.enabled", false);
        String localHttpBind = cfg.getString("editor.local-http.bind", "127.0.0.1");
        int localHttpPort = Math.max(1024, Math.min(65535, cfg.getInt("editor.local-http.port", 8787)));

        SmtpConfig smtp = new SmtpConfig(
                cfg.getBoolean("email.enabled", false),
                cfg.getString("email.smtp.host", "smtp.example.com"),
                cfg.getInt("email.smtp.port", 587),
                SmtpConfig.Security.parse(cfg.getString("email.smtp.security", "STARTTLS")),
                cfg.getString("email.smtp.username", ""),
                cfg.getString("email.smtp.password", ""),
                cfg.getString("email.smtp.from-address", "noreply@example.com"),
                cfg.getString("email.smtp.from-name", "JustLogin"),
                Math.max(1000, cfg.getInt("email.smtp.connect-timeout-ms", 5000)),
                Math.max(1000, cfg.getInt("email.smtp.read-timeout-ms", 10000)),
                Math.max(60, cfg.getInt("email.code-ttl-seconds", 600)),
                Math.max(10L, cfg.getLong("email.cooldown-seconds", 120L)),
                cfg.getString("email.server-name", "Minecraft Server")
        );

        boolean checkUpdates = cfg.contains("update-check")
                ? cfg.getBoolean("update-check", true)
                : cfg.getBoolean("updates.check", true);
        boolean metrics = cfg.getBoolean("metrics", true);

        CoreSettings core = new CoreSettings(
                usernamePattern,
                minLen,
                maxLen,
                rejectUserPw,
                rejectCommonPw,
                argonMem,
                argonIter,
                argonPar,
                maxConcurrent,
                maxQueued,
                maxAccIp,
                maxIp,
                backoff,
                lockout,
                sessionsEnabled,
                sessionDuration,
                totpIssuer,
                totpWindow,
                autoDetectMojang,
                mojangCache,
                maxAccountsPerIp,
                auditRetentionDays,
                skinsEnabled,
                skinsRestoreCracked,
                skinsCacheSeconds
        );

        return new Settings(
                language, ui, timeoutSeconds, kickDup, legacyFallback, titleReminder,
                dialogSinglePassword, bedrockCumulusForms,
                captchaEnabled, captchaRequireOnRegister, captchaTriggerAfterFailures,
                captchaLength, captchaExpireSeconds,
                core, standalonePremiumEnabled, standalonePreventProxy, premiumFallbackToPassword,
                proxyEnabled, proxyMode, sharedSecret, requireFwd, dbConfig, smtp,
                webUrl, relayUrl, pageSize, ttlSeconds,
                localHttpEnabled, localHttpBind, localHttpPort,
                checkUpdates, metrics, skinsCommandEnabled, skinCooldownSeconds
        );
    }

    public boolean skinsEnabled() {
        return core.skinsEnabled();
    }

    public boolean skinsRestoreCrackedByName() {
        return core.skinsRestoreCrackedByName();
    }

    public long skinsCacheSeconds() {
        return core.skinsCacheSeconds();
    }

    private static ProxyMode parseProxyMode(String raw) {
        if (raw == null) return ProxyMode.STANDALONE;
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "velocity" -> ProxyMode.VELOCITY;
            case "bungee", "bungeecord" -> ProxyMode.BUNGEE;
            default -> ProxyMode.STANDALONE;
        };
    }
}

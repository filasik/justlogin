package me.skerik.justlogin.bungee;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import me.skerik.justlogin.core.model.CoreSettings;
import me.skerik.justlogin.core.service.ProxyAuthService;
import me.skerik.justlogin.core.storage.DbConfig;
import net.md_5.bungee.config.Configuration;
import net.md_5.bungee.config.ConfigurationProvider;
import net.md_5.bungee.config.YamlConfiguration;
import org.jspecify.annotations.Nullable;

/** Loads typed BungeeCord proxy configuration from {@code config.yml}. */
public record BungeeConfig(
        CoreSettings core,
        String sharedSecret,
        boolean floodgateFallback,
        Set<String> authServers,
        DbConfig dbConfig,
        String locale,
        String invalidUsernameMessage,
        String missingSecretMessage,
        String authRequiredServerMessage,
        String notReadyMessage,
        String authServiceErrorMessage,
        String authServerUnavailableMessage,
        boolean metrics
) {

    public BungeeConfig(
            CoreSettings core,
            String sharedSecret,
            boolean floodgateFallback,
            Set<String> authServers,
            DbConfig dbConfig,
            String invalidUsernameMessage,
            String missingSecretMessage,
            String authRequiredServerMessage,
            boolean metrics
    ) {
        this(core, sharedSecret, floodgateFallback, authServers, dbConfig, "en",
                invalidUsernameMessage, missingSecretMessage, authRequiredServerMessage,
                ProxyMessages.EN_NOT_READY, ProxyMessages.EN_AUTH_SERVICE_ERROR,
                ProxyMessages.EN_AUTH_SERVER_UNAVAILABLE, metrics);
    }

    public BungeeConfig(
            CoreSettings core,
            String sharedSecret,
            boolean floodgateFallback,
            DbConfig dbConfig,
            String invalidUsernameMessage,
            String missingSecretMessage,
            boolean metrics
    ) {
        this(core, sharedSecret, floodgateFallback, Set.of(), dbConfig,
                invalidUsernameMessage, missingSecretMessage, ProxyMessages.EN_AUTH_REQUIRED_SERVER, metrics);
    }

    public static final String PLACEHOLDER_SECRET = "CHANGE-ME-TO-A-LONG-RANDOM-SECRET";

    public static BungeeConfig load(Path dataDirectory) throws IOException {
        Files.createDirectories(dataDirectory);
        Path file = dataDirectory.resolve("config.yml");
        if (!Files.exists(file)) {
            try (InputStream in = BungeeConfig.class.getResourceAsStream("/config.yml")) {
                if (in != null) Files.copy(in, file);
            }
        }
        Configuration cfg = ConfigurationProvider.getProvider(YamlConfiguration.class).load(file.toFile());
        return fromConfiguration(cfg, dataDirectory);
    }

    public static BungeeConfig fromConfiguration(Configuration cfg, Path dataDirectory) {
        CoreSettings d = CoreSettings.defaults();
        String locale = ProxyMessages.normalizeLocale(cfg.getString("locale", "en"));
        String rawRegex = cfg.getString("username.regex", "^[a-zA-Z0-9_]{3,16}$");
        Pattern pattern;
        try {
            pattern = Pattern.compile(rawRegex);
        } catch (PatternSyntaxException e) {
            pattern = d.usernamePattern();
        }

        boolean autoDetect = cfg.getBoolean("proxy.auto-detect-mojang", false);
        long cacheSec = Math.max(10L, cfg.getLong("proxy.mojang-cache-seconds", 300L));
        String sharedSecret = cfg.getString("proxy.shared-secret", "");
        boolean floodgate = cfg.getBoolean("proxy.floodgate-fallback", true);
        Set<String> authServers = new LinkedHashSet<>();
        List<String> rawServers = cfg.getStringList("proxy.auth-servers");
        if (rawServers != null) {
            for (String s : rawServers) {
                if (s != null && !s.isBlank()) authServers.add(s.trim().toLowerCase(Locale.ROOT));
            }
        }

        String dbPrefix = cfg.contains("storage") ? "storage" : "database";
        String dbType = cfg.getString(dbPrefix + ".type", "sqlite").toLowerCase(Locale.ROOT);
        DbConfig db;
        if ("mariadb".equals(dbType) || "mysql".equals(dbType)) {
            db = new DbConfig(
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
            Path sqliteFile = dataDirectory.resolve(cfg.getString(dbPrefix + ".sqlite.file", "data/justlogin.db")).normalize();
            db = DbConfig.sqlite(sqliteFile, Math.max(1, cfg.getInt(dbPrefix + ".sqlite.pool-size", 4)));
        }

        CoreSettings core = new CoreSettings(
                pattern, d.minPasswordLength(), d.maxPasswordLength(),
                d.rejectUsernameAsPassword(), d.rejectCommonPasswords(),
                d.argon2MemoryKib(), d.argon2Iterations(), d.argon2Parallelism(),
                d.maxConcurrentHashes(), d.maxQueuedHashes(),
                d.maxLoginAttemptsPerAccountIp(), d.maxLoginAttemptsPerIp(),
                d.baseBackoffMillis(), d.lockoutSeconds(),
                d.sessionsEnabled(), d.sessionDurationSeconds(),
                d.totpIssuer(), d.totpWindowSteps(),
                autoDetect, cacheSec
        );

        String invalidMsg = resolveMessage(
                cfg.getString("messages.invalid-username", ""),
                ProxyMessages.EN_INVALID_USERNAME,
                ProxyMessages.invalidUsername(locale));
        String missingSec = resolveMessage(
                cfg.getString("messages.missing-secret", ""),
                ProxyMessages.EN_MISSING_SECRET,
                ProxyMessages.missingSecret(locale));
        String authReqMsg = resolveMessage(
                cfg.getString("messages.auth-required-server", ""),
                ProxyMessages.EN_AUTH_REQUIRED_SERVER,
                ProxyMessages.authRequiredServer(locale));
        String notReadyMsg = resolveMessage(
                cfg.getString("messages.not-ready", ""),
                ProxyMessages.EN_NOT_READY,
                ProxyMessages.notReady(locale));
        String authErrMsg = resolveMessage(
                cfg.getString("messages.auth-service-error", ""),
                ProxyMessages.EN_AUTH_SERVICE_ERROR,
                ProxyMessages.authServiceError(locale));
        String authUnavailMsg = resolveMessage(
                cfg.getString("messages.auth-server-unavailable", ""),
                ProxyMessages.EN_AUTH_SERVER_UNAVAILABLE,
                ProxyMessages.authServerUnavailable(locale));
        boolean metrics = cfg.getBoolean("metrics", true);

        return new BungeeConfig(core, sharedSecret, floodgate, Set.copyOf(authServers), db,
                locale, invalidMsg, missingSec, authReqMsg, notReadyMsg, authErrMsg, authUnavailMsg, metrics);
    }

    private static String resolveMessage(@Nullable String configured, String enDefault, String localizedDefault) {
        if (configured == null || configured.isBlank() || configured.equals(enDefault)) {
            return localizedDefault;
        }
        return configured;
    }

    public boolean isSecretValid() {
        return sharedSecret != null
                && sharedSecret.length() >= 16
                && !PLACEHOLDER_SECRET.equals(sharedSecret);
    }

    public String formatDenyReason(ProxyAuthService.DenyReason reason) {
        if (reason == ProxyAuthService.DenyReason.INVALID_USERNAME) {
            return invalidUsernameMessage;
        }
        return ProxyMessages.formatDeny(locale, reason);
    }

    public String formatDeny(ProxyAuthService.JoinResolution resolution) {
        if (resolution.denyCode() != null) {
            return formatDenyReason(resolution.denyCode());
        }
        if (resolution.denyReason() != null && !resolution.denyReason().isBlank()) {
            return resolution.denyReason();
        }
        return authServiceErrorMessage;
    }
}

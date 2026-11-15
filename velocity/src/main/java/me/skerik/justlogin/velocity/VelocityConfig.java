package me.skerik.justlogin.velocity;

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
import org.jspecify.annotations.Nullable;
import org.spongepowered.configurate.ConfigurationNode;
import org.spongepowered.configurate.serialize.SerializationException;
import org.spongepowered.configurate.yaml.YamlConfigurationLoader;

/** Loads typed Velocity proxy configuration from {@code config.yml}. */
public record VelocityConfig(
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

    public VelocityConfig(
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

    public VelocityConfig(
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

    public static VelocityConfig load(Path dataDirectory) throws IOException {
        Files.createDirectories(dataDirectory);
        Path file = dataDirectory.resolve("config.yml");
        if (!Files.exists(file)) {
            try (InputStream in = VelocityConfig.class.getResourceAsStream("/config.yml")) {
                if (in != null) {
                    Files.copy(in, file);
                }
            }
        }
        ConfigurationNode root = YamlConfigurationLoader.builder().path(file).build().load();
        return fromNode(root, dataDirectory);
    }

    public static VelocityConfig fromNode(ConfigurationNode root, Path dataDirectory) {
        CoreSettings d = CoreSettings.defaults();
        String locale = ProxyMessages.normalizeLocale(root.node("locale").getString("en"));
        String rawRegex = root.node("username", "regex").getString("^[a-zA-Z0-9_]{3,16}$");
        Pattern pattern;
        try {
            pattern = Pattern.compile(rawRegex);
        } catch (PatternSyntaxException e) {
            pattern = d.usernamePattern();
        }

        boolean autoDetect = root.node("proxy", "auto-detect-mojang").getBoolean(false);
        long cacheSec = Math.max(10L, root.node("proxy", "mojang-cache-seconds").getLong(300L));
        String sharedSecret = root.node("proxy", "shared-secret").getString("");
        boolean floodgate = root.node("proxy", "floodgate-fallback").getBoolean(true);
        Set<String> authServers = new LinkedHashSet<>();
        try {
            List<String> rawServers = root.node("proxy", "auth-servers").getList(String.class, List.of());
            for (String s : rawServers) {
                if (s != null && !s.isBlank()) authServers.add(s.trim().toLowerCase(Locale.ROOT));
            }
        } catch (SerializationException ignored) {
        }

        ConfigurationNode storageNode = !root.node("storage").virtual()
                ? root.node("storage")
                : root.node("database");
        String dbType = storageNode.node("type").getString("sqlite").toLowerCase(Locale.ROOT);
        DbConfig db;
        if ("mariadb".equals(dbType) || "mysql".equals(dbType)) {
            ConfigurationNode maria = storageNode.node("mariadb");
            db = new DbConfig(
                    DbConfig.Dialect.MARIADB,
                    null,
                    maria.node("host").getString("localhost"),
                    maria.node("port").getInt(3306),
                    maria.node("database").getString("justlogin"),
                    maria.node("user").getString("root"),
                    maria.node("password").getString(""),
                    Math.max(2, maria.node("pool-size").getInt(10)),
                    maria.node("ssl-mode").getString("")
            );
        } else {
            ConfigurationNode sqlite = storageNode.node("sqlite");
            Path sqliteFile = dataDirectory.resolve(sqlite.node("file").getString("data/justlogin.db")).normalize();
            db = DbConfig.sqlite(sqliteFile, Math.max(1, sqlite.node("pool-size").getInt(4)));
        }

        boolean skinsEnabled = root.node("skins", "enabled").getBoolean(true);
        boolean skinsRestoreByName = root.node("skins", "restore-by-name")
                .getBoolean(root.node("skins", "restore-cracked-by-name").getBoolean(true));
        long skinsCacheSec = Math.max(10L, root.node("skins", "cache-seconds").getLong(600L));

        CoreSettings core = new CoreSettings(
                pattern, d.minPasswordLength(), d.maxPasswordLength(),
                d.rejectUsernameAsPassword(), d.rejectCommonPasswords(),
                d.argon2MemoryKib(), d.argon2Iterations(), d.argon2Parallelism(),
                d.maxConcurrentHashes(), d.maxQueuedHashes(),
                d.maxLoginAttemptsPerAccountIp(), d.maxLoginAttemptsPerIp(),
                d.baseBackoffMillis(), d.lockoutSeconds(),
                d.sessionsEnabled(), d.sessionDurationSeconds(),
                d.totpIssuer(), d.totpWindowSteps(),
                autoDetect, cacheSec,
                d.maxAccountsPerIp(), d.auditRetentionDays(),
                skinsEnabled, skinsRestoreByName, skinsCacheSec
        );

        String invalidMsg = resolveMessage(
                root.node("messages", "invalid-username").getString(),
                ProxyMessages.EN_INVALID_USERNAME,
                ProxyMessages.invalidUsername(locale));
        String missingSec = resolveMessage(
                root.node("messages", "missing-secret").getString(),
                ProxyMessages.EN_MISSING_SECRET,
                ProxyMessages.missingSecret(locale));
        String authReqMsg = resolveMessage(
                root.node("messages", "auth-required-server").getString(),
                ProxyMessages.EN_AUTH_REQUIRED_SERVER,
                ProxyMessages.authRequiredServer(locale));
        String notReadyMsg = resolveMessage(
                root.node("messages", "not-ready").getString(),
                ProxyMessages.EN_NOT_READY,
                ProxyMessages.notReady(locale));
        String authErrMsg = resolveMessage(
                root.node("messages", "auth-service-error").getString(),
                ProxyMessages.EN_AUTH_SERVICE_ERROR,
                ProxyMessages.authServiceError(locale));
        String authUnavailMsg = resolveMessage(
                root.node("messages", "auth-server-unavailable").getString(),
                ProxyMessages.EN_AUTH_SERVER_UNAVAILABLE,
                ProxyMessages.authServerUnavailable(locale));
        boolean metrics = root.node("metrics").getBoolean(true);

        return new VelocityConfig(core, sharedSecret, floodgate, Set.copyOf(authServers), db,
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

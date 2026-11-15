package me.skerik.justlogin.velocity;

import com.google.inject.Inject;
import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.ResultedEvent;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.connection.PluginMessageEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.player.GameProfileRequestEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.InboundConnection;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.ServerConnection;
import com.velocitypowered.api.proxy.messages.MinecraftChannelIdentifier;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.util.GameProfile;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import me.skerik.justlogin.core.crypto.ProxyTokenSigner;
import me.skerik.justlogin.core.crypto.ServerSecrets;
import me.skerik.justlogin.core.security.UsernameValidator;
import me.skerik.justlogin.core.service.MojangApiClient;
import me.skerik.justlogin.core.service.MojangSkinClient;
import me.skerik.justlogin.core.service.ProxyAuthService;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import me.skerik.justlogin.core.storage.Database;
import me.skerik.justlogin.core.storage.DbConfig;
import me.skerik.justlogin.core.storage.Migrations;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import net.kyori.adventure.text.minimessage.tag.resolver.TagResolver;
import org.bstats.charts.SimplePie;
import org.bstats.velocity.Metrics;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;

/** Velocity proxy entrypoint for JustLogin (Mojang online/password negotiation, immutable {@code game_uuid}, signed forwarding). */
public final class JustLoginVelocity {

    private static final String REPO = "https://github.com/filasik/justLogin";
    private static final MinecraftChannelIdentifier CHANNEL = MinecraftChannelIdentifier.from(ProxyTokenSigner.CHANNEL);

    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;
    private final Metrics.Factory metricsFactory;

    private volatile @Nullable VelocityConfig config;
    private volatile @Nullable Database database;
    private volatile @Nullable ProxyAuthService proxyAuth;
    private volatile @Nullable MojangSkinClient skinClient;
    private volatile @Nullable ProxyTokenSigner signer;
    private volatile boolean misconfigured;

    private final Map<String, String> pendingDenials = new ConcurrentHashMap<>();
    private final Set<UUID> authenticatedPlayers = ConcurrentHashMap.newKeySet();
    private @Nullable Object floodgateApi;
    private @Nullable Method floodgateCheck;

    @Inject
    public JustLoginVelocity(
            ProxyServer server,
            Logger logger,
            @DataDirectory Path dataDirectory,
            Metrics.Factory metricsFactory
    ) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
        this.metricsFactory = metricsFactory;
    }

    @Subscribe
    public void onInitialize(ProxyInitializeEvent event) {
        long started = System.nanoTime();
        try {
            VelocityConfig cfg = VelocityConfig.load(dataDirectory);
            this.config = cfg;
            Files.createDirectories(dataDirectory.resolve("data"));
            ServerSecrets secrets = ServerSecrets.loadOrCreate(dataDirectory.resolve("secrets.key"));

            if (!cfg.isSecretValid()) {
                logger.error("proxy.shared-secret in JustLogin Velocity config.yml is missing or still uses the default placeholder! "
                        + "Set a shared secret >= 16 characters matching Paper config.yml.");
                this.misconfigured = true;
                return;
            }
            if (cfg.dbConfig().dialect() == DbConfig.Dialect.SQLITE) {
                logger.warn("storage.type is set to 'sqlite' on Velocity! Proxy and Paper backends MUST share the same database "
                        + "(use 'mariadb' unless SQLite points to the exact same shared file path on a single machine).");
            }
            if (cfg.authServers().isEmpty()) {
                logger.warn("proxy.auth-servers is empty! Unauthenticated players are not locked to a dedicated auth/limbo server on the proxy.");
            }
            secrets = secrets.withProxySecret(cfg.sharedSecret());

            this.database = new Database(cfg.dbConfig());
            int schemaVersion = Migrations.migrate(this.database);
            AccountStore accounts = new AccountStore(this.database);
            AuditStore audit = new AuditStore(this.database);
            MojangApiClient mojang = new MojangApiClient(cfg.core().mojangCacheSeconds(), System::currentTimeMillis);
            this.skinClient = new MojangSkinClient(mojang, () -> {
                VelocityConfig current = this.config;
                return current != null ? current.core().skinsCacheSeconds() : cfg.core().skinsCacheSeconds();
            }, System::currentTimeMillis);
            this.proxyAuth = new ProxyAuthService(accounts, audit, mojang, secrets, () -> {
                VelocityConfig current = this.config;
                return current != null ? current.core() : cfg.core();
            }, System::currentTimeMillis);
            this.signer = new ProxyTokenSigner(secrets.proxySecret());

            server.getChannelRegistrar().register(CHANNEL);
            initFloodgateReflection();

            Properties buildProps = readBuildProperties();
            String version = buildProps.getProperty("version", "1.0.0").strip();
            int bstatsId = parseIntOrZero(buildProps.getProperty("bstats-id", "0"));
            boolean metricsActive = false;
            if (cfg.metrics() && bstatsId > 0) {
                Metrics m = metricsFactory.make(this, bstatsId);
                m.addCustomChart(new SimplePie("storage", () -> cfg.dbConfig().dialect().name().toLowerCase(Locale.ROOT)));
                m.addCustomChart(new SimplePie("mojang_autodetect", () -> Boolean.toString(cfg.core().premiumAutoDetect())));
                metricsActive = true;
            }

            long ms = Math.max(1L, (System.nanoTime() - started) / 1_000_000L);
            printBanner(version, cfg, schemaVersion, metricsActive, ms);
        } catch (Exception e) {
            logger.error("Failed to initialize JustLogin Velocity", e);
            this.misconfigured = true;
        }
    }

    private void printBanner(String version, VelocityConfig cfg, int schemaVersion, boolean metricsActive, long ms) {
        MiniMessage mm = MiniMessage.miniMessage();
        Map<String, String> details = new LinkedHashMap<>();
        details.put("storage", cfg.dbConfig().dialect().name().toLowerCase(Locale.ROOT) + " (schema v" + schemaVersion + ")");
        details.put("mojang", cfg.core().premiumAutoDetect() ? "auto-detect on" : "auto-detect off");
        details.put("metrics", metricsActive ? "bStats active" : "disabled");

        TagResolver.Builder r = TagResolver.builder()
                .resolver(Placeholder.unparsed("version", version))
                .resolver(Placeholder.unparsed("ms", Long.toString(ms)))
                .resolver(Placeholder.unparsed("repo", REPO));
        var console = server.getConsoleCommandSource();
        console.sendMessage(mm.deserialize(""));
        console.sendMessage(mm.deserialize("<dark_gray>  ┌─ <aqua><bold>JustLogin</bold> <gray>v<version> <dark_gray>· <gray>Velocity", r.build()));
        console.sendMessage(mm.deserialize("<dark_gray>  │"));
        int i = 0;
        for (Map.Entry<String, String> row : details.entrySet()) {
            r.resolver(Placeholder.unparsed("k" + i, String.format("%-9s", row.getKey())));
            r.resolver(Placeholder.unparsed("v" + i, row.getValue()));
            console.sendMessage(mm.deserialize("<dark_gray>  │  <gray><k" + i + "> <white><v" + i + ">", r.build()));
            i++;
        }
        console.sendMessage(mm.deserialize("<dark_gray>  │"));
        console.sendMessage(mm.deserialize("<dark_gray>  └─ <green>Ready in <ms> ms <dark_gray>· <blue><underlined><repo></underlined>", r.build()));
        console.sendMessage(mm.deserialize(""));
    }

    private static Properties readBuildProperties() {
        Properties props = new Properties();
        try (InputStream in = JustLoginVelocity.class.getResourceAsStream("/build.properties")) {
            if (in != null) props.load(in);
        } catch (Exception ignored) {
        }
        return props;
    }

    private static int parseIntOrZero(String raw) {
        try {
            return Integer.parseInt(raw.strip());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    @Subscribe
    public void onShutdown(ProxyShutdownEvent event) {
        if (database != null) database.close();
    }

    @Subscribe(priority = -50)
    public @Nullable EventTask onPreLogin(PreLoginEvent event) {
        VelocityConfig cfg = this.config;
        ProxyAuthService auth = this.proxyAuth;
        if (misconfigured || auth == null || cfg == null) {
            String msg = cfg != null ? cfg.missingSecretMessage() : ProxyMessages.notReady("en");
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text(msg)));
            return null;
        }
        String username = event.getUsername();
        boolean fg = cfg.floodgateFallback() && isFloodgate(event.getUniqueId());
        return EventTask.resumeWhenComplete(auth.decidePreLogin(username, fg).thenAccept(dec -> {
            switch (dec.action()) {
                case DENY_INVALID_USERNAME -> event.setResult(
                        PreLoginEvent.PreLoginComponentResult.denied(Component.text(cfg.invalidUsernameMessage())));
                case DENY_MOJANG_UNAVAILABLE -> event.setResult(
                        PreLoginEvent.PreLoginComponentResult.denied(
                                Component.text(cfg.formatDenyReason(ProxyAuthService.DenyReason.MOJANG_UNAVAILABLE))));
                case FORCE_ONLINE -> event.setResult(PreLoginEvent.PreLoginComponentResult.forceOnlineMode());
                case FORCE_OFFLINE, ALLOW_OFFLINE -> {
                    if (!fg) {
                        event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
                    }
                }
            }
        }).exceptionally(ex -> {
            logger.error("Error during pre-login decision for {}", username, ex);
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    Component.text(cfg.authServiceErrorMessage())));
            return null;
        }));
    }

    @Subscribe(priority = -50)
    public @Nullable EventTask onGameProfileRequest(GameProfileRequestEvent event) {
        VelocityConfig cfg = this.config;
        ProxyAuthService auth = this.proxyAuth;
        if (misconfigured || auth == null || cfg == null) return null;
        String ip = extractIp(event.getConnection());
        UUID originalUuid = event.getOriginalProfile().getId();
        String lower = UsernameValidator.normalizeLower(event.getUsername());
        return EventTask.resumeWhenComplete(auth.resolveJoinProfile(
                event.getUsername(), originalUuid, event.isOnlineMode(), ip).thenCompose(res -> {
            if (!res.allowed()) {
                pendingDenials.put(lower, cfg.formatDeny(res));
                return CompletableFuture.completedFuture(null);
            }
            UUID finalUuid = res.targetGameUuid() != null ? res.targetGameUuid() : event.getGameProfile().getId();
            GameProfile profile = event.getGameProfile();
            if (res.targetGameUuid() != null && !res.targetGameUuid().equals(profile.getId())) {
                profile = profile.withId(res.targetGameUuid());
            }
            if (res.onlineAuthenticated()) {
                authenticatedPlayers.add(finalUuid);
            }
            if (!cfg.core().skinsEnabled()) {
                event.setGameProfile(profile);
                return CompletableFuture.completedFuture(null);
            }
            if (res.hasCustomSkin() && res.customSkinValue() != null && res.customSkinSignature() != null) {
                event.setGameProfile(withTextures(profile, res.customSkinValue(), res.customSkinSignature()));
                return CompletableFuture.completedFuture(null);
            }
            MojangSkinClient skins = this.skinClient;
            if (!res.onlineAuthenticated()
                    && cfg.core().skinsRestoreByName()
                    && !hasTextures(profile)
                    && !(cfg.floodgateFallback() && isFloodgate(originalUuid))
                    && skins != null) {
                GameProfile updatedProfile = profile;
                return skins.fetchByUsername(event.getUsername())
                        .completeOnTimeout(MojangSkinClient.SkinLookupResult.unavailable(), 2500L, TimeUnit.MILLISECONDS)
                        .exceptionally(ex -> MojangSkinClient.SkinLookupResult.unavailable())
                        .thenAccept(skinRes -> {
                            if (skinRes.status() == MojangSkinClient.Status.FOUND && skinRes.skin() != null) {
                                event.setGameProfile(withTextures(
                                        updatedProfile, skinRes.skin().value(), skinRes.skin().signature()));
                            } else {
                                event.setGameProfile(updatedProfile);
                            }
                        });
            }
            event.setGameProfile(profile);
            return CompletableFuture.completedFuture(null);
        }).exceptionally(ex -> {
            logger.error("Error resolving join profile for {}", event.getUsername(), ex);
            pendingDenials.put(lower, cfg.authServiceErrorMessage());
            return null;
        }));
    }

    private static boolean hasTextures(GameProfile profile) {
        for (GameProfile.Property prop : profile.getProperties()) {
            if ("textures".equals(prop.getName()) && prop.getValue() != null && !prop.getValue().isBlank()) {
                return true;
            }
        }
        return false;
    }

    private static GameProfile withTextures(GameProfile profile, String value, String signature) {
        List<GameProfile.Property> props = new ArrayList<>();
        for (GameProfile.Property existing : profile.getProperties()) {
            if (!"textures".equals(existing.getName())) {
                props.add(existing);
            }
        }
        props.add(new GameProfile.Property("textures", value, signature));
        return profile.withProperties(props);
    }

    @Subscribe(priority = -50)
    public void onLogin(LoginEvent event) {
        VelocityConfig cfg = this.config;
        if (misconfigured || proxyAuth == null || cfg == null) {
            String msg = cfg != null ? cfg.missingSecretMessage() : ProxyMessages.notReady("en");
            event.setResult(ResultedEvent.ComponentResult.denied(Component.text(msg)));
            return;
        }
        String reason = pendingDenials.remove(UsernameValidator.normalizeLower(event.getPlayer().getUsername()));
        if (reason != null) {
            authenticatedPlayers.remove(event.getPlayer().getUniqueId());
            event.setResult(ResultedEvent.ComponentResult.denied(Component.text(reason)));
        }
    }

    @Subscribe(priority = 50)
    public void onServerPreConnect(ServerPreConnectEvent event) {
        VelocityConfig cfg = this.config;
        if (cfg == null || cfg.authServers().isEmpty()) return;
        Player player = event.getPlayer();
        if (authenticatedPlayers.contains(player.getUniqueId())) return;
        Optional<RegisteredServer> targetOpt = event.getResult().getServer();
        String targetName = targetOpt.map(s -> s.getServerInfo().getName().toLowerCase(Locale.ROOT)).orElse("");
        if (cfg.authServers().contains(targetName)) return;

        if (player.getCurrentServer().isEmpty()) {
            for (String authName : cfg.authServers()) {
                Optional<RegisteredServer> authServer = server.getServer(authName);
                if (authServer.isPresent()) {
                    event.setResult(ServerPreConnectEvent.ServerResult.allowed(authServer.get()));
                    return;
                }
            }
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
            player.disconnect(Component.text(cfg.authServerUnavailableMessage()));
            return;
        }
        event.setResult(ServerPreConnectEvent.ServerResult.denied());
        player.sendMessage(Component.text(cfg.authRequiredServerMessage()));
    }

    @Subscribe
    public void onServerConnected(ServerConnectedEvent event) {
        if (misconfigured || proxyAuth == null || signer == null) return;
        Player player = event.getPlayer();
        byte[] signed = proxyAuth.signBackendMessageIfOnline(signer, player.getUsername(), player.getUniqueId());
        if (signed != null) {
            authenticatedPlayers.add(player.getUniqueId());
            event.getServer().sendPluginMessage(CHANNEL, signed);
        }
    }

    @Subscribe
    public void onPluginMessage(PluginMessageEvent event) {
        if (!CHANNEL.equals(event.getIdentifier())) return;
        // Threat model #1/#2: never allow client connections to spoof or eavesdrop justlogin:auth messages
        if (!(event.getSource() instanceof ServerConnection sc)) {
            event.setResult(PluginMessageEvent.ForwardResult.handled());
            return;
        }
        event.setResult(PluginMessageEvent.ForwardResult.handled());
        if (signer == null || config == null) return;
        ProxyTokenSigner.VerifiedMessage msg = signer.verify(event.getData(), System.currentTimeMillis());
        if (msg == null) return;
        Player player = sc.getPlayer();
        if (!player.getUniqueId().equals(msg.gameUuid())) return;
        if (msg.type() == ProxyTokenSigner.MessageType.BACKEND_AUTH_OK) {
            if (config.authServers().isEmpty()
                    || config.authServers().contains(sc.getServerInfo().getName().toLowerCase(Locale.ROOT))) {
                authenticatedPlayers.add(msg.gameUuid());
            }
        } else if (msg.type() == ProxyTokenSigner.MessageType.LOGOUT) {
            authenticatedPlayers.remove(msg.gameUuid());
        }
    }

    @Subscribe
    public void onDisconnect(DisconnectEvent event) {
        String name = event.getPlayer().getUsername();
        pendingDenials.remove(UsernameValidator.normalizeLower(name));
        authenticatedPlayers.remove(event.getPlayer().getUniqueId());
        if (proxyAuth != null) {
            proxyAuth.onDisconnect(name);
        }
    }

    private void initFloodgateReflection() {
        if (!server.getPluginManager().isLoaded("floodgate")) return;
        try {
            Class<?> cls = Class.forName("org.geysermc.floodgate.api.FloodgateApi");
            this.floodgateApi = cls.getMethod("getInstance").invoke(null);
            this.floodgateCheck = cls.getMethod("isFloodgatePlayer", UUID.class);
        } catch (Throwable ignored) {
            this.floodgateApi = null;
            this.floodgateCheck = null;
        }
    }

    private boolean isFloodgate(@Nullable UUID uuid) {
        return isFloodgate(uuid, floodgateApi, floodgateCheck);
    }

    static boolean isFloodgate(@Nullable UUID uuid, @Nullable Object api, @Nullable Method checkMethod) {
        if (uuid == null || uuid.getMostSignificantBits() != 0L || api == null || checkMethod == null) {
            return false;
        }
        try {
            return Boolean.TRUE.equals(checkMethod.invoke(api, uuid));
        } catch (Throwable ignored) {
            return false;
        }
    }

    static String extractIp(@Nullable InboundConnection conn) {
        if (conn == null) return "unknown";
        InetSocketAddress addr = conn.getRemoteAddress();
        if (addr != null && addr.getAddress() != null) {
            return addr.getAddress().getHostAddress();
        }
        return "unknown";
    }
}

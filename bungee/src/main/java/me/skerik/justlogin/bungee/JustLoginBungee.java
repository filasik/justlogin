package me.skerik.justlogin.bungee;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import me.skerik.justlogin.core.crypto.ProxyTokenSigner;
import me.skerik.justlogin.core.crypto.ServerSecrets;
import me.skerik.justlogin.core.service.MojangApiClient;
import me.skerik.justlogin.core.service.ProxyAuthService;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import me.skerik.justlogin.core.storage.Database;
import me.skerik.justlogin.core.storage.DbConfig;
import me.skerik.justlogin.core.storage.Migrations;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.config.ServerInfo;
import net.md_5.bungee.api.connection.PendingConnection;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.connection.Server;
import net.md_5.bungee.api.event.LoginEvent;
import net.md_5.bungee.api.event.PlayerDisconnectEvent;
import net.md_5.bungee.api.event.PluginMessageEvent;
import net.md_5.bungee.api.event.PreLoginEvent;
import net.md_5.bungee.api.event.ServerConnectEvent;
import net.md_5.bungee.api.event.ServerConnectedEvent;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.event.EventHandler;
import net.md_5.bungee.event.EventPriority;
import org.bstats.bungeecord.Metrics;
import org.bstats.charts.SimplePie;
import org.jspecify.annotations.Nullable;

/** BungeeCord proxy entrypoint for JustLogin. */
public final class JustLoginBungee extends Plugin implements Listener {

    private static final String REPO = "https://github.com/filasik/justLogin";

    private volatile @Nullable BungeeConfig config;
    private volatile @Nullable Database database;
    private volatile @Nullable ProxyAuthService proxyAuth;
    private volatile @Nullable ProxyTokenSigner signer;
    private volatile boolean misconfigured;
    private final Set<UUID> authenticatedPlayers = ConcurrentHashMap.newKeySet();

    private @Nullable Object floodgateApi;
    private @Nullable Method floodgateCheck;

    @Override
    public void onEnable() {
        long started = System.nanoTime();
        try {
            Path dataDir = getDataFolder().toPath();
            BungeeConfig cfg = BungeeConfig.load(dataDir);
            this.config = cfg;
            Files.createDirectories(dataDir.resolve("data"));
            ServerSecrets secrets = ServerSecrets.loadOrCreate(dataDir.resolve("secrets.key"));

            int schemaVersion = 0;
            if (!cfg.isSecretValid()) {
                getLogger().severe("proxy.shared-secret in JustLogin Bungee config.yml is missing or still uses the default placeholder! "
                        + "Set a shared secret >= 16 characters matching Paper config.yml.");
                this.misconfigured = true;
            } else {
                if (cfg.dbConfig().dialect() == DbConfig.Dialect.SQLITE) {
                    getLogger().warning("storage.type is set to 'sqlite' on BungeeCord! Proxy and Paper backends MUST share the same database "
                            + "(use 'mariadb' unless SQLite points to the exact same shared file path on a single machine).");
                }
                if (cfg.authServers().isEmpty()) {
                    getLogger().warning("proxy.auth-servers is empty! Unauthenticated players are not locked to a dedicated auth/limbo server on the proxy.");
                }
                secrets = secrets.withProxySecret(cfg.sharedSecret());
                this.database = new Database(cfg.dbConfig());
                schemaVersion = Migrations.migrate(this.database);
                this.proxyAuth = new ProxyAuthService(
                        new AccountStore(this.database),
                        new AuditStore(this.database),
                        new MojangApiClient(cfg.core().mojangCacheSeconds(), System::currentTimeMillis),
                        secrets,
                        () -> {
                            BungeeConfig current = this.config;
                            return current != null ? current.core() : cfg.core();
                        },
                        System::currentTimeMillis);
                this.signer = new ProxyTokenSigner(secrets.proxySecret());
            }

            getProxy().registerChannel(ProxyTokenSigner.CHANNEL);
            getProxy().getPluginManager().registerListener(this, this);
            initFloodgateReflection();
            if (!misconfigured) {
                Properties buildProps = readBuildProperties();
                int bstatsId = parseIntOrZero(buildProps.getProperty("bstats-id", "0"));
                boolean metricsActive = false;
                if (cfg.metrics() && bstatsId > 0) {
                    Metrics m = new Metrics(this, bstatsId);
                    m.addCustomChart(new SimplePie("storage", () -> cfg.dbConfig().dialect().name().toLowerCase(Locale.ROOT)));
                    m.addCustomChart(new SimplePie("mojang_autodetect", () -> Boolean.toString(cfg.core().premiumAutoDetect())));
                    metricsActive = true;
                }
                long ms = Math.max(1L, (System.nanoTime() - started) / 1_000_000L);
                printBanner(getDescription().getVersion(), cfg, schemaVersion, metricsActive, ms);
            }
        } catch (Exception e) {
            getLogger().severe("Failed to enable JustLogin Bungee: " + e.getMessage());
            this.misconfigured = true;
        }
    }

    private void printBanner(String version, BungeeConfig cfg, int schemaVersion, boolean metricsActive, long ms) {
        Map<String, String> details = new LinkedHashMap<>();
        details.put("storage", cfg.dbConfig().dialect().name().toLowerCase(Locale.ROOT) + " (schema v" + schemaVersion + ")");
        details.put("mojang", cfg.core().premiumAutoDetect() ? "auto-detect on" : "auto-detect off");
        details.put("metrics", metricsActive ? "bStats active" : "disabled");

        getLogger().info("");
        getLogger().info("  ┌─ JustLogin v" + version + " · BungeeCord");
        getLogger().info("  │");
        for (Map.Entry<String, String> row : details.entrySet()) {
            getLogger().info("  │  " + String.format("%-9s", row.getKey()) + " " + row.getValue());
        }
        getLogger().info("  │");
        getLogger().info("  └─ Ready in " + ms + " ms · " + REPO);
        getLogger().info("");
    }

    private static Properties readBuildProperties() {
        Properties props = new Properties();
        try (InputStream in = JustLoginBungee.class.getResourceAsStream("/build.properties")) {
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

    @Override
    public void onDisable() {
        if (database != null) database.close();
    }

    @EventHandler(priority = EventPriority.LOW)
    public void onPreLogin(PreLoginEvent event) {
        BungeeConfig cfg = this.config;
        ProxyAuthService auth = this.proxyAuth;
        if (misconfigured || auth == null || cfg == null) {
            event.setCancelled(true);
            String msg = cfg != null ? cfg.missingSecretMessage() : ProxyMessages.notReady("en");
            event.setReason(new TextComponent(msg));
            return;
        }

        PendingConnection conn = event.getConnection();
        boolean fg = cfg.floodgateFallback() && isFloodgate(conn.getUniqueId());
        event.registerIntent(this);
        getProxy().getScheduler().runAsync(this, () -> {
            try {
                var dec = auth.decidePreLogin(conn.getName(), fg).join();
                switch (dec.action()) {
                    case DENY_INVALID_USERNAME -> {
                        event.setCancelled(true);
                        event.setReason(new TextComponent(cfg.invalidUsernameMessage()));
                    }
                    case DENY_MOJANG_UNAVAILABLE -> {
                        event.setCancelled(true);
                        event.setReason(new TextComponent(
                                cfg.formatDenyReason(ProxyAuthService.DenyReason.MOJANG_UNAVAILABLE)));
                    }
                    case FORCE_ONLINE -> conn.setOnlineMode(true);
                    case FORCE_OFFLINE, ALLOW_OFFLINE -> {
                        if (!fg) conn.setOnlineMode(false);
                    }
                }
            } catch (Exception e) {
                event.setCancelled(true);
                event.setReason(new TextComponent(cfg.authServiceErrorMessage()));
            } finally {
                event.completeIntent(this);
            }
        });
    }

    @EventHandler(priority = EventPriority.LOW)
    public void onLogin(LoginEvent event) {
        BungeeConfig cfg = this.config;
        ProxyAuthService auth = this.proxyAuth;
        if (misconfigured || auth == null || cfg == null) {
            event.setCancelled(true);
            String msg = cfg != null ? cfg.missingSecretMessage() : ProxyMessages.notReady("en");
            event.setReason(new TextComponent(msg));
            return;
        }
        PendingConnection conn = event.getConnection();
        String ip = extractIp(conn);
        event.registerIntent(this);
        getProxy().getScheduler().runAsync(this, () -> {
            try {
                var res = auth.resolveJoinProfile(conn.getName(), conn.getUniqueId(), conn.isOnlineMode(), ip).join();
                if (!res.allowed()) {
                    event.setCancelled(true);
                    event.setReason(new TextComponent(cfg.formatDeny(res)));
                    return;
                }
                UUID finalUuid = res.targetGameUuid() != null ? res.targetGameUuid() : conn.getUniqueId();
                if (res.targetGameUuid() != null && !res.targetGameUuid().equals(conn.getUniqueId())) {
                    if (!applyUniqueId(conn, res.targetGameUuid(), getLogger())) {
                        event.setCancelled(true);
                        event.setReason(new TextComponent(cfg.authServiceErrorMessage()));
                        return;
                    }
                }
                if (res.onlineAuthenticated()) {
                    authenticatedPlayers.add(finalUuid);
                }
            } catch (Exception e) {
                event.setCancelled(true);
                event.setReason(new TextComponent(cfg.authServiceErrorMessage()));
            } finally {
                event.completeIntent(this);
            }
        });
    }

    @EventHandler(priority = EventPriority.HIGH)
    public void onServerConnect(ServerConnectEvent event) {
        BungeeConfig cfg = this.config;
        if (cfg == null || cfg.authServers().isEmpty()) return;
        ProxiedPlayer player = event.getPlayer();
        if (authenticatedPlayers.contains(player.getUniqueId())) return;
        String targetName = event.getTarget() != null ? event.getTarget().getName().toLowerCase(Locale.ROOT) : "";
        if (cfg.authServers().contains(targetName)) return;

        if (player.getServer() == null) {
            for (String authName : cfg.authServers()) {
                ServerInfo info = getProxy().getServerInfo(authName);
                if (info != null) {
                    event.setTarget(info);
                    return;
                }
            }
            event.setCancelled(true);
            player.disconnect(new TextComponent(cfg.authServerUnavailableMessage()));
            return;
        }
        event.setCancelled(true);
        player.sendMessage(new TextComponent(cfg.authRequiredServerMessage()));
    }

    @EventHandler
    public void onServerConnected(ServerConnectedEvent event) {
        if (misconfigured || proxyAuth == null || signer == null) return;
        ProxiedPlayer player = event.getPlayer();
        byte[] signed = proxyAuth.signBackendMessageIfOnline(signer, player.getName(), player.getUniqueId());
        if (signed != null) {
            authenticatedPlayers.add(player.getUniqueId());
            event.getServer().sendData(ProxyTokenSigner.CHANNEL, signed);
        }
    }

    @EventHandler
    public void onPluginMessage(PluginMessageEvent event) {
        if (!ProxyTokenSigner.CHANNEL.equals(event.getTag())) return;
        // Drop all client-originated or unconsumed justlogin:auth packets
        if (!(event.getSender() instanceof Server srv)) {
            event.setCancelled(true);
            return;
        }
        event.setCancelled(true);
        if (signer == null || config == null) return;
        ProxyTokenSigner.VerifiedMessage msg = signer.verify(event.getData(), System.currentTimeMillis());
        if (msg == null) return;
        ProxiedPlayer target = getProxy().getPlayer(msg.gameUuid());
        if (target == null || target.getServer() == null || !target.getServer().equals(srv)) return;
        if (msg.type() == ProxyTokenSigner.MessageType.BACKEND_AUTH_OK) {
            if (config.authServers().isEmpty()
                    || config.authServers().contains(srv.getInfo().getName().toLowerCase(Locale.ROOT))) {
                authenticatedPlayers.add(msg.gameUuid());
            }
        } else if (msg.type() == ProxyTokenSigner.MessageType.LOGOUT) {
            authenticatedPlayers.remove(msg.gameUuid());
        }
    }

    @EventHandler
    public void onDisconnect(PlayerDisconnectEvent event) {
        authenticatedPlayers.remove(event.getPlayer().getUniqueId());
        if (proxyAuth != null) {
            proxyAuth.onDisconnect(event.getPlayer().getName());
        }
    }

    private void initFloodgateReflection() {
        if (getProxy().getPluginManager().getPlugin("floodgate") == null) return;
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

    static boolean applyUniqueId(PendingConnection conn, UUID targetUuid, @Nullable Logger logger) {
        Field uniqueIdField = findUniqueIdField(conn.getClass());
        if (uniqueIdField != null) {
            try {
                uniqueIdField.setAccessible(true);
                uniqueIdField.set(conn, targetUuid);
                return true;
            } catch (ReflectiveOperationException | RuntimeException e) {
                if (logger != null) {
                    logger.severe("Failed to rewrite PendingConnection uniqueId via reflection for "
                            + conn.getName() + ": " + e.getMessage());
                }
                return false;
            }
        }
        try {
            conn.setUniqueId(targetUuid);
            return true;
        } catch (RuntimeException e) {
            if (logger != null) {
                logger.severe("Failed to set PendingConnection uniqueId for "
                        + conn.getName() + ": " + e.getMessage());
            }
            return false;
        }
    }

    private static @Nullable Field findUniqueIdField(@Nullable Class<?> type) {
        for (Class<?> cur = type; cur != null && cur != Object.class; cur = cur.getSuperclass()) {
            try {
                Field f = cur.getDeclaredField("uniqueId");
                if (UUID.class.isAssignableFrom(f.getType())) {
                    return f;
                }
            } catch (NoSuchFieldException ignored) {
            }
        }
        return null;
    }

    static String extractIp(PendingConnection conn) {
        if (conn.getSocketAddress() instanceof InetSocketAddress isa && isa.getAddress() != null) {
            return isa.getAddress().getHostAddress();
        }
        return "unknown";
    }
}

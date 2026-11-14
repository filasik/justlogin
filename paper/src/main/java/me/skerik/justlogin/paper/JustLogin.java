package me.skerik.justlogin.paper;

import io.papermc.paper.plugin.lifecycle.event.types.LifecycleEvents;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import me.skerik.justlogin.api.JustLoginAPI;
import me.skerik.justlogin.core.crypto.ProxyTokenSigner;
import me.skerik.justlogin.core.crypto.ServerSecrets;
import me.skerik.justlogin.core.importer.MigrationScanner;
import me.skerik.justlogin.core.storage.Database;
import me.skerik.justlogin.core.storage.Migrations;
import me.skerik.justlogin.paper.command.AdminCommands;
import me.skerik.justlogin.paper.command.AuthCommands;
import me.skerik.justlogin.paper.command.EmailCommands;
import me.skerik.justlogin.paper.command.SkinCommands;
import me.skerik.justlogin.paper.config.ConfigUpdater;
import me.skerik.justlogin.paper.config.Messages;
import me.skerik.justlogin.paper.config.Settings;
import me.skerik.justlogin.paper.listener.ConfigureAuthListener;
import me.skerik.justlogin.paper.listener.PlayerLifecycleListener;
import me.skerik.justlogin.paper.listener.PreAuthProtectionListener;
import me.skerik.justlogin.paper.listener.ProxyMessageListener;
import me.skerik.justlogin.paper.util.Banner;
import me.skerik.justlogin.paper.util.LogPasswordFilter;
import me.skerik.justlogin.paper.util.Stats;
import me.skerik.justlogin.paper.util.UpdateChecker;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.PluginManager;
import org.bukkit.plugin.ServicePriority;
import org.bukkit.plugin.java.JavaPlugin;
import org.jspecify.annotations.Nullable;

/** Paper entrypoint for JustLogin with async two-phase storage initialization. */
public final class JustLogin extends JavaPlugin {

    private long enableStarted;
    private Scheduler scheduler;
    private volatile Messages earlyMessages;
    private volatile @Nullable Context context;
    private volatile @Nullable Database openingDatabase;
    private volatile boolean shuttingDown;
    private @Nullable Stats stats;
    private @Nullable LogPasswordFilter logFilter;
    private @Nullable Runnable cleanupTask;
    private @Nullable Runnable updateTask;
    private @Nullable UpdateChecker updater;

    @Override
    public void onEnable() {
        this.enableStarted = System.nanoTime();
        saveDefaultConfig();
        ConfigUpdater.update(this);
        reloadConfig();

        Settings initialSettings = Settings.load(getConfig(), getDataFolder().toPath());
        this.earlyMessages = new Messages(this);
        this.earlyMessages.load(initialSettings.language());
        this.scheduler = new PaperScheduler(this);
        this.logFilter = LogPasswordFilter.installOnRoot();

        PluginManager pm = getServer().getPluginManager();
        pm.registerEvents(new ConfigureAuthListener(this), this);
        pm.registerEvents(new PlayerLifecycleListener(this), this);
        pm.registerEvents(new PreAuthProtectionListener(this), this);

        ProxyMessageListener proxyMessenger = new ProxyMessageListener(this);
        Bukkit.getMessenger().registerIncomingPluginChannel(this, ProxyTokenSigner.CHANNEL, proxyMessenger);
        Bukkit.getMessenger().registerOutgoingPluginChannel(this, ProxyTokenSigner.CHANNEL);

        AuthCommands authCommands = new AuthCommands(this, proxyMessenger);
        AdminCommands adminCommands = new AdminCommands(this);
        EmailCommands emailCommands = new EmailCommands(this);
        SkinCommands skinCommands = new SkinCommands(this);
        getLifecycleManager().registerEventHandler(LifecycleEvents.COMMANDS, event -> {
            authCommands.register(event.registrar());
            adminCommands.register(event.registrar());
            emailCommands.register(event.registrar());
            skinCommands.register(event.registrar());
        });

        Path dataDir = getDataFolder().toPath();
        scheduler.runAsync(() -> openStorage(dataDir, initialSettings));
    }

    private void openStorage(Path dataDir, Settings initialSettings) {
        ServerSecrets secrets;
        try {
            Files.createDirectories(dataDir.resolve("data"));
            secrets = ServerSecrets.loadOrCreate(dataDir.resolve("secrets.key"));
        } catch (IOException e) {
            getLogger().severe("Failed to load/create secrets.key: " + e.getMessage());
            scheduler.runGlobal(() -> getServer().getPluginManager().disablePlugin(this));
            return;
        }

        Database database = new Database(initialSettings.dbConfig());
        this.openingDatabase = database;
        if (shuttingDown) {
            database.close();
            this.openingDatabase = null;
            return;
        }
        int schemaVersion;
        try {
            schemaVersion = Migrations.migrate(database);
        } catch (Exception e) {
            getLogger().severe("Database migration failed: " + e.getMessage());
            database.close();
            this.openingDatabase = null;
            scheduler.runGlobal(() -> getServer().getPluginManager().disablePlugin(this));
            return;
        }

        scheduler.runGlobal(() -> finishStartup(initialSettings, database, secrets, schemaVersion));
    }

    private void finishStartup(Settings initialSettings, Database database, ServerSecrets secrets, int schemaVersion) {
        this.openingDatabase = null;
        if (!isEnabled() || shuttingDown) {
            database.close();
            return;
        }

        Context ctx = new Context(this, scheduler, initialSettings, earlyMessages, database, secrets);
        ctx.standalonePremium().install();
        getServer().getPluginManager().registerEvents(ctx.adminGui(), this);
        getServer().getServicesManager().register(
                JustLoginAPI.class, new JustLoginApiImpl(ctx), this, ServicePriority.Normal);
        this.context = ctx;
        this.stats = Stats.start(this, initialSettings);

        this.cleanupTask = scheduler.runAsyncTimer(() -> {
            ctx.authService().maintenanceCleanup();
            ctx.editorService().pruneExpired();
            ctx.standalonePremium().pruneExpired();
            ctx.captchaManager().pruneExpired();
            ctx.sessionManager().pruneExpired();
            ctx.pruneExpiredCooldowns();
        }, 20L * 60L, 20L * 60L * 5L);

        if (initialSettings.checkUpdates()) {
            this.updater = new UpdateChecker(getPluginMeta().getVersion(), getLogger());
            long twelveHoursTicks = 20L * 60L * 60L * 12L;
            this.updateTask = scheduler.runAsyncTimer(updater::check, 20L, twelveHoursTicks);
        }

        List<String> conflicts = new ArrayList<>();
        for (String legacyName : MigrationScanner.LEGACY_PLUGIN_NAMES) {
            var loaded = getServer().getPluginManager().getPlugin(legacyName);
            if (loaded != null && loaded.isEnabled()) {
                conflicts.add(loaded.getName());
            }
        }
        ctx.setActiveConflictingPlugins(conflicts);
        if (!conflicts.isEmpty()) {
            getLogger().warning("[Migration] Conflicting auth plugin(s) currently enabled: "
                    + String.join(", ", conflicts)
                    + ". Remove their .jar files from plugins/ after running /jl import auto!");
        }

        Path pluginsDir = getDataFolder().toPath().toAbsolutePath().normalize().getParent();
        scheduler.runAsync(() -> {
            List<MigrationScanner.DetectedSource> detected = MigrationScanner.scan(pluginsDir);
            ctx.setDetectedMigrations(detected);
            if (!detected.isEmpty()) {
                String summary = detected.stream()
                        .map(s -> s.displayName() + " [" + s.summary() + "]")
                        .reduce((a, b) -> a + ", " + b)
                        .orElse("");
                getLogger().info("[Migration] Detected " + detected.size()
                        + " legacy auth database(s): " + summary
                        + ". Run '/jl import auto' (or '/jl import auto --dry-run') to migrate.");
            }
        });

        Map<String, String> details = new LinkedHashMap<>();
        details.put("storage", initialSettings.dbConfig().dialect().name().toLowerCase(Locale.ROOT)
                + " (schema v" + schemaVersion + ")");
        String hookNote = initialSettings.proxyEnabled()
                ? " · proxy " + initialSettings.proxyMode().name().toLowerCase(Locale.ROOT)
                : (ctx.isStandalonePremiumActive()
                        ? " · standalone + premium (hook active)"
                        : (initialSettings.standalonePremiumEnabled() && !getServer().getOnlineMode()
                                ? " · standalone (hook unavailable)"
                                : " · standalone"));
        details.put("auth", initialSettings.loginUi().name().toLowerCase(Locale.ROOT) + hookNote);
        details.put("locale", initialSettings.language());
        details.put("metrics", stats.active() ? "bStats active" : "disabled");

        long startupMs = Math.max(1L, (System.nanoTime() - enableStarted) / 1_000_000L);
        Banner.print(
                getComponentLogger(),
                getPluginMeta().getVersion(),
                getServer().getMinecraftVersion(),
                details,
                startupMs);
    }

    @Override
    public void onDisable() {
        this.shuttingDown = true;
        if (cleanupTask != null) cleanupTask.run();
        if (updateTask != null) updateTask.run();
        if (stats != null) stats.close();
        if (logFilter != null) logFilter.uninstallFromRoot();
        Bukkit.getMessenger().unregisterIncomingPluginChannel(this, ProxyTokenSigner.CHANNEL);
        Bukkit.getMessenger().unregisterOutgoingPluginChannel(this, ProxyTokenSigner.CHANNEL);
        if (context != null) {
            getServer().getServicesManager().unregisterAll(this);
            context.closeLocalEditor();
            context.standalonePremium().uninstall();
            context.sessionManager().clearAll();
            context.hashing().close();
            context.database().close();
        } else if (openingDatabase != null) {
            openingDatabase.close();
            openingDatabase = null;
        }
    }

    public void reloadPluginConfig() {
        Context ctx = this.context;
        if (ctx == null) return;
        reloadConfig();
        Settings reloaded = Settings.load(getConfig(), getDataFolder().toPath());
        ctx.reloadSettings(reloaded);
    }

    public void notifyUpdateIfAvailable(Player player) {
        UpdateChecker u = this.updater;
        Context ctx = this.context;
        if (u == null || ctx == null || !player.hasPermission("justlogin.admin")) return;
        String newer = u.newerVersion();
        if (newer == null) return;
        String releaseUrl = u.url() != null ? u.url() : Banner.REPO + "/releases";
        ctx.messages().send(player, "update.available", Map.of("version", newer, "url", releaseUrl));
    }

    public void notifyMigrationsIfAvailable(Player player) {
        Context ctx = this.context;
        if (ctx == null) return;
        if (!player.hasPermission("justlogin.admin") && !player.hasPermission("justlogin.admin.import")) {
            return;
        }
        List<String> conflicts = ctx.activeConflictingPlugins();
        if (!conflicts.isEmpty()) {
            ctx.messages().send(player, "admin.migration-conflict-warning",
                    Map.of("plugins", String.join(", ", conflicts)));
        }
        List<MigrationScanner.DetectedSource> detected = ctx.detectedMigrations();
        if (!detected.isEmpty()) {
            ctx.messages().send(player, "admin.migration-detected-header",
                    Map.of("count", String.valueOf(detected.size())));
            for (MigrationScanner.DetectedSource src : detected) {
                ctx.messages().sendRaw(player, "admin.migration-detected-line",
                        Map.of("source", src.displayName(), "summary", src.summary()));
            }
            ctx.messages().sendRaw(player, "admin.migration-detected-auto-btn");
        }
    }

    public @Nullable Context context() {
        return context;
    }

    public Messages earlyMessages() {
        return earlyMessages;
    }

    public @Nullable UpdateChecker updater() {
        return updater;
    }
}

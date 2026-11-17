package me.skerik.justlogin.paper;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import me.skerik.justlogin.core.crypto.HashingExecutor;
import me.skerik.justlogin.core.crypto.ProxyTokenSigner;
import me.skerik.justlogin.core.crypto.ServerSecrets;
import me.skerik.justlogin.core.importer.MigrationScanner;
import me.skerik.justlogin.core.security.LoginRateLimiter;
import me.skerik.justlogin.core.security.UsernameValidator;
import me.skerik.justlogin.core.service.AuthService;
import me.skerik.justlogin.core.service.EmailRecoveryService;
import me.skerik.justlogin.core.service.MojangApiClient;
import me.skerik.justlogin.core.service.MojangSkinClient;
import me.skerik.justlogin.core.service.MojangSessionClient;
import me.skerik.justlogin.core.service.SmtpMailer;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import me.skerik.justlogin.core.storage.BackupCodeStore;
import me.skerik.justlogin.core.storage.Database;
import me.skerik.justlogin.core.storage.SessionStore;
import me.skerik.justlogin.editor.EditorService;
import me.skerik.justlogin.editor.LocalHttpEditorServer;
import me.skerik.justlogin.paper.auth.AuthSessionManager;
import me.skerik.justlogin.paper.auth.CaptchaManager;
import me.skerik.justlogin.paper.auth.PaperAuthCoordinator;
import me.skerik.justlogin.paper.command.HelpRenderer;
import me.skerik.justlogin.paper.config.Messages;
import me.skerik.justlogin.paper.config.Settings;
import me.skerik.justlogin.paper.dialog.DialogUi;
import me.skerik.justlogin.paper.dialog.PaperDialogUi;
import me.skerik.justlogin.paper.gui.AdminGui;
import me.skerik.justlogin.paper.totp.TotpQrMapManager;
import me.skerik.justlogin.paper.premium.StandaloneLoginBridge;
import me.skerik.justlogin.paper.premium.StandalonePremiumManager;
import me.skerik.justlogin.paper.util.ClientCapabilityCheck;
import me.skerik.justlogin.paper.util.ProxyStartupCheck;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;
import org.jspecify.annotations.Nullable;

/** Central dependency container for the Paper plugin runtime. */
public final class Context {

    private final JavaPlugin plugin;
    private final Scheduler scheduler;
    private final Logger logger;
    private final Messages messages;
    private final Database database;
    private volatile ServerSecrets secrets;
    private final HashingExecutor hashing;
    private final LoginRateLimiter rateLimiter;
    private final AccountStore accounts;
    private final SessionStore sessions;
    private final BackupCodeStore backupCodes;
    private final AuditStore audit;
    private final AuthService authService;
    private final EmailRecoveryService emailRecovery;
    private final EditorService editorService;
    private final AuthSessionManager sessionManager;
    private final CaptchaManager captchaManager;
    private final DialogUi dialogUi;
    private final AdminGui adminGui;
    private final TotpQrMapManager totpQrMaps;
    private final ClientCapabilityCheck capabilities;
    private final PaperAuthCoordinator coordinator;
    private final StandalonePremiumManager standalonePremium;
    private final MojangSkinClient skinClient;
    private final Map<UUID, Long> skinCooldownUntil = new ConcurrentHashMap<>();

    private volatile Settings settings;
    private volatile @Nullable ProxyTokenSigner proxySigner;
    private volatile boolean proxyMisconfigured;
    private volatile boolean paperForwardingEnabled;
    private volatile @Nullable LocalHttpEditorServer localEditorServer;
    private volatile List<MigrationScanner.DetectedSource> detectedMigrations = List.of();
    private volatile List<String> activeConflictingPlugins = List.of();

    public Context(
            JavaPlugin plugin,
            Scheduler scheduler,
            Settings initialSettings,
            Messages messages,
            Database database,
            ServerSecrets baseSecrets
    ) {
        this.plugin = plugin;
        this.scheduler = scheduler;
        this.logger = plugin.getLogger();
        this.settings = initialSettings;
        this.messages = messages;
        this.database = database;
        this.secrets = baseSecrets;
        this.hashing = new HashingExecutor(
                initialSettings.core().maxConcurrentHashes(),
                initialSettings.core().maxQueuedHashes());
        this.rateLimiter = new LoginRateLimiter(System::currentTimeMillis);
        this.accounts = new AccountStore(database);
        this.sessions = new SessionStore(database);
        this.backupCodes = new BackupCodeStore(database);
        this.audit = new AuditStore(database);
        this.authService = new AuthService(
                accounts, sessions, backupCodes, audit, secrets, hashing, rateLimiter,
                () -> this.settings.core(), System::currentTimeMillis);
        this.emailRecovery = new EmailRecoveryService(
                accounts, sessions, audit, secrets, hashing, rateLimiter,
                new SmtpMailer(() -> this.settings.smtpConfig()),
                () -> this.settings.core(), () -> this.settings.smtpConfig(), System::currentTimeMillis);
        this.editorService = new EditorService(accounts, audit, System::currentTimeMillis);
        this.sessionManager = new AuthSessionManager();
        this.captchaManager = new CaptchaManager(System::currentTimeMillis);
        this.dialogUi = new PaperDialogUi(messages, () -> this.settings.dialogSinglePassword());
        this.adminGui = new AdminGui(this);
        this.capabilities = new ClientCapabilityCheck();
        this.coordinator = new PaperAuthCoordinator(this);
        StandaloneLoginBridge loginBridge = StandaloneLoginBridge.tryCreate(this.logger);
        this.standalonePremium = new StandalonePremiumManager(
                this.scheduler,
                this.messages,
                this.capabilities,
                this.accounts,
                this.audit,
                this.secrets,
                () -> this.settings,
                () -> this.paperForwardingEnabled,
                loginBridge,
                new MojangSessionClient()
        );
        MojangApiClient skinMojangApi = new MojangApiClient(
                () -> this.settings.skinsCacheSeconds(), System::currentTimeMillis);
        this.skinClient = new MojangSkinClient(
                skinMojangApi, () -> this.settings.skinsCacheSeconds(), System::currentTimeMillis);
        this.totpQrMaps = new TotpQrMapManager(this);
        applyProxySettings(initialSettings);
        applyEditorSettings(initialSettings);
    }

    public void reloadSettings(Settings reloaded) {
        this.settings = reloaded;
        this.messages.load(reloaded.language());
        this.skinClient.clearCache();
        applyProxySettings(reloaded);
        applyEditorSettings(reloaded);
    }

    private synchronized void applyEditorSettings(Settings s) {
        if (localEditorServer != null) {
            localEditorServer.close();
            localEditorServer = null;
        }
        if (!s.editorLocalHttpEnabled()) return;
        try {
            localEditorServer = LocalHttpEditorServer.start(s.editorLocalHttpBind(), s.editorLocalHttpPort());
            logger.info("Local loopback web editor enabled at " + localEditorServer.baseUrl());
        } catch (Exception e) {
            logger.warning("Could not start local web editor HTTP server: " + e.getMessage());
        }
    }

    public void closeLocalEditor() {
        LocalHttpEditorServer srv = this.localEditorServer;
        if (srv != null) {
            srv.close();
            this.localEditorServer = null;
        }
    }

    public String effectiveEditorWebUrl() {
        LocalHttpEditorServer srv = this.localEditorServer;
        return srv != null ? srv.baseUrl() : settings.editorWebUrl();
    }

    public String effectiveEditorRelayUrl() {
        LocalHttpEditorServer srv = this.localEditorServer;
        return srv != null ? srv.baseUrl() : settings.editorRelayUrl();
    }

    public boolean isLocalEditorRunning() {
        return this.localEditorServer != null;
    }

    public void notifyProxyState(Player player, ProxyTokenSigner.MessageType type, long accountId) {
        ProxyTokenSigner signer = this.proxySigner;
        if (signer == null || !settings.proxyEnabled() || proxyMisconfigured) return;
        byte[] payload = signer.sign(
                type, accountId, UsernameValidator.normalizeLower(player.getName()),
                player.getUniqueId(), System.currentTimeMillis());
        player.sendPluginMessage(plugin, ProxyTokenSigner.CHANNEL, payload);
    }

    private void applyProxySettings(Settings s) {
        Path serverRoot = plugin.getDataFolder().toPath().toAbsolutePath().normalize().getParent();
        if (serverRoot != null && serverRoot.getParent() != null) {
            serverRoot = serverRoot.getParent();
        } else {
            serverRoot = Path.of(".").toAbsolutePath().normalize();
        }
        this.paperForwardingEnabled = ProxyStartupCheck.isPaperProxyForwardingEnabled(serverRoot);
        ProxyStartupCheck.CheckResult check = ProxyStartupCheck.evaluate(s, serverRoot);
        for (String w : check.warnings()) {
            logger.warning("[ProxyCheck] " + w);
        }
        if (!check.healthy()) {
            for (String err : check.errors()) {
                logger.severe("[ProxyCheck] " + err);
            }
            logger.severe("[ProxyCheck] Failing closed: incoming connections will be rejected until proxy configuration is fixed.");
            this.proxyMisconfigured = true;
            this.proxySigner = null;
            return;
        }
        this.proxyMisconfigured = false;
        if (s.proxyEnabled() && !s.proxySharedSecret().isBlank()) {
            this.proxySigner = new ProxyTokenSigner(secrets.withProxySecret(s.proxySharedSecret()).proxySecret());
        } else {
            this.proxySigner = null;
        }
    }

    public JavaPlugin plugin() { return plugin; }
    public Scheduler scheduler() { return scheduler; }
    public Logger logger() { return logger; }
    public Settings settings() { return settings; }
    public Messages messages() { return messages; }
    public Database database() { return database; }
    public ServerSecrets secrets() { return secrets; }
    public HashingExecutor hashing() { return hashing; }
    public LoginRateLimiter rateLimiter() { return rateLimiter; }
    public AccountStore accounts() { return accounts; }
    public SessionStore sessions() { return sessions; }
    public BackupCodeStore backupCodes() { return backupCodes; }
    public AuditStore audit() { return audit; }
    public AuthService authService() { return authService; }
    public EmailRecoveryService emailRecovery() { return emailRecovery; }
    public EditorService editorService() { return editorService; }
    public AuthSessionManager sessionManager() { return sessionManager; }
    public CaptchaManager captchaManager() { return captchaManager; }
    public DialogUi dialogUi() { return dialogUi; }
    public TotpQrMapManager totpQrMaps() { return totpQrMaps; }

    public AdminGui adminGui() { return adminGui; }
    public ClientCapabilityCheck capabilities() { return capabilities; }
    public PaperAuthCoordinator coordinator() { return coordinator; }
    public StandalonePremiumManager standalonePremium() { return standalonePremium; }
    public MojangSkinClient skinClient() { return skinClient; }
    public boolean isStandalonePremiumActive() { return standalonePremium.isActiveRuntime(); }
    public @Nullable ProxyTokenSigner proxySigner() { return proxySigner; }
    public boolean isProxyMisconfigured() { return proxyMisconfigured; }

    public long remainingSkinCooldownSeconds(UUID playerUuid) {
        Long until = skinCooldownUntil.get(playerUuid);
        if (until == null) return 0L;
        long diffMs = until - System.currentTimeMillis();
        if (diffMs <= 0L) {
            skinCooldownUntil.remove(playerUuid, until);
            return 0L;
        }
        return (diffMs + 999L) / 1000L;
    }

    public void markSkinChanged(UUID playerUuid) {
        long cooldownSec = settings.skinCooldownSeconds();
        if (cooldownSec > 0L) {
            skinCooldownUntil.put(playerUuid, System.currentTimeMillis() + cooldownSec * 1000L);
        }
    }

    public void pruneExpiredCooldowns() {
        long now = System.currentTimeMillis();
        skinCooldownUntil.entrySet().removeIf(e -> e.getValue() <= now);
    }

    public HelpRenderer helpRenderer() {
        boolean onlineMode = Bukkit.getServer() != null && Bukkit.getServer().getOnlineMode();
        boolean premiumCapable = !onlineMode && (settings.proxyEnabled() || isStandalonePremiumActive());
        return new HelpRenderer(
                messages,
                plugin.getPluginMeta().getVersion(),
                settings.smtpConfig().enabled(),
                settings.captchaEnabled(),
                premiumCapable,
                settings.skinsEnabled() && settings.skinsCommandEnabled()
        );
    }

    public List<MigrationScanner.DetectedSource> detectedMigrations() {
        return detectedMigrations;
    }

    public void setDetectedMigrations(List<MigrationScanner.DetectedSource> detectedMigrations) {
        this.detectedMigrations = List.copyOf(detectedMigrations);
    }

    public List<String> activeConflictingPlugins() {
        return activeConflictingPlugins;
    }

    public void setActiveConflictingPlugins(List<String> activeConflictingPlugins) {
        this.activeConflictingPlugins = List.copyOf(activeConflictingPlugins);
    }
}

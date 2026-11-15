package me.skerik.justlogin.paper.listener;

import com.destroystokyo.paper.profile.PlayerProfile;
import com.destroystokyo.paper.profile.ProfileProperty;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import me.skerik.justlogin.api.AccountSnapshot;
import me.skerik.justlogin.api.event.PlayerAuthenticatedEvent;
import me.skerik.justlogin.api.event.PlayerPremiumVerifiedEvent;
import me.skerik.justlogin.core.crypto.ProxyTokenSigner;
import me.skerik.justlogin.core.model.Account;
import me.skerik.justlogin.core.security.UsernameValidator;
import me.skerik.justlogin.core.service.MojangSkinClient;
import me.skerik.justlogin.core.service.ProxyAuthService;
import me.skerik.justlogin.paper.Context;
import me.skerik.justlogin.paper.JustLogin;
import me.skerik.justlogin.paper.auth.AuthSessionManager.AuthState;
import me.skerik.justlogin.paper.auth.AuthSessionManager.PlayerSession;
import me.skerik.justlogin.paper.auth.AuthSessionManager.PreAuthGrant;
import me.skerik.justlogin.paper.auth.CaptchaManager.Challenge;
import me.skerik.justlogin.paper.command.SkinCommands;
import me.skerik.justlogin.paper.config.Settings;
import me.skerik.justlogin.paper.premium.StandalonePremiumManager;
import me.skerik.justlogin.paper.util.BedrockFormUi;
import net.kyori.adventure.text.Component;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;

/**
 * Handles early pre-login duplicate/misconfig rejection, Play-phase session initialization, timeouts, and cleanup.
 */
public final class PlayerLifecycleListener implements Listener {

    private final JustLogin plugin;
    private final java.util.Set<AsyncPlayerPreLoginEvent> eventsWithVerifiedGrant =
            java.util.concurrent.ConcurrentHashMap.newKeySet();

    public PlayerLifecycleListener(JustLogin plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onAsyncPreLogin(AsyncPlayerPreLoginEvent event) {
        Context ctx = plugin.context();
        if (ctx == null) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    plugin.earlyMessages().component("error.not-ready"));
            return;
        }
        if (ctx.isProxyMisconfigured()) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    ctx.messages().component("general.proxy-misconfigured"));
            return;
        }
        String name = event.getName();
        boolean floodgatePre = ctx.capabilities().isFloodgate(event.getUniqueId());
        if (!UsernameValidator.isValid(name, ctx.settings().core().usernamePattern(), floodgatePre)) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    ctx.messages().component("general.invalid-username"));
            return;
        }
        // Threat model #7 & P0-1: prevent unauthenticated attackers from kicking/replacing an active session or pending dialog
        if (ctx.settings().kickDuplicateOnline() && ctx.sessionManager().isOnlineAuthenticated(name)) {
            ctx.sessionManager().recordRejectedDuplicate(name);
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    ctx.messages().component("general.duplicate-online"));
            return;
        }
        if (ctx.sessionManager().hasActiveConfigAuth(name)) {
            ctx.sessionManager().recordRejectedDuplicate(name);
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    ctx.messages().component("auth.duplicate-connection-pending"));
            return;
        }

        StandalonePremiumManager standalone = ctx.standalonePremium();
        StandalonePremiumManager.VerifiedChannelData verified = standalone.consumeVerifiedChannel(event);
        String ip = event.getAddress() != null ? event.getAddress().getHostAddress() : "unknown";

        if (verified != null) {
            ProxyAuthService.JoinResolution res;
            try {
                res = standalone.resolveVerifiedJoin(verified.canonicalName(), verified.mojangUuid(), ip)
                        .get(10, TimeUnit.SECONDS);
            } catch (Exception e) {
                ctx.logger().warning("Standalone Mojang join resolution failed for " + verified.canonicalName() + ": " + e.getMessage());
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                        ctx.messages().component("general.internal-error"));
                return;
            }
            if (!res.allowed() || res.targetGameUuid() == null) {
                Component denyMsg = res.denyCode() != null
                        ? ctx.messages().component(res.denyCode().messageKey())
                        : Component.text(res.denyReason() != null ? res.denyReason() : "Authentication rejected.");
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, denyMsg);
                return;
            }
            UUID gameUuid = res.targetGameUuid();
            if (ctx.settings().kickDuplicateOnline()
                    && (ctx.sessionManager().isOnlineAuthenticated(verified.canonicalName())
                    || ctx.sessionManager().isAuthenticated(gameUuid))) {
                ctx.sessionManager().recordRejectedDuplicate(verified.canonicalName());
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                        ctx.messages().component("general.duplicate-online"));
                return;
            }
            PlayerProfile profile = Bukkit.createProfileExact(gameUuid, verified.canonicalName());
            if (ctx.settings().skinsEnabled() && res.hasCustomSkin()) {
                SkinCommands.applyProfileTextures(profile, res.customSkinValue(), res.customSkinSignature());
            } else if (verified.texturesValue() != null) {
                profile.setProperty(new ProfileProperty(
                        "textures", verified.texturesValue(), verified.texturesSignature()));
            }
            event.setPlayerProfile(profile);
            standalone.recordVerifiedGrant(res.accountId(), gameUuid, verified.canonicalName(), res.pendingConfirmed());
            eventsWithVerifiedGrant.add(event);
            return;
        }

        boolean needStandaloneCheck = !ctx.settings().proxyEnabled() && ctx.isStandalonePremiumActive();
        boolean needSkinCheck = ctx.settings().skinsEnabled();
        if (needStandaloneCheck || needSkinCheck) {
            String nameLower = UsernameValidator.normalizeLower(name);
            Account acc = null;
            try {
                acc = ctx.accounts().findByNameLower(nameLower).get(10, TimeUnit.SECONDS).orElse(null);
            } catch (Exception e) {
                if (needStandaloneCheck) {
                    ctx.logger().warning("Pre-login account lookup failed for " + name + ": " + e.getMessage());
                    event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                            ctx.messages().component("general.internal-error"));
                    return;
                }
            }

            if (needStandaloneCheck && acc != null) {
                if (acc.isPremiumConfirmed() && !floodgatePre) {
                    event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                            ctx.messages().component("premium.online-mode-required"));
                    return;
                }
                if (!floodgatePre && !acc.gameUuid().equals(event.getUniqueId())) {
                    PlayerProfile fixed = Bukkit.createProfileExact(acc.gameUuid(), name);
                    fixed.setProperties(event.getPlayerProfile().getProperties());
                    event.setPlayerProfile(fixed);
                }
            }

            if (needSkinCheck) {
                PlayerProfile profile = event.getPlayerProfile();
                if (acc != null && acc.hasCustomSkin()) {
                    SkinCommands.applyProfileTextures(profile, acc.skinValue(), acc.skinSignature());
                    event.setPlayerProfile(profile);
                } else if (ctx.settings().skinsRestoreByName()
                        && !floodgatePre
                        && !SkinCommands.hasTextures(profile)) {
                    MojangSkinClient.SkinLookupResult skinRes = ctx.skinClient().fetchByUsername(name)
                            .completeOnTimeout(MojangSkinClient.SkinLookupResult.unavailable(), 2500L, TimeUnit.MILLISECONDS)
                            .exceptionally(ex -> MojangSkinClient.SkinLookupResult.unavailable())
                            .join();
                    if (skinRes.status() == MojangSkinClient.Status.FOUND && skinRes.skin() != null) {
                        SkinCommands.applyProfileTextures(
                                profile, skinRes.skin().value(), skinRes.skin().signature());
                        event.setPlayerProfile(profile);
                    }
                }
            }
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onAsyncPreLoginMonitor(AsyncPlayerPreLoginEvent event) {
        boolean hadGrant = eventsWithVerifiedGrant.remove(event);
        if (!hadGrant || event.getLoginResult() == AsyncPlayerPreLoginEvent.Result.ALLOWED) return;
        Context ctx = plugin.context();
        if (ctx != null) {
            ctx.standalonePremium().clearVerifiedGrant(event.getUniqueId());
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        Context ctx = plugin.context();
        if (ctx == null) {
            player.kick(plugin.earlyMessages().component("error.not-ready"));
            return;
        }
        String ip = player.getAddress() != null && player.getAddress().getAddress() != null
                ? player.getAddress().getAddress().getHostAddress() : "unknown";

        PreAuthGrant grant = ctx.sessionManager().consumePreAuthGrant(player.getName(), player.getUniqueId(), ip);
        AuthState initialState = grant != null ? grant.state() : AuthState.AWAITING_LOGIN;
        Account account = grant != null ? grant.account() : null;

        if (grant == null && ctx.settings().proxyEnabled()) {
            initialState = AuthState.AWAITING_LOGIN;
        }
        if (initialState == AuthState.AUTHENTICATED && account != null && account.forcePasswordChange()) {
            initialState = AuthState.AWAITING_FORCED_PW_CHANGE;
        }

        PlayerSession session = ctx.sessionManager().registerPlayerSession(
                player.getUniqueId(), player.getName(), ip, initialState, account, player.getLocation());

        // Check duplicate DB fallback only if no grant existed
        if (grant == null) {
            ctx.accounts().findByNameLower(session.nameLower()).whenComplete((opt, ex) ->
                    ctx.scheduler().runForEntity(player, () -> {
                        if (opt == null || opt.isEmpty()) {
                            session.setState(AuthState.AWAITING_REGISTER);
                        } else {
                            Account acc = opt.get();
                            session.setAccount(acc);
                            session.setState(acc.isPremiumConfirmed() && ctx.settings().proxyEnabled()
                                    ? AuthState.AWAITING_PROXY : AuthState.AWAITING_LOGIN);
                        }
                        setupUnauthenticatedPlayUi(ctx, player, session);
                    }, null));
            scheduleAuthTimeout(ctx, player, session);
            return;
        }

        if (initialState == AuthState.AUTHENTICATED) {
            PlayerAuthenticatedEvent.AuthMethod authMethod;
            if (grant.standalonePremium()) {
                authMethod = PlayerAuthenticatedEvent.AuthMethod.STANDALONE_PREMIUM;
                ctx.messages().send(player, "auth.proxy-auto-login", Map.of("player", player.getName()));
                if (grant.pendingConfirmed() && account != null && account.premiumUuid() != null) {
                    ctx.messages().send(player, "premium.confirmed");
                    Bukkit.getPluginManager().callEvent(new PlayerPremiumVerifiedEvent(
                            player, account.premiumUuid(), AccountSnapshot.fromAccount(account)));
                }
            } else if (grant.sessionResumed()) {
                authMethod = PlayerAuthenticatedEvent.AuthMethod.SESSION;
                ctx.messages().send(player, "auth.session-resumed");
            } else {
                authMethod = PlayerAuthenticatedEvent.AuthMethod.PASSWORD;
                ctx.messages().send(player, "auth.login-success", Map.of("player", player.getName()));
            }
            if (account != null) {
                ctx.notifyProxyState(player, ProxyTokenSigner.MessageType.BACKEND_AUTH_OK, account.id());
            }
            AccountSnapshot snap = account != null ? AccountSnapshot.fromAccount(account) : null;
            Bukkit.getPluginManager().callEvent(new PlayerAuthenticatedEvent(player, snap, authMethod));
            plugin.notifyUpdateIfAvailable(player);
            plugin.notifyMigrationsIfAvailable(player);
            return;
        }

        if (initialState == AuthState.AWAITING_FORCED_PW_CHANGE) {
            ctx.messages().send(player, "auth.force-password-change");
        }

        setupUnauthenticatedPlayUi(ctx, player, session);
        scheduleAuthTimeout(ctx, player, session);
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        Context ctx = plugin.context();
        if (ctx != null) {
            ctx.sessionManager().removePlayerSession(event.getPlayer().getUniqueId());
            ctx.captchaManager().clear(UsernameValidator.normalizeLower(event.getPlayer().getName()));
        }
    }

    private void setupUnauthenticatedPlayUi(Context ctx, Player player, PlayerSession session) {
        if (session.isAuthenticated() || session.state() == AuthState.AWAITING_PROXY) return;
        if (session.state() == AuthState.AWAITING_REGISTER) {
            ctx.captchaManager().ensureRequiredForRegister(
                    session.nameLower(),
                    ctx.settings().captchaEnabled(),
                    ctx.settings().captchaRequireOnRegister(),
                    ctx.settings().captchaLength(),
                    ctx.settings().captchaExpireSeconds());
        }
        Challenge captcha = ctx.captchaManager().getPending(session.nameLower());
        if (captcha != null) {
            ctx.messages().send(player, "captcha.required", Map.of("code", captcha.code()));
        } else if (ctx.settings().bedrockCumulusForms() && ctx.capabilities().isFloodgate(player.getUniqueId())) {
            openBedrockForm(ctx, player, session);
        } else if (ctx.settings().loginUi() == Settings.UiMode.DIALOG
                && (!ctx.settings().fallbackForLegacyClients() || ctx.capabilities().supportsDialogs(player.getUniqueId()))
                && session.state() == AuthState.AWAITING_FORCED_PW_CHANGE) {
            ctx.coordinator().openPlayDialog(player, session, null);
        }
        ctx.coordinator().sendPrompt(player, session);
        Runnable cancel = ctx.scheduler().runEntityTimer(player, () -> {
            if (!session.isAuthenticated() && player.isOnline()) {
                Challenge ch = ctx.captchaManager().getPending(session.nameLower());
                if (ch != null) {
                    ctx.messages().send(player, "captcha.required", Map.of("code", ch.code()));
                } else {
                    ctx.coordinator().sendPrompt(player, session);
                }
            }
        }, null, 100L, 100L);
        session.setReminderCancel(cancel);
    }

    private void openBedrockForm(Context ctx, Player player, PlayerSession session) {
        UUID uuid = player.getUniqueId();
        var msg = ctx.messages();
        switch (session.state()) {
            case AWAITING_REGISTER -> BedrockFormUi.sendTwoFieldForm(
                    uuid,
                    msg.raw("bedrock.register-title"),
                    msg.raw("bedrock.register-content").replace("{min}", String.valueOf(ctx.settings().core().minPasswordLength())),
                    msg.raw("bedrock.password-label"), msg.raw("bedrock.password-placeholder"),
                    msg.raw("bedrock.confirm-label"), msg.raw("bedrock.confirm-placeholder"),
                    (pw, confirm) -> ctx.scheduler().runForEntity(player,
                            () -> ctx.coordinator().submitPlayRegister(player, session, pw, confirm, false), null));
            case AWAITING_LOGIN -> BedrockFormUi.sendSingleFieldForm(
                    uuid,
                    msg.raw("bedrock.login-title"),
                    msg.raw("bedrock.login-content"),
                    msg.raw("bedrock.password-label"), msg.raw("bedrock.password-placeholder"),
                    pw -> ctx.scheduler().runForEntity(player,
                            () -> ctx.coordinator().submitPlayLogin(player, session, pw, false), null));
            case AWAITING_2FA -> BedrockFormUi.sendSingleFieldForm(
                    uuid,
                    msg.raw("bedrock.totp-title"),
                    msg.raw("bedrock.totp-content"),
                    msg.raw("bedrock.totp-label"), msg.raw("bedrock.totp-placeholder"),
                    code -> ctx.scheduler().runForEntity(player,
                            () -> ctx.coordinator().submitPlayTotp(player, session, code, false), null));
            default -> {}
        }
    }

    private void scheduleAuthTimeout(Context ctx, Player player, PlayerSession session) {
        long timeoutTicks = session.state() == AuthState.AWAITING_PROXY
                ? 20L * 15L
                : 20L * ctx.settings().timeoutSeconds();
        ctx.scheduler().runEntityLater(player, () -> {
            if (!player.isOnline() || session.isAuthenticated()) return;
            Component kickMsg = session.state() == AuthState.AWAITING_PROXY
                    ? ctx.messages().component("general.proxy-verification-required")
                    : ctx.messages().component("general.timeout-kick");
            player.kick(kickMsg);
        }, null, timeoutTicks);
    }
}

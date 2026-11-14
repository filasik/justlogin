package me.skerik.justlogin.paper.listener;

import com.destroystokyo.paper.event.player.PlayerConnectionCloseEvent;
import com.destroystokyo.paper.profile.PlayerProfile;
import io.papermc.paper.connection.PlayerCommonConnection;
import io.papermc.paper.connection.PlayerConfigurationConnection;
import io.papermc.paper.connection.PlayerGameConnection;
import io.papermc.paper.event.connection.configuration.AsyncPlayerConnectionConfigureEvent;
import io.papermc.paper.event.player.PlayerCustomClickEvent;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import me.skerik.justlogin.core.model.Account;
import me.skerik.justlogin.core.security.UsernameValidator;
import me.skerik.justlogin.core.service.AuthService.PreAuthCheck;
import me.skerik.justlogin.paper.Context;
import me.skerik.justlogin.paper.JustLogin;
import me.skerik.justlogin.paper.auth.AuthSessionManager.AuthState;
import me.skerik.justlogin.paper.auth.AuthSessionManager.ConfigOutcome;
import me.skerik.justlogin.paper.auth.AuthSessionManager.ConfigPhase;
import me.skerik.justlogin.paper.auth.AuthSessionManager.PendingConfigAuth;
import me.skerik.justlogin.paper.auth.AuthSessionManager.PlayerSession;
import me.skerik.justlogin.paper.config.Settings;
import me.skerik.justlogin.paper.dialog.ClickData;
import me.skerik.justlogin.paper.premium.StandalonePremiumManager;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;

/**
 * Handles pre-world authentication during Paper's async Configuration phase (MC 1.21.7+ Dialogs)
 * and routes dialog submissions from both Configuration and Play phases.
 */
public final class ConfigureAuthListener implements Listener {

    private final JustLogin plugin;

    public ConfigureAuthListener(JustLogin plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.NORMAL)
    public void onConfigure(AsyncPlayerConnectionConfigureEvent event) {
        PlayerConfigurationConnection conn = event.getConnection();
        Context ctx = plugin.context();
        if (ctx == null) {
            conn.disconnect(plugin.earlyMessages().component("error.not-ready"));
            return;
        }
        if (ctx.isProxyMisconfigured()) {
            conn.disconnect(ctx.messages().component("general.proxy-misconfigured"));
            return;
        }

        PlayerProfile profile = conn.getProfile();
        String username = profile.getName();
        UUID profileUuid = profile.getId();
        if (username == null || username.isBlank()) {
            conn.disconnect(ctx.messages().component("general.invalid-username"));
            return;
        }
        String ip = extractIp(conn);

        if (ctx.settings().kickDuplicateOnline() && ctx.sessionManager().isOnlineAuthenticated(username)) {
            ctx.sessionManager().recordRejectedDuplicate(username);
            conn.disconnect(ctx.messages().component("general.duplicate-online"));
            return;
        }
        if (ctx.sessionManager().hasActiveConfigAuth(username)) {
            ctx.sessionManager().recordRejectedDuplicate(username);
            conn.disconnect(ctx.messages().component("auth.duplicate-connection-pending"));
            return;
        }

        boolean floodgate = ctx.capabilities().isFloodgate(profileUuid);
        PreAuthCheck pre;
        try {
            pre = ctx.authService().checkPreAuth(username, ip, floodgate).get(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            ctx.logger().warning("Pre-auth lookup failed for " + username + ": " + e.getMessage());
            conn.disconnect(ctx.messages().component("general.internal-error"));
            return;
        }

        switch (pre.decision()) {
            case INVALID_USERNAME -> {
                conn.disconnect(ctx.messages().component("general.invalid-username"));
                return;
            }
            case RATE_LIMITED -> {
                conn.disconnect(ctx.messages().component("general.rate-limited",
                        Map.of("seconds", String.valueOf(pre.retryAfterSeconds()))));
                return;
            }
            case SESSION_RESUMED -> {
                Account acc = pre.account();
                AuthState state = (acc != null && acc.forcePasswordChange())
                        ? AuthState.AWAITING_FORCED_PW_CHANGE : AuthState.AUTHENTICATED;
                ctx.sessionManager().grantPreAuth(username, profileUuid, ip, state, acc, true);
                return;
            }
            case REQUIRE_PREMIUM_ONLINE -> {
                if (ctx.settings().proxyEnabled()) {
                    // Proxy verifies Mojang online mode and transmits HMAC-signed justlogin:auth on join
                    ctx.sessionManager().grantPreAuth(username, profileUuid, ip, AuthState.AWAITING_PROXY, pre.account(), false);
                    return;
                }
                Account acc = pre.account();
                StandalonePremiumManager.VerifiedGrant standaloneGrant =
                        ctx.standalonePremium().consumeVerifiedGrant(profileUuid, username);
                if (standaloneGrant != null && acc != null) {
                    if (acc.forcePasswordChange() && acc.hasPassword()) {
                        // Fall through to forced password change UI cleanly before entering world
                        pre = new PreAuthCheck(PreAuthCheck.Decision.REQUIRE_LOGIN, acc, 0);
                    } else {
                        ctx.authService().recordSuccessfulSession(acc, username, ip);
                        ctx.sessionManager().grantPreAuth(
                                username, profileUuid, ip, AuthState.AUTHENTICATED, acc, false,
                                true, standaloneGrant.pendingConfirmed());
                        return;
                    }
                } else if (ctx.isStandalonePremiumActive()) {
                    conn.disconnect(ctx.messages().component("premium.online-mode-required"));
                    return;
                } else if (!ctx.settings().premiumFallbackToPassword()) {
                    conn.disconnect(ctx.messages().component("premium.fallback-disabled"));
                    return;
                } else if (acc == null || !acc.hasPassword()) {
                    conn.disconnect(ctx.messages().component("general.proxy-verification-required"));
                    return;
                }
                // Standalone premium disabled and fallback-to-password=true: fall through to password auth
            }
            case REQUIRE_REGISTER, REQUIRE_LOGIN -> {}
        }

        boolean registerMode = pre.decision() == PreAuthCheck.Decision.REQUIRE_REGISTER;
        if (registerMode) {
            ctx.captchaManager().ensureRequiredForRegister(
                    UsernameValidator.normalizeLower(username),
                    ctx.settings().captchaEnabled(),
                    ctx.settings().captchaRequireOnRegister(),
                    ctx.settings().captchaLength(),
                    ctx.settings().captchaExpireSeconds());
        }
        boolean hasPendingCaptcha = ctx.captchaManager().getPending(UsernameValidator.normalizeLower(username)) != null;
        boolean useDialog = !hasPendingCaptcha
                && ctx.settings().loginUi() == Settings.UiMode.DIALOG
                && (!ctx.settings().fallbackForLegacyClients() || ctx.capabilities().supportsDialogs(profileUuid));

        if (!useDialog) {
            ctx.sessionManager().grantPreAuth(
                    username, profileUuid, ip,
                    registerMode ? AuthState.AWAITING_REGISTER : AuthState.AWAITING_LOGIN,
                    pre.account(), false);
            return;
        }

        PendingConfigAuth pending = ctx.sessionManager().createConfigAuth(
                username, profileUuid, ip, conn,
                registerMode ? ConfigPhase.REGISTER : ConfigPhase.LOGIN,
                pre.account());

        if (registerMode) {
            ctx.dialogUi().showRegisterDialog(
                    conn.getAudience(), username, ctx.settings().core().minPasswordLength(), pending.nonce(), null);
        } else {
            ctx.dialogUi().showLoginDialog(conn.getAudience(), username, pending.nonce(), null);
        }

        try {
            ConfigOutcome outcome = pending.future().get(ctx.settings().timeoutSeconds(), TimeUnit.SECONDS);
            if (!outcome.authenticated()) {
                conn.disconnect(ctx.messages().component("general.cancelled-kick"));
                return;
            }
            ctx.sessionManager().grantPreAuth(
                    username, profileUuid, ip, AuthState.AUTHENTICATED, outcome.account(), false);
        } catch (TimeoutException e) {
            ctx.sessionManager().finishConfigAuth(pending, ConfigOutcome.failed("timeout"));
            conn.disconnect(ctx.messages().component("general.timeout-kick"));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            ctx.sessionManager().finishConfigAuth(pending, ConfigOutcome.failed("interrupted"));
            conn.disconnect(ctx.messages().component("general.internal-error"));
        } catch (ExecutionException e) {
            ctx.sessionManager().finishConfigAuth(pending, ConfigOutcome.failed("error"));
            conn.disconnect(ctx.messages().component("general.internal-error"));
        }
    }

    @EventHandler
    public void onConnectionClose(PlayerConnectionCloseEvent event) {
        Context ctx = plugin.context();
        if (ctx == null) return;
        String playerName = event.getPlayerName();
        if (ctx.sessionManager().consumeRejectedDuplicate(playerName)) {
            return;
        }
        if (playerName != null && ctx.sessionManager().isOnlineAuthenticated(playerName)) {
            return;
        }
        ctx.sessionManager().cancelConfigAuthByIdentity(playerName, event.getPlayerUniqueId());
        if (playerName != null) {
            ctx.sessionManager().consumePreAuthGrant(playerName);
        }
        ctx.standalonePremium().clearVerifiedGrant(event.getPlayerUniqueId());
    }

    @EventHandler
    public void onCustomClick(PlayerCustomClickEvent event) {
        Context ctx = plugin.context();
        if (ctx == null) return;
        ClickData click = ClickData.parse(event.getIdentifier(), event.getTag());
        if (click == null) return;

        String arg1;
        String arg2 = "";
        switch (click.action()) {
            case REGISTER, FORCE_PW -> {
                arg1 = ClickData.readText(event.getDialogResponseView(), ClickData.FIELD_PASSWORD);
                if (click.action() == ClickData.Action.REGISTER && ctx.settings().dialogSinglePassword()) {
                    arg2 = arg1;
                } else {
                    arg2 = ClickData.readText(event.getDialogResponseView(), ClickData.FIELD_CONFIRM);
                }
            }
            case LOGIN -> arg1 = ClickData.readText(event.getDialogResponseView(), ClickData.FIELD_PASSWORD);
            case TOTP -> arg1 = ClickData.readText(event.getDialogResponseView(), ClickData.FIELD_CODE);
            case CANCEL -> arg1 = "";
            default -> {
                return;
            }
        }

        PlayerCommonConnection common = event.getCommonConnection();
        if (common instanceof PlayerConfigurationConnection configConn) {
            PendingConfigAuth pending = ctx.sessionManager().getConfigByNonce(click.nonce());
            if (pending == null || pending.connection() != configConn) return;
            String connName = configConn.getProfile().getName();
            if (connName == null || !connName.equalsIgnoreCase(pending.username())) return;
            final String f1 = arg1;
            final String f2 = arg2;
            ctx.scheduler().runAsync(() -> ctx.coordinator().handleConfigDialogAction(pending, click.action(), f1, f2));
        } else if (common instanceof PlayerGameConnection gameConn) {
            Player player = gameConn.getPlayer();
            PlayerSession session = ctx.sessionManager().getSessionByNonce(click.nonce());
            if (session == null || !session.uuid().equals(player.getUniqueId())) return;
            final String f1 = arg1;
            final String f2 = arg2;
            ctx.scheduler().runAsync(() -> ctx.coordinator().handlePlayDialogAction(player, session, click.action(), f1, f2));
        }
    }

    private static String extractIp(PlayerConfigurationConnection conn) {
        InetSocketAddress isa = conn.getClientAddress();
        if (isa != null && isa.getAddress() != null) {
            return isa.getAddress().getHostAddress();
        }
        if (conn.getAddress() instanceof InetSocketAddress sa && sa.getAddress() != null) {
            return sa.getAddress().getHostAddress();
        }
        return "unknown";
    }
}

package me.skerik.justlogin.paper.listener;

import me.skerik.justlogin.api.AccountSnapshot;
import me.skerik.justlogin.api.event.PlayerAuthenticatedEvent;
import me.skerik.justlogin.api.event.PlayerLoggedOutEvent;
import me.skerik.justlogin.api.event.PlayerPremiumVerifiedEvent;
import me.skerik.justlogin.core.crypto.ProxyTokenSigner;
import me.skerik.justlogin.core.security.UsernameValidator;
import me.skerik.justlogin.paper.Context;
import me.skerik.justlogin.paper.JustLogin;
import me.skerik.justlogin.paper.auth.AuthSessionManager.AuthState;
import me.skerik.justlogin.paper.auth.AuthSessionManager.PlayerSession;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.messaging.PluginMessageListener;

/**
 * Verifies HMAC-SHA256 + timestamp + nonce signed {@code justlogin:auth} messages arriving from Velocity or BungeeCord.
 */
public final class ProxyMessageListener implements PluginMessageListener {

    private final JustLogin plugin;

    public ProxyMessageListener(JustLogin plugin) {
        this.plugin = plugin;
    }

    @Override
    public void onPluginMessageReceived(String channel, Player player, byte[] message) {
        if (!ProxyTokenSigner.CHANNEL.equals(channel)) return;
        Context ctx = plugin.context();
        if (ctx == null || !ctx.settings().proxyEnabled() || ctx.isProxyMisconfigured()) return;
        ProxyTokenSigner signer = ctx.proxySigner();
        if (signer == null) return;

        ProxyTokenSigner.VerifiedMessage verified = signer.verify(message, System.currentTimeMillis());
        if (verified == null) {
            ctx.logger().warning("Rejected invalid/expired/replayed proxy auth message for connection " + player.getName());
            return;
        }

        if (!verified.nameLower().equals(UsernameValidator.normalizeLower(player.getName()))
                || !verified.gameUuid().equals(player.getUniqueId())) {
            ctx.logger().warning("Rejected mismatched proxy token identity for " + player.getName()
                    + " (token target=" + verified.nameLower() + ")");
            return;
        }

        switch (verified.type()) {
            case AUTH_OK, PREMIUM_VERIFIED -> {
                PlayerSession session = ctx.sessionManager().getSession(player.getUniqueId());
                if (session == null || session.isAuthenticated()) return;
                ctx.accounts().findById(verified.accountId()).whenComplete((opt, ex) ->
                        ctx.scheduler().runForEntity(player, () -> {
                            if (opt == null || opt.isEmpty()) return;
                            var acc = opt.get();
                            ctx.authService().recordSuccessfulSession(acc, player.getName(), session.ip());
                            if (acc.forcePasswordChange() && acc.hasPassword()) {
                                session.setAccount(acc);
                                session.setState(AuthState.AWAITING_FORCED_PW_CHANGE);
                                ctx.messages().send(player, "auth.force-password-change");
                                return;
                            }
                            ctx.coordinator().completePlayAuth(player, session, acc, "auth.proxy-auto-login",
                                    PlayerAuthenticatedEvent.AuthMethod.PROXY_PREMIUM, false);
                            if (verified.type() == ProxyTokenSigner.MessageType.PREMIUM_VERIFIED) {
                                ctx.messages().send(player, "premium.confirmed");
                                if (acc.premiumUuid() != null) {
                                    Bukkit.getPluginManager().callEvent(new PlayerPremiumVerifiedEvent(
                                            player, acc.premiumUuid(), AccountSnapshot.fromAccount(acc)));
                                }
                            }
                        }, null));
            }
            case LOGOUT -> {
                PlayerSession session = ctx.sessionManager().getSession(player.getUniqueId());
                if (session != null && session.isAuthenticated()) {
                    AccountSnapshot snap = session.account() != null ? AccountSnapshot.fromAccount(session.account()) : null;
                    session.setState(AuthState.AWAITING_LOGIN);
                    ctx.messages().send(player, "auth.logged-out");
                    Bukkit.getPluginManager().callEvent(new PlayerLoggedOutEvent(player, snap));
                    ctx.coordinator().sendPrompt(player, session);
                }
            }
            case BACKEND_AUTH_OK -> {
                // Backend->Proxy only; ignore if received inbound on Paper.
            }
        }
    }

    public void sendToProxy(Player player, ProxyTokenSigner.MessageType type, long accountId) {
        Context ctx = plugin.context();
        if (ctx == null) return;
        ProxyTokenSigner signer = ctx.proxySigner();
        if (signer == null || !ctx.settings().proxyEnabled()) return;
        byte[] payload = signer.sign(
                type, accountId, UsernameValidator.normalizeLower(player.getName()),
                player.getUniqueId(), System.currentTimeMillis());
        player.sendPluginMessage(ctx.plugin(), ProxyTokenSigner.CHANNEL, payload);
    }
}

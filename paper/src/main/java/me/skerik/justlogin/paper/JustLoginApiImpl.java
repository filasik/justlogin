package me.skerik.justlogin.paper;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import me.skerik.justlogin.api.AccountSnapshot;
import me.skerik.justlogin.api.JustLoginAPI;
import me.skerik.justlogin.api.event.PlayerLoggedOutEvent;
import me.skerik.justlogin.core.crypto.ProxyTokenSigner;
import me.skerik.justlogin.paper.auth.AuthSessionManager.AuthState;
import me.skerik.justlogin.paper.auth.AuthSessionManager.PlayerSession;
import me.skerik.justlogin.paper.config.Settings;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;

/** Package-private runtime backing {@link JustLoginAPI} registered in {@code ServicesManager}. */
final class JustLoginApiImpl implements JustLoginAPI {

    private final Context ctx;

    JustLoginApiImpl(Context ctx) {
        this.ctx = ctx;
    }

    @Override
    public boolean isAuthenticated(UUID playerUuid) {
        return playerUuid != null && ctx.sessionManager().isAuthenticated(playerUuid);
    }

    @Override
    public CompletableFuture<Optional<AccountSnapshot>> findAccount(String username) {
        if (username == null || username.isBlank()) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        return ctx.accounts().findByNameLower(username.toLowerCase(java.util.Locale.ROOT))
                .thenApply(opt -> opt.map(AccountSnapshot::fromAccount));
    }

    @Override
    public CompletableFuture<Optional<AccountSnapshot>> findAccount(UUID gameUuid) {
        if (gameUuid == null) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        return ctx.accounts().findByGameUuid(gameUuid)
                .thenApply(opt -> opt.map(AccountSnapshot::fromAccount));
    }

    @Override
    public void forceLogout(Player player) {
        if (player == null) return;
        ctx.scheduler().runForEntity(player, () -> {
            PlayerSession session = ctx.sessionManager().getSession(player.getUniqueId());
            if (session == null || !session.isAuthenticated()) return;
            long accountId = session.account() != null ? session.account().id() : -1L;
            AccountSnapshot snap = session.account() != null ? AccountSnapshot.fromAccount(session.account()) : null;
            session.setState(AuthState.AWAITING_LOGIN);
            session.setAnchorLocation(player.getLocation());
            ctx.notifyProxyState(player, ProxyTokenSigner.MessageType.LOGOUT, accountId);
            Bukkit.getPluginManager().callEvent(new PlayerLoggedOutEvent(player, snap));
            ctx.messages().send(player, "auth.logged-out");
            if (ctx.settings().loginUi() == Settings.UiMode.DIALOG
                    && (!ctx.settings().fallbackForLegacyClients() || ctx.capabilities().supportsDialogs(player.getUniqueId()))) {
                ctx.coordinator().openPlayDialog(player, session, null);
            }
            ctx.coordinator().sendPrompt(player, session);
        }, null);
    }
}

package me.skerik.justlogin.api.event;

import me.skerik.justlogin.api.AccountSnapshot;
import org.bukkit.entity.Player;
import org.bukkit.event.Event;
import org.bukkit.event.HandlerList;
import org.jspecify.annotations.Nullable;

/** Fired after a player completes authentication (password, 2FA, session resume, or Mojang premium). */
public final class PlayerAuthenticatedEvent extends Event {

    public enum AuthMethod {
        PASSWORD,
        PASSWORD_2FA,
        SESSION,
        PROXY_PREMIUM,
        STANDALONE_PREMIUM,
        EMAIL_RECOVERY
    }

    private static final HandlerList HANDLERS = new HandlerList();

    private final Player player;
    private final @Nullable AccountSnapshot account;
    private final AuthMethod method;

    public PlayerAuthenticatedEvent(Player player, @Nullable AccountSnapshot account, AuthMethod method) {
        super(false);
        this.player = player;
        this.account = account;
        this.method = method;
    }

    public Player getPlayer() {
        return player;
    }

    public @Nullable AccountSnapshot getAccount() {
        return account;
    }

    public AuthMethod getMethod() {
        return method;
    }

    @Override
    public HandlerList getHandlers() {
        return HANDLERS;
    }

    public static HandlerList getHandlerList() {
        return HANDLERS;
    }
}

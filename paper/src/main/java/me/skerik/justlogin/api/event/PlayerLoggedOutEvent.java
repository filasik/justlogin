package me.skerik.justlogin.api.event;

import me.skerik.justlogin.api.AccountSnapshot;
import org.bukkit.entity.Player;
import org.bukkit.event.Event;
import org.bukkit.event.HandlerList;
import org.jspecify.annotations.Nullable;

/** Fired when an authenticated player logs out via {@code /logout}, proxy request, or API. */
public final class PlayerLoggedOutEvent extends Event {

    private static final HandlerList HANDLERS = new HandlerList();

    private final Player player;
    private final @Nullable AccountSnapshot account;

    public PlayerLoggedOutEvent(Player player, @Nullable AccountSnapshot account) {
        super(false);
        this.player = player;
        this.account = account;
    }

    public Player getPlayer() {
        return player;
    }

    public @Nullable AccountSnapshot getAccount() {
        return account;
    }

    @Override
    public HandlerList getHandlers() {
        return HANDLERS;
    }

    public static HandlerList getHandlerList() {
        return HANDLERS;
    }
}

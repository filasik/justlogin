package me.skerik.justlogin.api.event;

import java.util.UUID;
import me.skerik.justlogin.api.AccountSnapshot;
import org.bukkit.entity.Player;
import org.bukkit.event.Event;
import org.bukkit.event.HandlerList;
import org.jspecify.annotations.Nullable;

/** Fired when a {@code /premium} verification succeeds with Mojang online-mode cryptographic proof. */
public final class PlayerPremiumVerifiedEvent extends Event {

    private static final HandlerList HANDLERS = new HandlerList();

    private final Player player;
    private final UUID premiumUuid;
    private final @Nullable AccountSnapshot account;

    public PlayerPremiumVerifiedEvent(Player player, UUID premiumUuid, @Nullable AccountSnapshot account) {
        super(false);
        this.player = player;
        this.premiumUuid = premiumUuid;
        this.account = account;
    }

    public Player getPlayer() {
        return player;
    }

    public UUID getPremiumUuid() {
        return premiumUuid;
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

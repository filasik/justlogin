package me.skerik.justlogin.api;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.bukkit.entity.Player;

/** Public service registered in Bukkit's {@code ServicesManager} for third-party plugin integrations. */
public interface JustLoginAPI {

    boolean isAuthenticated(UUID playerUuid);

    default boolean isAuthenticated(Player player) {
        return player != null && isAuthenticated(player.getUniqueId());
    }

    CompletableFuture<Optional<AccountSnapshot>> findAccount(String username);

    CompletableFuture<Optional<AccountSnapshot>> findAccount(UUID gameUuid);

    void forceLogout(Player player);
}

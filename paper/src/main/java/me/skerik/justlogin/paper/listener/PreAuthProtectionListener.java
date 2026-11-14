package me.skerik.justlogin.paper.listener;

import com.destroystokyo.paper.event.server.AsyncTabCompleteEvent;
import io.papermc.paper.event.player.AsyncChatEvent;
import java.util.Locale;
import me.skerik.justlogin.paper.Context;
import me.skerik.justlogin.paper.JustLogin;
import me.skerik.justlogin.paper.auth.AuthSessionManager.AuthState;
import me.skerik.justlogin.paper.auth.AuthSessionManager.PlayerSession;
import org.bukkit.Location;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.block.SignChangeEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.entity.EntityPickupItemEvent;
import org.bukkit.event.entity.EntityTargetEvent;
import org.bukkit.event.entity.FoodLevelChangeEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryDragEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.player.PlayerBedEnterEvent;
import org.bukkit.event.player.PlayerBucketEmptyEvent;
import org.bukkit.event.player.PlayerBucketFillEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerCommandSendEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerEditBookEvent;
import org.bukkit.event.player.PlayerFishEvent;
import org.bukkit.event.player.PlayerInteractAtEntityEvent;
import org.bukkit.event.player.PlayerInteractEntityEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerItemConsumeEvent;
import org.bukkit.event.player.PlayerItemHeldEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerPortalEvent;
import org.bukkit.event.player.PlayerSwapHandItemsEvent;
import org.bukkit.event.vehicle.VehicleEnterEvent;

/**
 * Strict default-deny lockdown for any player in Play phase whose authentication is incomplete
 * (Threat model #8: command allowlist, zero chat/movement/inventory/world/combat interaction).
 */
public final class PreAuthProtectionListener implements Listener {

    private final JustLogin plugin;

    public PreAuthProtectionListener(JustLogin plugin) {
        this.plugin = plugin;
    }

    private boolean isLocked(Player player) {
        if (player.hasMetadata("NPC")) return false;
        Context ctx = plugin.context();
        return ctx == null || !ctx.sessionManager().isAuthenticated(player.getUniqueId());
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onMove(PlayerMoveEvent event) {
        if (!isLocked(event.getPlayer())) return;
        if (!event.hasExplicitlyChangedPosition()) return;
        Location from = event.getFrom();
        Location to = event.getTo();
        event.setTo(new Location(from.getWorld(), from.getX(), from.getY(), from.getZ(), to.getYaw(), to.getPitch()));
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onChat(AsyncChatEvent event) {
        Player player = event.getPlayer();
        Context ctx = plugin.context();
        if (ctx == null) {
            event.setCancelled(true);
            plugin.earlyMessages().send(player, "error.not-ready");
            return;
        }
        event.viewers().removeIf(v -> v instanceof Player p && isLocked(p));
        PlayerSession session = ctx.sessionManager().getSession(player.getUniqueId());
        if (session != null && session.isAuthenticated()) return;
        event.setCancelled(true);
        ctx.messages().send(player, "auth.must-auth-first");
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onCommandPreprocess(PlayerCommandPreprocessEvent event) {
        Player player = event.getPlayer();
        Context ctx = plugin.context();
        if (ctx == null) {
            event.setCancelled(true);
            plugin.earlyMessages().send(player, "error.not-ready");
            return;
        }
        PlayerSession session = ctx.sessionManager().getSession(player.getUniqueId());
        if (session != null && session.isAuthenticated()) return;

        if (!isAllowedPreAuthCommand(session != null ? session.state() : AuthState.AWAITING_LOGIN, event.getMessage())) {
            event.setCancelled(true);
            ctx.messages().send(player, "auth.must-auth-first");
        }
    }

    /** Pure allowlist evaluator tested against threat model #8. */
    public static boolean isAllowedPreAuthCommand(AuthState state, String rawMessage) {
        if (rawMessage == null || !rawMessage.startsWith("/")) return false;
        String trimmed = rawMessage.substring(1).trim();
        if (trimmed.isEmpty()) return false;
        int sp = trimmed.indexOf(' ');
        String label = (sp < 0 ? trimmed : trimmed.substring(0, sp)).toLowerCase(Locale.ROOT);
        if (label.startsWith("justlogin:")) {
            label = label.substring("justlogin:".length());
        } else if (label.contains(":")) {
            return false; // Reject arbitrary plugin namespace prefixes before authentication
        }
        if (state != AuthState.AUTHENTICATED && state != AuthState.AWAITING_PROXY
                && (label.equals("jl") || label.equals("justlogin") || label.equals("auth"))) {
            String rest = sp < 0 ? "" : trimmed.substring(sp + 1).trim().toLowerCase(Locale.ROOT);
            if (rest.isEmpty() || rest.equals("help") || rest.startsWith("help ")
                    || rest.equals("?") || rest.startsWith("? ")) {
                return true;
            }
        }
        return switch (state) {
            case AWAITING_REGISTER -> label.equals("register") || label.equals("reg") || label.equals("captcha");
            case AWAITING_LOGIN -> {
                if (label.equals("login") || label.equals("l") || label.equals("captcha")) yield true;
                if (label.equals("email")) {
                    String rest = sp < 0 ? "" : trimmed.substring(sp + 1).trim().toLowerCase(Locale.ROOT);
                    yield rest.startsWith("recover");
                }
                yield false;
            }
            case AWAITING_2FA -> {
                if (!label.equals("2fa")) yield false;
                String rest = sp < 0 ? "" : trimmed.substring(sp + 1).trim().toLowerCase(Locale.ROOT);
                yield rest.startsWith("verify ") || rest.equals("verify");
            }
            case AWAITING_FORCED_PW_CHANGE -> label.equals("changepassword") || label.equals("changepass") || label.equals("cp");
            case AWAITING_PROXY, AUTHENTICATED -> false;
        };
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onCommandSend(PlayerCommandSendEvent event) {
        Context ctx = plugin.context();
        PlayerSession session = ctx == null ? null : ctx.sessionManager().getSession(event.getPlayer().getUniqueId());
        if (session == null || !session.isAuthenticated()) {
            event.getCommands().removeIf(c -> !c.equals("login") && !c.equals("l")
                    && !c.equals("register") && !c.equals("reg") && !c.equals("2fa")
                    && !c.equals("changepassword") && !c.equals("changepass") && !c.equals("cp")
                    && !c.equals("captcha") && !c.equals("email")
                    && !c.equals("justlogin") && !c.equals("jl") && !c.equals("auth"));
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onTabComplete(AsyncTabCompleteEvent event) {
        if (event.getSender() instanceof Player player && isLocked(player)) {
            Context ctx = plugin.context();
            PlayerSession session = ctx == null ? null : ctx.sessionManager().getSession(player.getUniqueId());
            AuthState state = session == null ? null : session.state();
            if (!isAllowedPreAuthTabComplete(state, event.getBuffer())) {
                event.setCancelled(true);
            }
        }
    }

    public static boolean isAllowedPreAuthTabComplete(AuthState state, String rawBuffer) {
        if (rawBuffer == null || state == null) return false;
        if (isAllowedPreAuthCommand(state, rawBuffer)) return true;
        String trimmed = rawBuffer.trim().toLowerCase(Locale.ROOT);
        if (trimmed.startsWith("/")) trimmed = trimmed.substring(1).trim();
        int colon = trimmed.indexOf(':');
        int space = trimmed.indexOf(' ');
        if (colon >= 0 && (space < 0 || colon < space)) {
            trimmed = trimmed.substring(colon + 1);
        }
        if (state != AuthState.AUTHENTICATED && state != AuthState.AWAITING_PROXY) {
            for (String root : new String[] { "jl", "justlogin", "auth" }) {
                if (trimmed.equals(root) || (trimmed.startsWith(root + " ") && (root + " help").startsWith(trimmed))
                        || (trimmed.startsWith(root + " ") && (root + " ?").startsWith(trimmed))) {
                    return true;
                }
            }
        }
        if (state == AuthState.AWAITING_LOGIN && (trimmed.equals("email") || (trimmed.startsWith("email ") && "email recover".startsWith(trimmed)))) {
            return true;
        }
        return state == AuthState.AWAITING_2FA && (trimmed.equals("2fa") || (trimmed.startsWith("2fa ") && "2fa verify".startsWith(trimmed)));
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInventoryOpen(InventoryOpenEvent event) {
        if (event.getPlayer() instanceof Player p && isLocked(p)) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInventoryClick(InventoryClickEvent event) {
        if (event.getWhoClicked() instanceof Player p && isLocked(p)) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInventoryDrag(InventoryDragEvent event) {
        if (event.getWhoClicked() instanceof Player p && isLocked(p)) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onDrop(PlayerDropItemEvent event) {
        if (isLocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onPickup(EntityPickupItemEvent event) {
        if (event.getEntity() instanceof Player p && isLocked(p)) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onSwapHand(PlayerSwapHandItemsEvent event) {
        if (isLocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onItemHeld(PlayerItemHeldEvent event) {
        if (isLocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onConsume(PlayerItemConsumeEvent event) {
        if (isLocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInteract(PlayerInteractEvent event) {
        if (isLocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInteractEntity(PlayerInteractEntityEvent event) {
        if (isLocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInteractAtEntity(PlayerInteractAtEntityEvent event) {
        if (isLocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onBreak(BlockBreakEvent event) {
        if (isLocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onPlace(BlockPlaceEvent event) {
        if (isLocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onBucketEmpty(PlayerBucketEmptyEvent event) {
        if (isLocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onBucketFill(PlayerBucketFillEvent event) {
        if (isLocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onEditBook(PlayerEditBookEvent event) {
        if (isLocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onSign(SignChangeEvent event) {
        if (isLocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onBed(PlayerBedEnterEvent event) {
        if (isLocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onPortal(PlayerPortalEvent event) {
        if (isLocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onFish(PlayerFishEvent event) {
        if (isLocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onVehicleEnter(VehicleEnterEvent event) {
        if (event.getEntered() instanceof Player p && isLocked(p)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onDamage(EntityDamageEvent event) {
        if (event.getEntity() instanceof Player p && isLocked(p)) {
            event.setCancelled(true);
            if (event.getCause() == EntityDamageEvent.DamageCause.VOID) {
                Context ctx = plugin.context();
                PlayerSession s = ctx != null ? ctx.sessionManager().getSession(p.getUniqueId()) : null;
                Location target = s != null && s.anchorLocation() != null
                        ? s.anchorLocation() : p.getWorld().getSpawnLocation();
                p.setFallDistance(0f);
                p.teleportAsync(target);
            }
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onDamageByEntity(EntityDamageByEntityEvent event) {
        if (event.getDamager() instanceof Player p && isLocked(p)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onTarget(EntityTargetEvent event) {
        if (event.getTarget() instanceof Player p && isLocked(p)) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onFood(FoodLevelChangeEvent event) {
        if (event.getEntity() instanceof Player p && isLocked(p)) event.setCancelled(true);
    }
}

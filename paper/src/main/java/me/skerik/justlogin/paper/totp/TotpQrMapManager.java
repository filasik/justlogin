package me.skerik.justlogin.paper.totp;

import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import me.skerik.justlogin.paper.Context;
import me.skerik.justlogin.paper.auth.AuthSessionManager.PendingTotpSetup;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.PlayerDeathEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.player.PlayerInteractEntityEvent;
import org.bukkit.event.player.PlayerInteractAtEntityEvent;
import org.bukkit.event.player.PlayerArmorStandManipulateEvent;
import org.bukkit.event.player.PlayerGameModeChangeEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryDragEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerItemHeldEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerSwapHandItemsEvent;
import org.bukkit.event.player.PlayerTeleportEvent;
import org.jspecify.annotations.Nullable;

/** Owns client-only QR displays. All player inventory reads run on that player's entity thread. */
public final class TotpQrMapManager implements Listener {
    // Negative IDs cannot collide with normal world maps, and survive no server/world save.
    private static final AtomicInteger IDS = new AtomicInteger(-1);
    private static final long DISPLAY_MILLIS = 120_000L;
    private final Context ctx;
    private final Map<UUID, Display> displays = new ConcurrentHashMap<>();
    private volatile boolean closed;
    private volatile @Nullable QrMapPackets packets;

    private static final class Display {
        final Player player;
        final int slot;
        final int mapId = IDS.getAndDecrement();
        final PendingTotpSetup pending;
        final long expiresAt;
        @Nullable Object restorePacket;
        @Nullable Runnable cancelTimer;

        Display(Player player, PendingTotpSetup pending) {
            this.player = player;
            this.slot = player.getInventory().getHeldItemSlot();
            this.pending = pending;
            this.expiresAt = Math.min(pending.expiresAt(), System.currentTimeMillis() + DISPLAY_MILLIS);
        }
    }

    public TotpQrMapManager(Context ctx) {
        this.ctx = ctx;
    }

    public synchronized void show(Player player, String uri, PendingTotpSetup pending) {
        hide(player);
        if (closed || !ctx.settings().totpQrMapEnabled()) return;
        Display display = new Display(player, pending);
        displays.put(player.getUniqueId(), display);
        ctx.scheduler().runAsync(() -> {
            byte[] pixels;
            try {
                pixels = QrMapImage.encode(uri);
            } catch (Exception e) {
                ctx.scheduler().runForEntity(player, () -> fallback(display), () -> forget(display));
                return;
            }
            ctx.scheduler().runForEntity(player, () -> {
                synchronized (this) {
                    try {
                        if (!valid(display)) {
                            forget(display);
                            return;
                        }
                        if (packets == null) packets = new QrMapPackets();
                        display.restorePacket = packets.inventoryPacket(display.slot,
                                player.getInventory().getItem(display.slot));
                        packets.show(player, display.slot, display.mapId, pixels);
                        display.cancelTimer = ctx.scheduler().runEntityTimer(player, () -> {
                            if (displays.get(player.getUniqueId()) == display && !valid(display)) hide(player);
                        }, () -> forget(display), 20L, 20L);
                        ctx.messages().send(player, "totp.qr-shown");
                    } catch (Exception e) {
                        // Never include exception text: QR libraries may include the secret input in errors.
                        fallback(display);
                    } finally {
                        Arrays.fill(pixels, (byte) 0);
                    }
                }
            }, () -> {
                Arrays.fill(pixels, (byte) 0);
                forget(display);
            });
        });
    }

    private boolean valid(Display d) {
        Player p = d.player;
        return !closed && ctx.settings().totpQrMapEnabled() && p.isOnline()
                && displays.get(p.getUniqueId()) == d && System.currentTimeMillis() < d.expiresAt
                && ctx.sessionManager().isAuthenticated(p.getUniqueId())
                && ctx.sessionManager().pendingTotpSetup(p.getUniqueId()) == d.pending
                && p.getInventory().getHeldItemSlot() == d.slot;
    }

    private void fallback(Display d) {
        if (displays.get(d.player.getUniqueId()) != d) return;
        hide(d.player);
        ctx.messages().send(d.player, "totp.qr-unavailable");
    }

    private void forget(Display d) {
        displays.remove(d.player.getUniqueId(), d);
        if (d.cancelTimer != null) d.cancelTimer.run();
    }

    /** Clears map pixels, then restores the CURRENT real slot, never a cached item to the server. */
    public boolean hide(Player player) {
        Display d = displays.remove(player.getUniqueId());
        if (d == null) return false;
        if (d.cancelTimer != null) d.cancelTimer.run();
        QrMapPackets adapter = packets;
        if (adapter != null && d.restorePacket != null) {
            try {
                adapter.erase(player, d.mapId);
            } catch (ReflectiveOperationException ignored) { /* still restore the item */ }
            try {
                adapter.send(player, adapter.inventoryPacket(d.slot, player.getInventory().getItem(d.slot)));
            } catch (ReflectiveOperationException ignored) { /* disconnected client or unsupported packets */ }
        }
        return true;
    }

    /** Plugin shutdown may run outside a Folia entity thread: only send captured packets, no inventory reads. */
    public synchronized void close() {
        closed = true;
        for (Display d : displays.values()) {
            forget(d);
            QrMapPackets adapter = packets;
            if (adapter == null || d.restorePacket == null) continue;
            try {
                adapter.erase(d.player, d.mapId);
            } catch (ReflectiveOperationException ignored) { /* best effort on a closing connection */ }
            try {
                adapter.send(d.player, d.restorePacket);
            } catch (ReflectiveOperationException ignored) { /* server inventory was never changed */ }
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onHeld(PlayerItemHeldEvent event) { hide(event.getPlayer()); }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onDrop(PlayerDropItemEvent event) {
        if (hide(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onSwap(PlayerSwapHandItemsEvent event) {
        if (hide(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInteract(PlayerInteractEvent event) {
        if (hide(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInteractEntity(PlayerInteractEntityEvent event) {
        if (hide(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onInteractAtEntity(PlayerInteractAtEntityEvent event) {
        if (hide(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onArmorStand(PlayerArmorStandManipulateEvent event) {
        if (hide(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onGameMode(PlayerGameModeChangeEvent event) { hide(event.getPlayer()); }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onAttack(EntityDamageByEntityEvent event) {
        if (event.getDamager() instanceof Player player && hide(player)) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onOpen(InventoryOpenEvent event) {
        if (event.getPlayer() instanceof Player player) hide(player);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onClick(InventoryClickEvent event) {
        if (event.getWhoClicked() instanceof Player player && hide(player)) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onDrag(InventoryDragEvent event) {
        if (event.getWhoClicked() instanceof Player player && hide(player)) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onTeleport(PlayerTeleportEvent event) { hide(event.getPlayer()); }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onDeath(PlayerDeathEvent event) { hide(event.getEntity()); }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onQuit(PlayerQuitEvent event) {
        // The disconnected client's map cache is gone; do not touch a retiring entity's inventory.
        Display d = displays.get(event.getPlayer().getUniqueId());
        if (d != null) forget(d);
    }
}

package me.skerik.justlogin.paper.gui;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import me.skerik.justlogin.core.model.Account;
import me.skerik.justlogin.paper.Context;
import me.skerik.justlogin.paper.auth.AuthSessionManager.PlayerSession;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.bukkit.Bukkit;
import org.bukkit.Material;
import org.bukkit.entity.Player;
import org.bukkit.event.Event;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryDragEvent;
import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.InventoryHolder;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.jspecify.annotations.Nullable;

/**
 * Paginated read/quick-toggle admin account browser ({@code /jl gui}) enforcing strict Rule 8 click cancellation.
 */
public final class AdminGui implements Listener {

    private static final int PAGE_SIZE = 45;
    private static final int SIZE = 54;
    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneOffset.UTC);

    public enum FilterMode {
        ALL("gui.filter-all"),
        PREMIUM("gui.filter-premium"),
        CRACKED("gui.filter-cracked"),
        TOTP("gui.filter-2fa");

        private final String messageKey;

        FilterMode(String messageKey) {
            this.messageKey = messageKey;
        }

        public String messageKey() {
            return messageKey;
        }

        public FilterMode next() {
            FilterMode[] vals = values();
            return vals[(ordinal() + 1) % vals.length];
        }

        public boolean matches(Account a) {
            return switch (this) {
                case ALL -> true;
                case PREMIUM -> a.isPremiumConfirmed();
                case CRACKED -> !a.isPremiumConfirmed();
                case TOTP -> a.hasTotp();
            };
        }
    }

    public static final class GuiHolder implements InventoryHolder {
        private final int page;
        private final int totalPages;
        private final FilterMode filter;
        private final Map<Integer, Account> accountsBySlot = new HashMap<>();
        private @Nullable Inventory inventory;

        private GuiHolder(int page, int totalPages, FilterMode filter) {
            this.page = page;
            this.totalPages = totalPages;
            this.filter = filter;
        }

        public int page() { return page; }
        public int totalPages() { return totalPages; }
        public FilterMode filter() { return filter; }

        @Override
        public Inventory getInventory() {
            return inventory;
        }

        private void setInventory(Inventory inventory) {
            this.inventory = inventory;
        }
    }

    private final Context ctx;

    public AdminGui(Context ctx) {
        this.ctx = ctx;
    }

    public void open(Player player, int requestedPage) {
        open(player, requestedPage, FilterMode.ALL);
    }

    public void open(Player player, int requestedPage, FilterMode filter) {
        int safePage = Math.max(1, requestedPage);
        int offset = (safePage - 1) * PAGE_SIZE;
        ctx.accounts().countAccounts().thenCombine(ctx.accounts().listAccounts(offset, PAGE_SIZE), (total, rows) -> {
            List<Account> filtered = filter == FilterMode.ALL
                    ? rows
                    : rows.stream().filter(filter::matches).toList();
            int totalPages = Math.max(1, (int) Math.ceil(total / (double) PAGE_SIZE));
            int clampedPage = Math.min(safePage, totalPages);
            return new PageData(clampedPage, totalPages, total, filtered);
        }).whenComplete((data, ex) -> ctx.scheduler().runForEntity(player, () -> {
            if (ex != null || data == null) {
                ctx.messages().send(player, "general.internal-error");
                return;
            }
            if (!player.isOnline()) return;
            GuiHolder holder = new GuiHolder(data.page(), data.totalPages(), filter);
            Component title = ctx.messages().component("gui.title", Map.of(
                    "page", String.valueOf(data.page()),
                    "pages", String.valueOf(data.totalPages())));
            Inventory inv = Bukkit.createInventory(holder, SIZE, title);
            holder.setInventory(inv);
            populate(inv, holder, data);
            player.openInventory(inv);
        }, null));
    }

    private void populate(Inventory inv, GuiHolder holder, PageData data) {
        for (int i = 0; i < data.rows().size() && i < PAGE_SIZE; i++) {
            Account a = data.rows().get(i);
            holder.accountsBySlot.put(i, a);
            inv.setItem(i, accountItem(a));
        }

        if (data.page() > 1) {
            inv.setItem(45, navItem(Material.ARROW, ctx.messages().component("gui.prev-page"), List.of()));
        }
        inv.setItem(47, navItem(Material.HOPPER, ctx.messages().component(holder.filter().messageKey()), List.of()));
        inv.setItem(49, navItem(Material.BOOK,
                ctx.messages().component("gui.page-info", Map.of(
                        "page", String.valueOf(data.page()),
                        "pages", String.valueOf(data.totalPages()),
                        "total", String.valueOf(data.total()))),
                List.of()));
        inv.setItem(51, navItem(Material.SUNFLOWER, ctx.messages().component("gui.refresh"), List.of()));
        inv.setItem(52, navItem(Material.BARRIER, ctx.messages().component("gui.close"), List.of()));
        if (data.page() < data.totalPages()) {
            inv.setItem(53, navItem(Material.ARROW, ctx.messages().component("gui.next-page"), List.of()));
        }
    }

    private ItemStack accountItem(Account a) {
        Material mat = a.forcePasswordChange()
                ? Material.REDSTONE
                : (a.isPremiumConfirmed() ? Material.EMERALD : Material.IRON_INGOT);
        ItemStack stack = new ItemStack(mat);
        ItemMeta meta = stack.getItemMeta();
        if (meta != null) {
            PlayerSession s = ctx.sessionManager().getSessionByName(a.lastName());
            String onlineState = s != null ? s.state().name() : "OFFLINE";
            meta.displayName(Component.text(a.lastName(),
                    a.isPremiumConfirmed() ? NamedTextColor.GREEN : NamedTextColor.AQUA));
            meta.lore(List.of(
                    Component.text("ID: " + a.id() + " | State: " + onlineState, NamedTextColor.GRAY),
                    Component.text("UUID: " + a.gameUuid(), NamedTextColor.DARK_GRAY),
                    Component.text("Premium: " + a.premium() + " | 2FA: " + a.hasTotp(), NamedTextColor.YELLOW),
                    Component.text("Force PW Change: " + a.forcePasswordChange(), NamedTextColor.GOLD),
                    Component.text("Last login: " + TIME_FMT.format(Instant.ofEpochMilli(a.lastLoginAt())), NamedTextColor.GRAY),
                    Component.text("Left-click: Toggle Force PW Reset", NamedTextColor.DARK_AQUA),
                    Component.text("Right-click: Print details in chat", NamedTextColor.DARK_AQUA)
            ));
            stack.setItemMeta(meta);
        }
        return stack;
    }

    private static ItemStack navItem(Material mat, Component name, List<Component> lore) {
        ItemStack stack = new ItemStack(mat);
        ItemMeta meta = stack.getItemMeta();
        if (meta != null) {
            meta.displayName(name);
            if (!lore.isEmpty()) meta.lore(lore);
            stack.setItemMeta(meta);
        }
        return stack;
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = false)
    public void onInventoryClick(InventoryClickEvent event) {
        Inventory top = event.getView().getTopInventory();
        if (!(top.getHolder() instanceof GuiHolder holder)) return;
        // Rule 8: always cancel regardless of slot or prior cancellation
        event.setCancelled(true);
        event.setResult(Event.Result.DENY);

        if (event.getClickedInventory() == null || !event.getClickedInventory().equals(top)) return;
        if (!(event.getWhoClicked() instanceof Player player)) return;

        int slot = event.getRawSlot();
        if (slot == 45 && holder.page() > 1) {
            open(player, holder.page() - 1, holder.filter());
            return;
        }
        if (slot == 47) {
            open(player, 1, holder.filter().next());
            return;
        }
        if (slot == 51) {
            open(player, holder.page(), holder.filter());
            return;
        }
        if (slot == 52) {
            player.closeInventory();
            return;
        }
        if (slot == 53 && holder.page() < holder.totalPages()) {
            open(player, holder.page() + 1, holder.filter());
            return;
        }

        Account acc = holder.accountsBySlot.get(slot);
        if (acc == null) return;
        if (event.isRightClick()) {
            PlayerSession s = ctx.sessionManager().getSessionByName(acc.lastName());
            ctx.messages().send(player, "admin.status-header", Map.of("player", acc.lastName()));
            ctx.messages().sendRaw(player, "admin.status-line", Map.of(
                    "id", String.valueOf(acc.id()),
                    "uuid", acc.gameUuid().toString(),
                    "algo", acc.hashAlgo().name(),
                    "premium", String.valueOf(acc.premium()),
                    "pending", String.valueOf(acc.premiumPending()),
                    "totp", String.valueOf(acc.hasTotp()),
                    "forcePw", String.valueOf(acc.forcePasswordChange()),
                    "state", s != null ? s.state().name() : "OFFLINE"));
            return;
        }

        if (!player.hasPermission("justlogin.admin") && !player.hasPermission("justlogin.admin.forcepw")) {
            ctx.messages().send(player, "general.no-permission");
            return;
        }
        boolean nextForce = !acc.forcePasswordChange();
        ctx.authService().adminSetForcePasswordChange(acc.lastName(), nextForce, player.getName())
                .whenComplete((res, ex) -> ctx.scheduler().runForEntity(player, () -> {
                    ctx.messages().send(player, "admin.force-pw-updated",
                            Map.of("player", acc.lastName(), "value", String.valueOf(nextForce)));
                    open(player, holder.page(), holder.filter());
                }, null));
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = false)
    public void onInventoryDrag(InventoryDragEvent event) {
        if (event.getView().getTopInventory().getHolder() instanceof GuiHolder) {
            event.setCancelled(true);
            event.setResult(Event.Result.DENY);
        }
    }

    private record PageData(int page, int totalPages, long total, List<Account> rows) {
    }
}

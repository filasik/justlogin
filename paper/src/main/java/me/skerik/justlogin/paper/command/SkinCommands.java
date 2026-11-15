package me.skerik.justlogin.paper.command;

import com.destroystokyo.paper.profile.PlayerProfile;
import com.destroystokyo.paper.profile.ProfileProperty;
import com.mojang.brigadier.Command;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;
import io.papermc.paper.command.brigadier.CommandSourceStack;
import io.papermc.paper.command.brigadier.Commands;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import me.skerik.justlogin.core.model.Account;
import me.skerik.justlogin.core.service.MojangSkinClient;
import me.skerik.justlogin.core.service.MojangSkinClient.SkinData;
import me.skerik.justlogin.paper.Context;
import me.skerik.justlogin.paper.JustLogin;
import me.skerik.justlogin.paper.auth.AuthSessionManager.PlayerSession;
import org.bukkit.Bukkit;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.jspecify.annotations.Nullable;

/** Player-facing {@code /skin} command and shared Mojang texture application helpers. */
public final class SkinCommands {

    private static final Pattern MOJANG_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_]{3,16}$");

    private final JustLogin plugin;

    public SkinCommands(JustLogin plugin) {
        this.plugin = plugin;
    }

    private @Nullable Context readyContext(CommandSender sender) {
        Context ctx = plugin.context();
        if (ctx == null) {
            plugin.earlyMessages().send(sender, "error.not-ready");
        }
        return ctx;
    }

    public void register(Commands commands) {
        commands.register(
                Commands.literal("skin")
                        .requires(s -> hasSkinPerm(s.getSender()))
                        .executes(c -> usage(c, "skins.usage"))
                        .then(Commands.literal("reset")
                                .executes(this::handleReset))
                        .then(Commands.literal("clear")
                                .executes(this::handleReset))
                        .then(Commands.argument("target", StringArgumentType.word())
                                .suggests((c, b) -> {
                                    String rem = b.getRemainingLowerCase();
                                    if ("reset".startsWith(rem)) b.suggest("reset");
                                    if ("clear".startsWith(rem)) b.suggest("clear");
                                    for (Player online : Bukkit.getOnlinePlayers()) {
                                        String n = online.getName();
                                        if (n.toLowerCase(Locale.ROOT).startsWith(rem)) {
                                            b.suggest(n);
                                        }
                                    }
                                    return b.buildFuture();
                                })
                                .executes(c -> handleSet(c, StringArgumentType.getString(c, "target"))))
                        .build(),
                "Change or reset your player skin",
                List.of("skins"));
    }

    public static boolean isValidMojangUsername(@Nullable String target) {
        return target != null && MOJANG_NAME_PATTERN.matcher(target.strip()).matches();
    }

    public static boolean isResetKeyword(@Nullable String target) {
        if (target == null) return false;
        String lower = target.strip().toLowerCase(Locale.ROOT);
        return "reset".equals(lower) || "clear".equals(lower);
    }

    public static boolean hasTextures(PlayerProfile profile) {
        for (ProfileProperty prop : profile.getProperties()) {
            if ("textures".equals(prop.getName()) && prop.getValue() != null && !prop.getValue().isBlank()) {
                return true;
            }
        }
        return false;
    }

    public static void applyProfileTextures(PlayerProfile profile, @Nullable String value, @Nullable String signature) {
        profile.removeProperty("textures");
        if (value != null && !value.isBlank() && signature != null && !signature.isBlank()) {
            profile.setProperty(new ProfileProperty("textures", value, signature));
        }
    }

    public static void applyLiveSkin(Player player, @Nullable String value, @Nullable String signature) {
        PlayerProfile profile = player.getPlayerProfile();
        applyProfileTextures(profile, value, signature);
        player.setPlayerProfile(profile);
    }

    /**
     * Fetches a Mojang skin for {@code skinTarget} and persists it on {@code account}.
     * Callers run the returned completion on the appropriate entity/sender thread.
     */
    public static java.util.concurrent.CompletableFuture<MojangSkinClient.SkinLookupResult> fetchAndSaveCustomSkin(
            Context ctx, Account account, String skinTarget, String actor, String auditAction) {
        return ctx.skinClient().fetchByUsername(skinTarget).thenCompose(res -> {
            if (res.status() != MojangSkinClient.Status.FOUND || res.skin() == null) {
                return java.util.concurrent.CompletableFuture.completedFuture(res);
            }
            SkinData skin = res.skin();
            long now = System.currentTimeMillis();
            return ctx.accounts().updateCustomSkin(account.id(), skin.ownerName(), skin.value(), skin.signature(), now)
                    .thenCompose(v -> ctx.audit().record(now, actor, auditAction, account.lastName(), skin.ownerName()))
                    .thenApply(v -> res);
        });
    }

    /**
     * Clears any saved custom skin on {@code account} and optionally fetches their default Mojang skin by name.
     */
    public static java.util.concurrent.CompletableFuture<@Nullable SkinData> clearAndResolveDefaultSkin(
            Context ctx, Account account, String actor, String auditAction) {
        long now = System.currentTimeMillis();
        return ctx.accounts().clearCustomSkin(account.id(), now)
                .thenCompose(v -> ctx.audit().record(now, actor, auditAction, account.lastName(), null))
                .thenCompose(v -> {
                    boolean restoreDefault = ctx.settings().skinsEnabled()
                            && (ctx.settings().skinsRestoreByName() || account.isPremiumConfirmed());
                    if (!restoreDefault) {
                        return java.util.concurrent.CompletableFuture.completedFuture(null);
                    }
                    return ctx.skinClient().fetchByUsername(account.lastName())
                            .thenApply(res -> res.status() == MojangSkinClient.Status.FOUND ? res.skin() : null);
                });
    }

    private static boolean hasSkinPerm(CommandSender sender) {
        return !(sender instanceof Player) || sender.hasPermission("justlogin.skin");
    }

    private int usage(CommandContext<CommandSourceStack> c, String key) {
        Context ctx = readyContext(c.getSource().getSender());
        if (ctx == null) return Command.SINGLE_SUCCESS;
        ctx.messages().send(c.getSource().getSender(), key);
        return Command.SINGLE_SUCCESS;
    }

    private @Nullable PlayerSession requireAuthenticated(Context ctx, CommandContext<CommandSourceStack> c) {
        if (!(c.getSource().getSender() instanceof Player p)) {
            ctx.messages().send(c.getSource().getSender(), "general.players-only");
            return null;
        }
        PlayerSession s = ctx.sessionManager().getSession(p.getUniqueId());
        if (s == null || !s.isAuthenticated()) {
            ctx.messages().send(p, "auth.not-logged-in");
            return null;
        }
        return s;
    }

    private int handleSet(CommandContext<CommandSourceStack> c, String target) {
        if (isResetKeyword(target)) {
            return handleReset(c);
        }
        Context ctx = readyContext(c.getSource().getSender());
        if (ctx == null) return Command.SINGLE_SUCCESS;
        PlayerSession session = requireAuthenticated(ctx, c);
        if (session == null) return Command.SINGLE_SUCCESS;
        Player player = (Player) c.getSource().getSender();
        if (!ctx.settings().skinsEnabled() || !ctx.settings().skinsCommandEnabled()) {
            ctx.messages().send(player, "skins.disabled");
            return Command.SINGLE_SUCCESS;
        }
        if (!player.hasPermission("justlogin.skin")) {
            ctx.messages().send(player, "general.no-permission");
            return Command.SINGLE_SUCCESS;
        }
        if (!isValidMojangUsername(target)) {
            ctx.messages().send(player, "skins.invalid-target");
            return Command.SINGLE_SUCCESS;
        }
        if (!canBypassCooldown(player)) {
            long rem = ctx.remainingSkinCooldownSeconds(player.getUniqueId());
            if (rem > 0L) {
                ctx.messages().send(player, "skins.cooldown", Map.of("seconds", String.valueOf(rem)));
                return Command.SINGLE_SUCCESS;
            }
        }
        Account acc = session.account();
        if (acc == null) {
            ctx.messages().send(player, "auth.not-logged-in");
            return Command.SINGLE_SUCCESS;
        }
        ctx.messages().send(player, "skins.fetching", Map.of("skin", target));
        fetchAndSaveCustomSkin(ctx, acc, target, player.getName(), "SKIN_SET").whenComplete((res, ex) ->
                ctx.scheduler().runForEntity(player, () -> {
                    if (!player.isOnline()) return;
                    if (ex != null || res == null) {
                        ctx.messages().send(player, "skins.mojang-unavailable");
                        return;
                    }
                    switch (res.status()) {
                        case FOUND -> {
                            SkinData skin = res.skin();
                            if (skin == null) {
                                ctx.messages().send(player, "skins.mojang-unavailable");
                                return;
                            }
                            applyLiveSkin(player, skin.value(), skin.signature());
                            ctx.markSkinChanged(player.getUniqueId());
                            ctx.accounts().findByNameLower(session.nameLower()).whenComplete((opt, ex2) -> {
                                if (opt != null) opt.ifPresent(session::setAccount);
                            });
                            ctx.messages().send(player, "skins.changed", Map.of("skin", skin.ownerName()));
                        }
                        case NOT_FOUND -> ctx.messages().send(player, "skins.not-found", Map.of("skin", target));
                        case RATE_LIMITED, UNAVAILABLE -> ctx.messages().send(player, "skins.mojang-unavailable");
                    }
                }, null));
        return Command.SINGLE_SUCCESS;
    }

    private int handleReset(CommandContext<CommandSourceStack> c) {
        Context ctx = readyContext(c.getSource().getSender());
        if (ctx == null) return Command.SINGLE_SUCCESS;
        PlayerSession session = requireAuthenticated(ctx, c);
        if (session == null) return Command.SINGLE_SUCCESS;
        Player player = (Player) c.getSource().getSender();
        if (!ctx.settings().skinsEnabled() || !ctx.settings().skinsCommandEnabled()) {
            ctx.messages().send(player, "skins.disabled");
            return Command.SINGLE_SUCCESS;
        }
        if (!player.hasPermission("justlogin.skin")) {
            ctx.messages().send(player, "general.no-permission");
            return Command.SINGLE_SUCCESS;
        }
        if (!canBypassCooldown(player)) {
            long rem = ctx.remainingSkinCooldownSeconds(player.getUniqueId());
            if (rem > 0L) {
                ctx.messages().send(player, "skins.cooldown", Map.of("seconds", String.valueOf(rem)));
                return Command.SINGLE_SUCCESS;
            }
        }
        Account acc = session.account();
        if (acc == null) {
            ctx.messages().send(player, "auth.not-logged-in");
            return Command.SINGLE_SUCCESS;
        }
        clearAndResolveDefaultSkin(ctx, acc, player.getName(), "SKIN_RESET").whenComplete((skin, ex) ->
                ctx.scheduler().runForEntity(player, () -> {
                    if (!player.isOnline()) return;
                    if (ex != null) {
                        ctx.messages().send(player, "general.internal-error");
                        return;
                    }
                    if (skin != null) {
                        applyLiveSkin(player, skin.value(), skin.signature());
                        ctx.messages().send(player, "skins.reset-restored", Map.of("skin", skin.ownerName()));
                    } else {
                        applyLiveSkin(player, null, null);
                        ctx.messages().send(player, "skins.reset");
                    }
                    ctx.markSkinChanged(player.getUniqueId());
                    ctx.accounts().findByNameLower(session.nameLower()).whenComplete((opt, ex2) -> {
                        if (opt != null) opt.ifPresent(session::setAccount);
                    });
                }, null));
        return Command.SINGLE_SUCCESS;
    }

    private static boolean canBypassCooldown(Player player) {
        return player.hasPermission("justlogin.skin.bypasscooldown")
                || player.hasPermission("justlogin.admin.skin")
                || player.hasPermission("justlogin.admin");
    }
}

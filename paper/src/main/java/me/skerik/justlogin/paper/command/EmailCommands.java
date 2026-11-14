package me.skerik.justlogin.paper.command;

import com.mojang.brigadier.Command;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;
import io.papermc.paper.command.brigadier.CommandSourceStack;
import io.papermc.paper.command.brigadier.Commands;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import me.skerik.justlogin.core.service.EmailRecoveryService;
import me.skerik.justlogin.paper.Context;
import me.skerik.justlogin.paper.JustLogin;
import me.skerik.justlogin.paper.auth.AuthSessionManager.PlayerSession;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.jspecify.annotations.Nullable;

/** Player-facing {@code /email} management and password recovery command tree. */
public final class EmailCommands {

    private final JustLogin plugin;

    public EmailCommands(JustLogin plugin) {
        this.plugin = plugin;
    }

    public void register(Commands commands) {
        commands.register(
                Commands.literal("email")
                        .requires(s -> !(s.getSender() instanceof Player) || s.getSender().hasPermission("justlogin.email"))
                        .executes(c -> usage(c.getSource().getSender()))
                        .then(Commands.literal("set")
                                .requires(s -> !(s.getSender() instanceof Player) || s.getSender().hasPermission("justlogin.email"))
                                .executes(c -> usage(c.getSource().getSender()))
                                .then(Commands.argument("addressAndPassword", StringArgumentType.greedyString())
                                        .suggests((c, b) -> {
                                            if (b.getRemaining().isEmpty()) {
                                                b.suggest("<email@example.com> <password>");
                                            }
                                            return b.buildFuture();
                                        })
                                        .executes(c -> handleSetCombined(
                                                c,
                                                StringArgumentType.getString(c, "addressAndPassword")))))
                        .then(Commands.literal("confirm")
                                .requires(s -> !(s.getSender() instanceof Player) || s.getSender().hasPermission("justlogin.email"))
                                .executes(c -> usage(c.getSource().getSender()))
                                .then(Commands.argument("code", StringArgumentType.word())
                                        .suggests((c, b) -> {
                                            if (b.getRemaining().isEmpty()) {
                                                b.suggest("<code>");
                                            }
                                            return b.buildFuture();
                                        })
                                        .executes(c -> handleConfirm(c, StringArgumentType.getString(c, "code")))))
                        .then(Commands.literal("clear")
                                .requires(s -> !(s.getSender() instanceof Player) || s.getSender().hasPermission("justlogin.email"))
                                .executes(this::handleClear))
                        .then(Commands.literal("recover")
                                .requires(s -> !(s.getSender() instanceof Player) || s.getSender().hasPermission("justlogin.email"))
                                .executes(c -> usage(c.getSource().getSender()))
                                .then(Commands.argument("username", StringArgumentType.word())
                                        .suggests((c, b) -> {
                                            if (c.getSource().getSender() instanceof Player p) {
                                                if (p.getName().toLowerCase(java.util.Locale.ROOT).startsWith(b.getRemainingLowerCase())) {
                                                    b.suggest(p.getName());
                                                }
                                                return b.buildFuture();
                                            }
                                            Context ctx = plugin.context();
                                            if (ctx == null) {
                                                return b.buildFuture();
                                            }
                                            String rem = b.getRemainingLowerCase();
                                            return ctx.accounts().suggestNames(rem, 30).thenApply(names -> {
                                                for (String name : names) {
                                                    b.suggest(name);
                                                }
                                                return b.build();
                                            });
                                        })
                                        .executes(c -> handleRequestRecover(c, StringArgumentType.getString(c, "username")))
                                        .then(Commands.argument("code", StringArgumentType.word())
                                                .suggests((c, b) -> {
                                                    if (b.getRemaining().isEmpty()) {
                                                        b.suggest("<code>");
                                                    }
                                                    return b.buildFuture();
                                                })
                                                .executes(c -> usage(c.getSource().getSender()))
                                                .then(Commands.argument("newPassword", StringArgumentType.greedyString())
                                                        .suggests((c, b) -> {
                                                            if (b.getRemaining().isEmpty()) {
                                                                b.suggest("<newPassword>");
                                                            }
                                                            return b.buildFuture();
                                                        })
                                                        .executes(c -> handleCompleteRecover(
                                                                c,
                                                                StringArgumentType.getString(c, "username"),
                                                                StringArgumentType.getString(c, "code"),
                                                                StringArgumentType.getString(c, "newPassword")))))))
                        .build(),
                "Manage recovery email or recover forgotten password",
                List.of());
    }

    private @Nullable Context readyContext(CommandSender sender) {
        Context ctx = plugin.context();
        if (ctx == null) plugin.earlyMessages().send(sender, "error.not-ready");
        return ctx;
    }

    private int usage(CommandSender sender) {
        Context ctx = readyContext(sender);
        if (ctx != null) ctx.messages().send(sender, "email.usage");
        return Command.SINGLE_SUCCESS;
    }

    private int handleSetCombined(CommandContext<CommandSourceStack> c, String addressAndPassword) {
        String trimmed = addressAndPassword == null ? "" : addressAndPassword.strip();
        int sp = trimmed.indexOf(' ');
        if (sp <= 0) {
            return usage(c.getSource().getSender());
        }
        String address = trimmed.substring(0, sp).strip();
        String password = trimmed.substring(sp + 1).strip();
        if (address.isEmpty() || password.isEmpty()) {
            return usage(c.getSource().getSender());
        }
        return handleSet(c, address, password);
    }

    private int handleSet(CommandContext<CommandSourceStack> c, String address, String password) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        if (!(sender instanceof Player player)) {
            ctx.messages().send(sender, "general.players-only");
            return Command.SINGLE_SUCCESS;
        }
        PlayerSession session = ctx.sessionManager().getSession(player.getUniqueId());
        if (session == null || !session.isAuthenticated()) {
            ctx.messages().send(player, "auth.not-logged-in");
            return Command.SINGLE_SUCCESS;
        }
        ctx.emailRecovery().requestSetEmail(player.getName(), address, password.toCharArray(), session.ip(), player.getName())
                .whenComplete((res, ex) -> ctx.scheduler().runForEntity(player, () -> {
                    if (ex != null || res == null) {
                        ctx.messages().send(player, "general.internal-error");
                        return;
                    }
                    switch (res.status()) {
                        case CONFIRMATION_SENT, SUCCESS -> ctx.messages().send(player, "email.confirm-sent",
                                Map.of("email", EmailRecoveryService.maskEmail(address.trim())));
                        case DISABLED -> ctx.messages().send(player, "email.disabled");
                        case INVALID_EMAIL -> ctx.messages().send(player, "email.invalid");
                        case INVALID_CREDENTIALS -> ctx.messages().send(player, "auth.wrong-password");
                        case NO_PASSWORD_SET -> ctx.messages().send(player, "email.no-password-set");
                        case COOLDOWN -> ctx.messages().send(player, "email.cooldown",
                                Map.of("seconds", String.valueOf(res.waitSeconds())));
                        case RATE_LIMITED -> ctx.messages().send(player, "general.rate-limited",
                                Map.of("seconds", String.valueOf(res.waitSeconds())));
                        case SEND_FAILED -> ctx.messages().send(player, "email.send-failed");
                        case HASHING_BUSY -> ctx.messages().send(player, "general.hashing-busy");
                        default -> ctx.messages().send(player, "general.internal-error");
                    }
                }, null));
        return Command.SINGLE_SUCCESS;
    }

    private int handleConfirm(CommandContext<CommandSourceStack> c, String code) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        if (!(sender instanceof Player player)) {
            ctx.messages().send(sender, "general.players-only");
            return Command.SINGLE_SUCCESS;
        }
        PlayerSession session = ctx.sessionManager().getSession(player.getUniqueId());
        if (session == null || !session.isAuthenticated()) {
            ctx.messages().send(player, "auth.not-logged-in");
            return Command.SINGLE_SUCCESS;
        }
        ctx.emailRecovery().confirmEmail(player.getName(), code, session.ip(), player.getName())
                .whenComplete((res, ex) -> ctx.scheduler().runForEntity(player, () -> {
                    if (ex != null || res == null) {
                        ctx.messages().send(player, "general.internal-error");
                        return;
                    }
                    switch (res.status()) {
                        case SUCCESS -> ctx.messages().send(player, "email.confirmed");
                        case DISABLED -> ctx.messages().send(player, "email.disabled");
                        case RATE_LIMITED -> ctx.messages().send(player, "general.rate-limited",
                                Map.of("seconds", String.valueOf(res.waitSeconds())));
                        default -> ctx.messages().send(player, "email.invalid-code");
                    }
                }, null));
        return Command.SINGLE_SUCCESS;
    }

    private int handleClear(CommandContext<CommandSourceStack> c) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        if (!(sender instanceof Player player)) {
            ctx.messages().send(sender, "general.players-only");
            return Command.SINGLE_SUCCESS;
        }
        PlayerSession session = ctx.sessionManager().getSession(player.getUniqueId());
        if (session == null || !session.isAuthenticated()) {
            ctx.messages().send(player, "auth.not-logged-in");
            return Command.SINGLE_SUCCESS;
        }
        ctx.emailRecovery().clearEmail(player.getName(), player.getName())
                .whenComplete((res, ex) -> ctx.scheduler().runForEntity(player, () ->
                        ctx.messages().send(player, "email.cleared"), null));
        return Command.SINGLE_SUCCESS;
    }

    private int handleRequestRecover(CommandContext<CommandSourceStack> c, String username) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        if (!ctx.settings().smtpConfig().enabled()) {
            ctx.messages().send(sender, "email.disabled");
            return Command.SINGLE_SUCCESS;
        }
        String ip = extractSenderIp(sender);
        ctx.emailRecovery().requestRecovery(username, ip).whenComplete((res, ex) -> runOnSender(ctx, sender, () -> {
            if (ex != null || res == null) {
                ctx.messages().send(sender, "general.internal-error");
                return;
            }
            switch (res.status()) {
                case RATE_LIMITED -> ctx.messages().send(sender, "general.rate-limited",
                        Map.of("seconds", String.valueOf(res.waitSeconds())));
                case COOLDOWN -> ctx.messages().send(sender, "email.cooldown",
                        Map.of("seconds", String.valueOf(res.waitSeconds())));
                case SEND_FAILED -> ctx.messages().send(sender, "email.send-failed");
                case DISABLED -> ctx.messages().send(sender, "email.disabled");
                // Uniform anti-enumeration response across SENT / NO_EMAIL / NOT_REGISTERED
                default -> ctx.messages().send(sender, "email.recovery-requested");
            }
        }));
        return Command.SINGLE_SUCCESS;
    }

    private int handleCompleteRecover(
            CommandContext<CommandSourceStack> c, String username, String code, String newPw) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        String ip = extractSenderIp(sender);
        ctx.emailRecovery().completeRecovery(username, code, newPw.toCharArray(), ip)
                .whenComplete((res, ex) -> runOnSender(ctx, sender, () -> {
                    if (ex != null || res == null) {
                        ctx.messages().send(sender, "general.internal-error");
                        return;
                    }
                    switch (res.status()) {
                        case SUCCESS -> ctx.messages().send(sender, "email.recovery-complete");
                        case DISABLED -> ctx.messages().send(sender, "email.disabled");
                        case PASSWORD_POLICY_VIOLATION -> sender.sendMessage(
                                ctx.messages().component("prefix").append(ctx.coordinator().policyComponent(res.violation())));
                        case RATE_LIMITED -> ctx.messages().send(sender, "general.rate-limited",
                                Map.of("seconds", String.valueOf(res.waitSeconds())));
                        case HASHING_BUSY -> ctx.messages().send(sender, "general.hashing-busy");
                        default -> ctx.messages().send(sender, "email.invalid-code");
                    }
                }));
        return Command.SINGLE_SUCCESS;
    }

    private static String extractSenderIp(CommandSender sender) {
        if (sender instanceof Player p) {
            InetSocketAddress isa = p.getAddress();
            return isa != null && isa.getAddress() != null ? isa.getAddress().getHostAddress() : "unknown";
        }
        return "127.0.0.1";
    }

    private static void runOnSender(Context ctx, CommandSender sender, Runnable task) {
        if (sender instanceof Player p) ctx.scheduler().runForEntity(p, task, null);
        else ctx.scheduler().runGlobal(task);
    }
}

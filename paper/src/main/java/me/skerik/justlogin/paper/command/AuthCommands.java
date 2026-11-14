package me.skerik.justlogin.paper.command;

import com.mojang.brigadier.Command;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;
import io.papermc.paper.command.brigadier.CommandSourceStack;
import io.papermc.paper.command.brigadier.Commands;
import java.util.List;
import java.util.Map;
import me.skerik.justlogin.api.AccountSnapshot;
import me.skerik.justlogin.api.event.PlayerLoggedOutEvent;
import me.skerik.justlogin.core.crypto.ProxyTokenSigner;
import me.skerik.justlogin.core.model.Account;
import me.skerik.justlogin.core.service.AuthService;
import me.skerik.justlogin.paper.Context;
import me.skerik.justlogin.paper.JustLogin;
import me.skerik.justlogin.paper.auth.AuthSessionManager.AuthState;
import me.skerik.justlogin.paper.auth.AuthSessionManager.PlayerSession;
import me.skerik.justlogin.paper.config.Messages;
import me.skerik.justlogin.paper.config.Settings;
import me.skerik.justlogin.paper.listener.ProxyMessageListener;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.event.ClickEvent;
import org.bukkit.Bukkit;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.jspecify.annotations.Nullable;

/** Player-facing authentication commands registered via Paper Brigadier lifecycle API. */
public final class AuthCommands {

    private final JustLogin plugin;
    private final ProxyMessageListener proxyMessenger;

    public AuthCommands(JustLogin plugin, ProxyMessageListener proxyMessenger) {
        this.plugin = plugin;
        this.proxyMessenger = proxyMessenger;
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
                Commands.literal("login")
                        .requires(s -> hasUsePerm(s.getSender()))
                        .executes(c -> usage(c, "auth.usage-login"))
                        .then(Commands.argument("password", StringArgumentType.greedyString())
                                .suggests((c, b) -> {
                                    if (b.getRemaining().isEmpty()) {
                                        b.suggest("<password>");
                                    }
                                    return b.buildFuture();
                                })
                                .executes(c -> handleLogin(c, StringArgumentType.getString(c, "password"))))
                        .build(),
                "Log in to your account",
                List.of("l"));

        commands.register(
                Commands.literal("register")
                        .requires(s -> hasUsePerm(s.getSender()))
                        .executes(c -> usage(c, "auth.usage-register"))
                        .then(Commands.argument("passwordConfirm", StringArgumentType.greedyString())
                                .suggests((c, b) -> {
                                    String rem = b.getRemaining();
                                    if (rem.isEmpty()) {
                                        b.suggest("<password> <confirm>");
                                    } else if (!rem.contains(" ")) {
                                        b.suggest(rem + " <confirm>");
                                    }
                                    return b.buildFuture();
                                })
                                .executes(c -> {
                                    String[] parts = splitTwoArgs(StringArgumentType.getString(c, "passwordConfirm"));
                                    return parts == null
                                            ? usage(c, "auth.usage-register")
                                            : handleRegister(c, parts[0], parts[1]);
                                }))
                        .build(),
                "Register a new account",
                List.of("reg"));

        commands.register(
                Commands.literal("logout")
                        .requires(s -> hasUsePerm(s.getSender()))
                        .executes(this::handleLogout)
                        .build(),
                "Log out of your current session",
                List.of());

        commands.register(
                Commands.literal("changepassword")
                        .requires(s -> hasUsePerm(s.getSender()))
                        .executes(c -> usage(c, "auth.usage-changepassword"))
                        .then(Commands.argument("oldAndNewPassword", StringArgumentType.greedyString())
                                .suggests((c, b) -> {
                                    String rem = b.getRemaining();
                                    if (rem.isEmpty()) {
                                        b.suggest("<oldPassword> <newPassword>");
                                    } else if (!rem.contains(" ")) {
                                        b.suggest(rem + " <newPassword>");
                                    }
                                    return b.buildFuture();
                                })
                                .executes(c -> {
                                    String[] parts = splitTwoArgs(StringArgumentType.getString(c, "oldAndNewPassword"));
                                    return parts == null
                                            ? usage(c, "auth.usage-changepassword")
                                            : handleChangePassword(c, parts[0], parts[1]);
                                }))
                        .build(),
                "Change your account password",
                List.of("changepass", "cp"));

        commands.register(
                Commands.literal("unregister")
                        .requires(s -> hasUsePerm(s.getSender()))
                        .executes(c -> usage(c, "auth.usage-unregister"))
                        .then(Commands.argument("password", StringArgumentType.greedyString())
                                .suggests((c, b) -> {
                                    if (b.getRemaining().isEmpty()) {
                                        b.suggest("<password>");
                                    }
                                    return b.buildFuture();
                                })
                                .executes(c -> handleUnregister(c, StringArgumentType.getString(c, "password"))))
                        .build(),
                "Delete your registered account",
                List.of());

        commands.register(
                Commands.literal("2fa")
                        .requires(s -> hasUsePerm(s.getSender()) || s.getSender().hasPermission("justlogin.2fa"))
                        .executes(c -> usage(c, "totp.usage"))
                        .then(Commands.literal("setup")
                                .requires(s -> s.getSender().hasPermission("justlogin.2fa"))
                                .executes(this::handle2faSetup))
                        .then(Commands.literal("confirm")
                                .requires(s -> s.getSender().hasPermission("justlogin.2fa"))
                                .executes(c -> usage(c, "totp.usage"))
                                .then(Commands.argument("code", StringArgumentType.word())
                                        .suggests((c, b) -> {
                                            if (b.getRemaining().isEmpty()) {
                                                b.suggest("<code>");
                                            }
                                            return b.buildFuture();
                                        })
                                        .executes(c -> handle2faConfirm(c, StringArgumentType.getString(c, "code")))))
                        .then(Commands.literal("disable")
                                .requires(s -> s.getSender().hasPermission("justlogin.2fa"))
                                .executes(c -> usage(c, "totp.usage"))
                                .then(Commands.argument("code", StringArgumentType.word())
                                        .suggests((c, b) -> {
                                            if (b.getRemaining().isEmpty()) {
                                                b.suggest("<code>");
                                            }
                                            return b.buildFuture();
                                        })
                                        .executes(c -> handle2faDisable(c, StringArgumentType.getString(c, "code")))))
                        .then(Commands.literal("verify")
                                .executes(c -> usage(c, "totp.usage"))
                                .then(Commands.argument("code", StringArgumentType.word())
                                        .suggests((c, b) -> {
                                            if (b.getRemaining().isEmpty()) {
                                                b.suggest("<code>");
                                            }
                                            return b.buildFuture();
                                        })
                                        .executes(c -> handle2faVerify(c, StringArgumentType.getString(c, "code")))))
                        .build(),
                "Manage or verify two-factor authentication",
                List.of());

        commands.register(
                Commands.literal("premium")
                        .requires(s -> !(s.getSender() instanceof Player) || s.getSender().hasPermission("justlogin.premium"))
                        .executes(this::handlePremium)
                        .build(),
                "Link your Mojang account for automatic online login",
                List.of());

        commands.register(
                Commands.literal("cracked")
                        .requires(s -> !(s.getSender() instanceof Player) || s.getSender().hasPermission("justlogin.premium"))
                        .executes(c -> handleCracked(c, null))
                        .then(Commands.argument("password", StringArgumentType.greedyString())
                                .suggests((c, b) -> {
                                    if (b.getRemaining().isEmpty()) {
                                        b.suggest("<password>");
                                    }
                                    return b.buildFuture();
                                })
                                .executes(c -> handleCracked(c, StringArgumentType.getString(c, "password"))))
                        .build(),
                "Switch back to offline password authentication",
                List.of());

        commands.register(
                Commands.literal("captcha")
                        .requires(s -> hasUsePerm(s.getSender()))
                        .executes(c -> usage(c, "captcha.usage"))
                        .then(Commands.argument("code", StringArgumentType.word())
                                .suggests((c, b) -> {
                                    if (b.getRemaining().isEmpty()) {
                                        b.suggest("<code>");
                                    }
                                    return b.buildFuture();
                                })
                                .executes(c -> handleCaptcha(c, StringArgumentType.getString(c, "code"))))
                        .build(),
                "Complete pre-authentication captcha challenge",
                List.of());
    }

    private static boolean hasUsePerm(CommandSender sender) {
        return !(sender instanceof Player) || sender.hasPermission("justlogin.use");
    }

    private static String @Nullable [] splitTwoArgs(String raw) {
        String trimmed = raw.trim();
        int sp = trimmed.indexOf(' ');
        if (sp <= 0 || sp >= trimmed.length() - 1) return null;
        String first = trimmed.substring(0, sp);
        String second = trimmed.substring(sp + 1).trim();
        return second.isEmpty() ? null : new String[] { first, second };
    }

    private int usage(CommandContext<CommandSourceStack> c, String key) {
        Context ctx = readyContext(c.getSource().getSender());
        if (ctx == null) return Command.SINGLE_SUCCESS;
        ctx.messages().send(c.getSource().getSender(), key);
        return Command.SINGLE_SUCCESS;
    }

    private @Nullable Player requirePlayer(Context ctx, CommandContext<CommandSourceStack> c) {
        if (c.getSource().getSender() instanceof Player p) return p;
        ctx.messages().send(c.getSource().getSender(), "general.players-only");
        return null;
    }

    private @Nullable PlayerSession requireAuthenticated(Context ctx, CommandContext<CommandSourceStack> c) {
        Player p = requirePlayer(ctx, c);
        if (p == null) return null;
        PlayerSession s = ctx.sessionManager().getSession(p.getUniqueId());
        if (s == null || !s.isAuthenticated()) {
            ctx.messages().send(p, "auth.not-logged-in");
            return null;
        }
        return s;
    }

    private int handleLogin(CommandContext<CommandSourceStack> c, String password) {
        Context ctx = readyContext(c.getSource().getSender());
        if (ctx == null) return Command.SINGLE_SUCCESS;
        Player player = requirePlayer(ctx, c);
        if (player == null) return Command.SINGLE_SUCCESS;
        PlayerSession session = ctx.sessionManager().getSession(player.getUniqueId());
        if (session == null) {
            ctx.messages().send(player, "general.internal-error");
            return Command.SINGLE_SUCCESS;
        }
        ctx.coordinator().submitPlayLogin(player, session, password, false);
        return Command.SINGLE_SUCCESS;
    }

    private int handleRegister(CommandContext<CommandSourceStack> c, String password, String confirm) {
        Context ctx = readyContext(c.getSource().getSender());
        if (ctx == null) return Command.SINGLE_SUCCESS;
        Player player = requirePlayer(ctx, c);
        if (player == null) return Command.SINGLE_SUCCESS;
        PlayerSession session = ctx.sessionManager().getSession(player.getUniqueId());
        if (session == null) {
            ctx.messages().send(player, "general.internal-error");
            return Command.SINGLE_SUCCESS;
        }
        ctx.coordinator().submitPlayRegister(player, session, password, confirm, false);
        return Command.SINGLE_SUCCESS;
    }

    private int handleLogout(CommandContext<CommandSourceStack> c) {
        Context ctx = readyContext(c.getSource().getSender());
        if (ctx == null) return Command.SINGLE_SUCCESS;
        PlayerSession session = requireAuthenticated(ctx, c);
        if (session == null) return Command.SINGLE_SUCCESS;
        Player player = (Player) c.getSource().getSender();
        Account acc = session.account();
        long accountId = acc != null ? acc.id() : -1L;
        boolean passwordless = acc != null && !acc.hasPassword();
        AccountSnapshot snap = acc != null ? AccountSnapshot.fromAccount(acc) : null;
        ctx.authService().logout(player.getName(), player.getName()).whenComplete((v, ex) ->
                ctx.scheduler().runForEntity(player, () -> {
                    ctx.notifyProxyState(player, ProxyTokenSigner.MessageType.LOGOUT, accountId);
                    Bukkit.getPluginManager().callEvent(new PlayerLoggedOutEvent(player, snap));
                    if (passwordless) {
                        ctx.sessionManager().removePlayerSession(player.getUniqueId());
                        player.kick(ctx.messages().component("auth.logged-out"));
                        return;
                    }
                    session.setState(AuthState.AWAITING_LOGIN);
                    session.setAnchorLocation(player.getLocation());
                    player.updateCommands();
                    ctx.messages().send(player, "auth.logged-out");
                    if (ctx.settings().loginUi() == Settings.UiMode.DIALOG
                            && (!ctx.settings().fallbackForLegacyClients() || ctx.capabilities().supportsDialogs(player.getUniqueId()))) {
                        ctx.coordinator().openPlayDialog(player, session, null);
                    }
                    ctx.coordinator().sendPrompt(player, session);
                }, null));
        return Command.SINGLE_SUCCESS;
    }

    private int handleCaptcha(CommandContext<CommandSourceStack> c, String code) {
        Context ctx = readyContext(c.getSource().getSender());
        if (ctx == null) return Command.SINGLE_SUCCESS;
        Player player = requirePlayer(ctx, c);
        if (player == null) return Command.SINGLE_SUCCESS;
        PlayerSession session = ctx.sessionManager().getSession(player.getUniqueId());
        if (session == null || session.isAuthenticated()) {
            ctx.messages().send(player, "captcha.none-pending");
            return Command.SINGLE_SUCCESS;
        }
        if (ctx.captchaManager().getPending(session.nameLower()) == null) {
            ctx.messages().send(player, "captcha.none-pending");
            return Command.SINGLE_SUCCESS;
        }
        if (!ctx.captchaManager().verify(session.nameLower(), code)) {
            ctx.messages().send(player, "captcha.invalid");
            return Command.SINGLE_SUCCESS;
        }
        ctx.messages().send(player, "captcha.solved");
        ctx.coordinator().sendPrompt(player, session);
        return Command.SINGLE_SUCCESS;
    }

    private int handleChangePassword(CommandContext<CommandSourceStack> c, String oldPw, String newPw) {
        Context ctx = readyContext(c.getSource().getSender());
        if (ctx == null) return Command.SINGLE_SUCCESS;
        Player player = requirePlayer(ctx, c);
        if (player == null) return Command.SINGLE_SUCCESS;
        PlayerSession session = ctx.sessionManager().getSession(player.getUniqueId());
        if (session == null || (!session.isAuthenticated() && session.state() != AuthState.AWAITING_FORCED_PW_CHANGE)) {
            ctx.messages().send(player, "auth.not-logged-in");
            return Command.SINGLE_SUCCESS;
        }
        ctx.authService().changePassword(player.getName(), oldPw.toCharArray(), newPw.toCharArray(), session.ip(), player.getName(), false)
                .whenComplete((res, ex) -> ctx.scheduler().runForEntity(player, () -> {
                    if (ex != null) {
                        ctx.messages().send(player, "general.internal-error");
                        return;
                    }
                    switch (res.status()) {
                        case SUCCESS -> {
                            ctx.messages().send(player, "auth.password-changed");
                            if (session.state() == AuthState.AWAITING_FORCED_PW_CHANGE) {
                                ctx.accounts().findByNameLower(session.nameLower()).whenComplete((opt, ex2) ->
                                        ctx.scheduler().runForEntity(player, () -> {
                                            Account acc = opt != null ? opt.orElse(session.account()) : session.account();
                                            if (acc != null) {
                                                ctx.authService().recordSuccessfulSession(acc, player.getName(), session.ip());
                                            }
                                            ctx.coordinator().completePlayAuth(player, session, acc, "auth.login-success");
                                        }, null));
                            }
                        }
                        case INVALID_CREDENTIALS -> ctx.messages().send(player, "auth.wrong-password");
                        case PASSWORD_POLICY_VIOLATION -> player.sendMessage(
                                ctx.messages().component("prefix").append(ctx.coordinator().policyComponent(res.policyViolation())));
                        case RATE_LIMITED -> ctx.messages().send(player, "general.rate-limited",
                                Map.of("seconds", String.valueOf(res.retryAfterSeconds())));
                        case HASHING_BUSY -> ctx.messages().send(player, "general.hashing-busy");
                        default -> ctx.messages().send(player, "general.internal-error");
                    }
                }, null));
        return Command.SINGLE_SUCCESS;
    }

    private int handleUnregister(CommandContext<CommandSourceStack> c, String password) {
        Context ctx = readyContext(c.getSource().getSender());
        if (ctx == null) return Command.SINGLE_SUCCESS;
        PlayerSession session = requireAuthenticated(ctx, c);
        if (session == null) return Command.SINGLE_SUCCESS;
        Player player = (Player) c.getSource().getSender();
        ctx.authService().unregister(player.getName(), password.toCharArray(), session.ip(), player.getName())
                .whenComplete((res, ex) -> ctx.scheduler().runForEntity(player, () -> {
                    if (ex != null) {
                        ctx.messages().send(player, "general.internal-error");
                        return;
                    }
                    switch (res.status()) {
                        case SUCCESS -> {
                            ctx.sessionManager().removePlayerSession(player.getUniqueId());
                            player.kick(ctx.messages().component("auth.unregistered"));
                        }
                        case INVALID_CREDENTIALS -> ctx.messages().send(player, "auth.wrong-password");
                        case RATE_LIMITED -> ctx.messages().send(player, "general.rate-limited",
                                Map.of("seconds", String.valueOf(res.retryAfterSeconds())));
                        case HASHING_BUSY -> ctx.messages().send(player, "general.hashing-busy");
                        default -> ctx.messages().send(player, "general.internal-error");
                    }
                }, null));
        return Command.SINGLE_SUCCESS;
    }

    private int handle2faSetup(CommandContext<CommandSourceStack> c) {
        Context ctx = readyContext(c.getSource().getSender());
        if (ctx == null) return Command.SINGLE_SUCCESS;
        PlayerSession session = requireAuthenticated(ctx, c);
        if (session == null) return Command.SINGLE_SUCCESS;
        Player player = (Player) c.getSource().getSender();
        Messages msg = ctx.messages();
        ctx.authService().beginTotpSetup(player.getName()).whenComplete((data, ex) ->
                ctx.scheduler().runForEntity(player, () -> {
                    if (ex != null) {
                        msg.send(player, "general.internal-error");
                        return;
                    }
                    if (data.status() == AuthService.Status.TOTP_ALREADY_ENABLED) {
                        msg.send(player, "totp.already-enabled");
                        return;
                    }
                    if (data.status() != AuthService.Status.SUCCESS || data.base32Secret() == null || data.otpauthUri() == null) {
                        msg.send(player, "general.internal-error");
                        return;
                    }
                    ctx.sessionManager().putPendingTotpSetup(
                            player.getUniqueId(), data.base32Secret(), System.currentTimeMillis() + 5 * 60_000L);
                    msg.send(player, "totp.setup-header");
                    player.sendMessage(msg.component("totp.setup-secret", Map.of("secret", data.base32Secret()))
                            .clickEvent(ClickEvent.copyToClipboard(data.base32Secret())));
                    player.sendMessage(msg.component("totp.setup-uri", Map.of("uri", data.otpauthUri()))
                            .clickEvent(ClickEvent.copyToClipboard(data.otpauthUri())));
                    msg.send(player, "totp.setup-confirm");
                }, null));
        return Command.SINGLE_SUCCESS;
    }

    private int handle2faConfirm(CommandContext<CommandSourceStack> c, String code) {
        Context ctx = readyContext(c.getSource().getSender());
        if (ctx == null) return Command.SINGLE_SUCCESS;
        PlayerSession session = requireAuthenticated(ctx, c);
        if (session == null) return Command.SINGLE_SUCCESS;
        Player player = (Player) c.getSource().getSender();
        Messages msg = ctx.messages();
        var pending = ctx.sessionManager().consumePendingTotpSetup(player.getUniqueId(), System.currentTimeMillis());
        if (pending == null) {
            msg.send(player, "totp.no-pending-setup");
            return Command.SINGLE_SUCCESS;
        }
        ctx.authService().confirmTotpSetup(player.getName(), pending.base32Secret(), code, player.getName())
                .whenComplete((res, ex) -> ctx.scheduler().runForEntity(player, () -> {
                    if (ex != null) {
                        msg.send(player, "general.internal-error");
                        return;
                    }
                    if (res.status() != AuthService.Status.SUCCESS) {
                        ctx.sessionManager().putPendingTotpSetup(
                                player.getUniqueId(), pending.base32Secret(), pending.expiresAt());
                        msg.send(player, "totp.invalid-code");
                        return;
                    }
                    msg.send(player, "totp.enabled");
                    for (String backup : res.backupCodes()) {
                        Component line = msg.component("totp.backup-code-line", Map.of("code", backup))
                                .clickEvent(ClickEvent.copyToClipboard(backup));
                        player.sendMessage(line);
                    }
                }, null));
        return Command.SINGLE_SUCCESS;
    }

    private int handle2faDisable(CommandContext<CommandSourceStack> c, String code) {
        Context ctx = readyContext(c.getSource().getSender());
        if (ctx == null) return Command.SINGLE_SUCCESS;
        PlayerSession session = requireAuthenticated(ctx, c);
        if (session == null) return Command.SINGLE_SUCCESS;
        Player player = (Player) c.getSource().getSender();
        ctx.authService().disableTotp(player.getName(), code, session.ip(), player.getName()).whenComplete((res, ex) ->
                ctx.scheduler().runForEntity(player, () -> {
                    if (ex != null) {
                        ctx.messages().send(player, "general.internal-error");
                        return;
                    }
                    switch (res.status()) {
                        case SUCCESS -> ctx.messages().send(player, "totp.disabled");
                        case TOTP_NOT_ENABLED -> ctx.messages().send(player, "totp.not-enabled");
                        case INVALID_CODE -> ctx.messages().send(player, "totp.invalid-code");
                        case TOTP_DECRYPT_ERROR -> ctx.messages().send(player, "totp.decrypt-error");
                        case RATE_LIMITED -> ctx.messages().send(player, "general.rate-limited",
                                Map.of("seconds", String.valueOf(res.retryAfterSeconds())));
                        default -> ctx.messages().send(player, "general.internal-error");
                    }
                }, null));
        return Command.SINGLE_SUCCESS;
    }

    private int handle2faVerify(CommandContext<CommandSourceStack> c, String code) {
        Context ctx = readyContext(c.getSource().getSender());
        if (ctx == null) return Command.SINGLE_SUCCESS;
        Player player = requirePlayer(ctx, c);
        if (player == null) return Command.SINGLE_SUCCESS;
        PlayerSession session = ctx.sessionManager().getSession(player.getUniqueId());
        if (session == null) {
            ctx.messages().send(player, "general.internal-error");
            return Command.SINGLE_SUCCESS;
        }
        ctx.coordinator().submitPlayTotp(player, session, code, false);
        return Command.SINGLE_SUCCESS;
    }

    private boolean ensurePremiumSupported(Context ctx, Player player) {
        if (Bukkit.getServer().getOnlineMode()) {
            ctx.messages().send(player, "premium.already-online-mode");
            return false;
        }
        if (ctx.settings().proxyEnabled() || ctx.isStandalonePremiumActive()) {
            return true;
        }
        String key = !ctx.settings().proxyEnabled() && !ctx.settings().standalonePremiumEnabled()
                ? "premium.not-enabled" : "premium.requires-proxy";
        ctx.messages().send(player, key);
        return false;
    }

    private int handlePremium(CommandContext<CommandSourceStack> c) {
        Context ctx = readyContext(c.getSource().getSender());
        if (ctx == null) return Command.SINGLE_SUCCESS;
        PlayerSession session = requireAuthenticated(ctx, c);
        if (session == null) return Command.SINGLE_SUCCESS;
        Player player = (Player) c.getSource().getSender();
        if (!ensurePremiumSupported(ctx, player)) {
            return Command.SINGLE_SUCCESS;
        }
        ctx.authService().requestPremium(player.getName(), player.getName()).whenComplete((res, ex) ->
                ctx.scheduler().runForEntity(player, () -> {
                    if (ex != null) {
                        ctx.messages().send(player, "general.internal-error");
                        return;
                    }
                    switch (res.status()) {
                        case SUCCESS -> ctx.messages().send(player, "premium.pending-created");
                        case ALREADY_PREMIUM -> ctx.messages().send(player, "premium.already-premium");
                        default -> ctx.messages().send(player, "general.internal-error");
                    }
                }, null));
        return Command.SINGLE_SUCCESS;
    }

    private int handleCracked(CommandContext<CommandSourceStack> c, @Nullable String passwordArg) {
        Context ctx = readyContext(c.getSource().getSender());
        if (ctx == null) return Command.SINGLE_SUCCESS;
        PlayerSession session = requireAuthenticated(ctx, c);
        if (session == null) return Command.SINGLE_SUCCESS;
        Player player = (Player) c.getSource().getSender();
        if (!ensurePremiumSupported(ctx, player)) {
            return Command.SINGLE_SUCCESS;
        }
        if (passwordArg != null) {
            ctx.authService().setCrackedWithInitialPassword(
                    player.getName(), passwordArg.toCharArray(), session.ip(), player.getName())
                    .whenComplete((pwRes, pwEx) -> ctx.scheduler().runForEntity(player, () -> {
                        if (pwEx != null || pwRes == null) {
                            ctx.messages().send(player, "general.internal-error");
                            return;
                        }
                        switch (pwRes.status()) {
                            case SUCCESS -> {
                                ctx.accounts().findByNameLower(session.nameLower()).whenComplete((opt, ex2) -> {
                                    if (opt != null) opt.ifPresent(session::setAccount);
                                });
                                ctx.messages().send(player, "premium.switched-cracked");
                            }
                            case PASSWORD_ALREADY_SET -> ctx.messages().send(player, "premium.password-already-set");
                            case PASSWORD_POLICY_VIOLATION -> player.sendMessage(
                                    ctx.messages().component("prefix").append(ctx.coordinator().policyComponent(pwRes.policyViolation())));
                            case HASHING_BUSY -> ctx.messages().send(player, "general.hashing-busy");
                            default -> ctx.messages().send(player, "general.internal-error");
                        }
                    }, null));
            return Command.SINGLE_SUCCESS;
        }
        finishCrackedSwitch(ctx, player, session);
        return Command.SINGLE_SUCCESS;
    }

    private void finishCrackedSwitch(Context ctx, Player player, PlayerSession session) {
        ctx.authService().setCracked(player.getName(), player.getName()).whenComplete((res, ex) ->
                ctx.scheduler().runForEntity(player, () -> {
                    if (ex != null) {
                        ctx.messages().send(player, "general.internal-error");
                        return;
                    }
                    switch (res.status()) {
                        case SUCCESS -> {
                            ctx.accounts().findByNameLower(session.nameLower()).whenComplete((opt, ex2) -> {
                                if (opt != null) opt.ifPresent(session::setAccount);
                            });
                            ctx.messages().send(player, "premium.switched-cracked");
                        }
                        case PASSWORD_REQUIRED_FOR_CRACKED -> ctx.messages().send(player, "premium.password-required-for-cracked");
                        default -> ctx.messages().send(player, "general.internal-error");
                    }
                }, null));
    }
}

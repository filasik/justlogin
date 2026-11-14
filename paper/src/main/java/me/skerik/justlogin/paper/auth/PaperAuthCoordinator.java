package me.skerik.justlogin.paper.auth;

import io.papermc.paper.connection.PlayerConfigurationConnection;
import java.util.Map;
import java.util.UUID;
import me.skerik.justlogin.api.AccountSnapshot;
import me.skerik.justlogin.api.event.PlayerAuthenticatedEvent;
import me.skerik.justlogin.api.event.PlayerRegisteredEvent;
import me.skerik.justlogin.core.crypto.ProxyTokenSigner;
import me.skerik.justlogin.core.model.Account;
import me.skerik.justlogin.core.security.PasswordPolicy;
import me.skerik.justlogin.core.security.UsernameValidator;
import me.skerik.justlogin.core.service.AuthService;
import me.skerik.justlogin.paper.Context;
import me.skerik.justlogin.paper.JustLogin;
import me.skerik.justlogin.paper.auth.AuthSessionManager.AuthState;
import me.skerik.justlogin.paper.auth.AuthSessionManager.ConfigOutcome;
import me.skerik.justlogin.paper.auth.AuthSessionManager.ConfigPhase;
import me.skerik.justlogin.paper.auth.AuthSessionManager.PendingConfigAuth;
import me.skerik.justlogin.paper.auth.AuthSessionManager.PlayerSession;
import me.skerik.justlogin.paper.auth.CaptchaManager.Challenge;
import me.skerik.justlogin.paper.config.Messages;
import me.skerik.justlogin.paper.dialog.ClickData;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.title.Title;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.jspecify.annotations.Nullable;

/**
 * Coordinates both Configuration-phase Dialog auth and Play-phase command/dialog auth across shared
 * {@link AuthService} calls without ever blocking main or Netty threads.
 */
public final class PaperAuthCoordinator {

    private final Context ctx;

    public PaperAuthCoordinator(Context ctx) {
        this.ctx = ctx;
    }

    public void handleConfigDialogAction(PendingConfigAuth pending, ClickData.Action action, String arg1, String arg2) {
        if (!(pending.connection() instanceof PlayerConfigurationConnection conn)) return;
        Messages msg = ctx.messages();

        switch (action) {
            case CANCEL -> {
                conn.disconnect(msg.component("general.cancelled-kick"));
                ctx.sessionManager().finishConfigAuth(pending, ConfigOutcome.failed("cancelled"));
            }
            case REGISTER -> {
                if (pending.phase() != ConfigPhase.REGISTER) return;
                if (!arg1.equals(arg2)) {
                    reshowConfig(pending, msg.component("auth.password-mismatch"));
                    return;
                }
                if (!pending.tryBeginOp()) return;
                UUID gameUuid = pending.profileUuid() != null ? pending.profileUuid() : offlineUuid(pending.username());
                boolean floodgate = ctx.capabilities().isFloodgate(pending.profileUuid());
                ctx.authService().register(pending.username(), gameUuid, arg1.toCharArray(), pending.ip(), pending.username(), floodgate)
                        .whenComplete((res, ex) -> {
                            pending.endOp();
                            if (ex != null) {
                                ctx.logger().warning("Config register error for " + pending.username() + ": " + ex.getMessage());
                                reshowConfig(pending, msg.component("general.internal-error"));
                                return;
                            }
                            switch (res.status()) {
                                case SUCCESS -> {
                                    ctx.dialogUi().close(conn.getAudience());
                                    ctx.sessionManager().finishConfigAuth(pending, ConfigOutcome.ok(res.account()));
                                }
                                case ALREADY_REGISTERED -> {
                                    pending.setPhase(ConfigPhase.LOGIN);
                                    reshowConfig(pending, msg.component("auth.already-registered"));
                                }
                                case PASSWORD_POLICY_VIOLATION -> reshowConfig(pending, policyComponent(res.policyViolation()));
                                case TOO_MANY_ACCOUNTS_PER_IP -> reshowConfig(pending, msg.component("auth.too-many-accounts-ip"));
                                case RATE_LIMITED -> {
                                    conn.disconnect(msg.component("general.rate-limited",
                                            Map.of("seconds", String.valueOf(res.retryAfterSeconds()))));
                                    ctx.sessionManager().finishConfigAuth(pending, ConfigOutcome.failed("rate_limited"));
                                }
                                case HASHING_BUSY -> reshowConfig(pending, msg.component("general.hashing-busy"));
                                default -> reshowConfig(pending, msg.component("general.internal-error"));
                            }
                        });
            }
            case LOGIN -> {
                if (pending.phase() != ConfigPhase.LOGIN) return;
                if (!pending.tryBeginOp()) return;
                boolean floodgate = ctx.capabilities().isFloodgate(pending.profileUuid());
                ctx.authService().login(pending.username(), arg1.toCharArray(), pending.ip(), floodgate)
                        .whenComplete((res, ex) -> {
                            pending.endOp();
                            if (ex != null) {
                                ctx.logger().warning("Config login error for " + pending.username() + ": " + ex.getMessage());
                                reshowConfig(pending, msg.component("general.internal-error"));
                                return;
                            }
                            handleConfigPostPassword(pending, conn, res);
                        });
            }
            case TOTP -> {
                if (pending.phase() != ConfigPhase.TOTP) return;
                if (!pending.tryBeginOp()) return;
                ctx.authService().verifyTotp(pending.username(), arg1.trim(), pending.ip())
                        .whenComplete((res, ex) -> {
                            pending.endOp();
                            if (ex != null) {
                                ctx.logger().warning("Config 2FA error for " + pending.username() + ": " + ex.getMessage());
                                reshowConfig(pending, msg.component("general.internal-error"));
                                return;
                            }
                            handleConfigPostTotp(pending, conn, res);
                        });
            }
            case FORCE_PW -> {
                if (pending.phase() != ConfigPhase.FORCED_PW_CHANGE) return;
                if (!arg1.equals(arg2)) {
                    reshowConfig(pending, msg.component("auth.password-mismatch"));
                    return;
                }
                if (!pending.tryBeginOp()) return;
                ctx.authService().changePassword(pending.username(), null, arg1.toCharArray(), pending.ip(), pending.username(), true)
                        .whenComplete((res, ex) -> {
                            pending.endOp();
                            if (ex != null) {
                                ctx.logger().warning("Config forced-pw error for " + pending.username() + ": " + ex.getMessage());
                                reshowConfig(pending, msg.component("general.internal-error"));
                                return;
                            }
                            switch (res.status()) {
                                case SUCCESS -> ctx.accounts().findByNameLower(pending.nameLower())
                                        .whenComplete((opt, ex2) -> {
                                            Account updated = opt != null ? opt.orElse(pending.account()) : pending.account();
                                            if (updated != null) {
                                                ctx.authService().recordSuccessfulSession(updated, pending.username(), pending.ip());
                                                ctx.dialogUi().close(conn.getAudience());
                                                ctx.sessionManager().finishConfigAuth(pending, ConfigOutcome.ok(updated));
                                            } else {
                                                conn.disconnect(msg.component("general.internal-error"));
                                                ctx.sessionManager().finishConfigAuth(pending, ConfigOutcome.failed("error"));
                                            }
                                        });
                                case PASSWORD_POLICY_VIOLATION -> reshowConfig(pending, policyComponent(res.policyViolation()));
                                case HASHING_BUSY -> reshowConfig(pending, msg.component("general.hashing-busy"));
                                default -> reshowConfig(pending, msg.component("general.internal-error"));
                            }
                        });
            }
        }
    }

    private void handleConfigPostPassword(
            PendingConfigAuth pending, PlayerConfigurationConnection conn, AuthService.LoginResult res) {
        Messages msg = ctx.messages();
        switch (res.status()) {
            case SUCCESS -> {
                ctx.dialogUi().close(conn.getAudience());
                ctx.sessionManager().finishConfigAuth(pending, ConfigOutcome.ok(res.account()));
            }
            case NEEDS_2FA -> {
                pending.setAccount(res.account());
                pending.setPhase(ConfigPhase.TOTP);
                ctx.dialogUi().showTotpDialog(conn.getAudience(), pending.nonce(), null);
            }
            case NEEDS_PASSWORD_CHANGE -> {
                pending.setAccount(res.account());
                pending.setPhase(ConfigPhase.FORCED_PW_CHANGE);
                ctx.dialogUi().showForcePasswordChangeDialog(
                        conn.getAudience(), ctx.settings().core().minPasswordLength(), pending.nonce(), null);
            }
            case NOT_REGISTERED -> {
                pending.setPhase(ConfigPhase.REGISTER);
                reshowConfig(pending, msg.component("auth.not-registered"));
            }
            case INVALID_CREDENTIALS -> reshowConfig(pending, msg.component("auth.wrong-password"));
            case RATE_LIMITED -> {
                conn.disconnect(msg.component("general.rate-limited",
                        Map.of("seconds", String.valueOf(res.retryAfterSeconds()))));
                ctx.sessionManager().finishConfigAuth(pending, ConfigOutcome.failed("rate_limited"));
            }
            case HASHING_BUSY -> reshowConfig(pending, msg.component("general.hashing-busy"));
            default -> reshowConfig(pending, msg.component("general.internal-error"));
        }
    }

    private void handleConfigPostTotp(
            PendingConfigAuth pending, PlayerConfigurationConnection conn, AuthService.LoginResult res) {
        Messages msg = ctx.messages();
        switch (res.status()) {
            case SUCCESS -> {
                ctx.dialogUi().close(conn.getAudience());
                ctx.sessionManager().finishConfigAuth(pending, ConfigOutcome.ok(res.account()));
            }
            case NEEDS_PASSWORD_CHANGE -> {
                pending.setAccount(res.account());
                pending.setPhase(ConfigPhase.FORCED_PW_CHANGE);
                ctx.dialogUi().showForcePasswordChangeDialog(
                        conn.getAudience(), ctx.settings().core().minPasswordLength(), pending.nonce(), null);
            }
            case INVALID_CODE -> reshowConfig(pending, msg.component("totp.invalid-code"));
            case TOTP_DECRYPT_ERROR -> {
                ctx.logger().warning("Could not decrypt 2FA secret for " + pending.username()
                        + " (secrets.key rotated/mismatch). An admin can run /jl reset2fa " + pending.username());
                reshowConfig(pending, msg.component("totp.decrypt-error"));
            }
            case RATE_LIMITED -> {
                conn.disconnect(msg.component("general.rate-limited",
                        Map.of("seconds", String.valueOf(res.retryAfterSeconds()))));
                ctx.sessionManager().finishConfigAuth(pending, ConfigOutcome.failed("rate_limited"));
            }
            default -> reshowConfig(pending, msg.component("general.internal-error"));
        }
    }

    private void reshowConfig(PendingConfigAuth pending, @Nullable Component error) {
        if (!(pending.connection() instanceof PlayerConfigurationConnection conn)) return;
        if (pending.future().isDone()) return;
        switch (pending.phase()) {
            case REGISTER -> ctx.dialogUi().showRegisterDialog(
                    conn.getAudience(), pending.username(), ctx.settings().core().minPasswordLength(), pending.nonce(), error);
            case LOGIN -> ctx.dialogUi().showLoginDialog(conn.getAudience(), pending.username(), pending.nonce(), error);
            case TOTP -> ctx.dialogUi().showTotpDialog(conn.getAudience(), pending.nonce(), error);
            case FORCED_PW_CHANGE -> ctx.dialogUi().showForcePasswordChangeDialog(
                    conn.getAudience(), ctx.settings().core().minPasswordLength(), pending.nonce(), error);
        }
    }

    public void handlePlayDialogAction(Player player, PlayerSession session, ClickData.Action action, String arg1, String arg2) {
        switch (action) {
            case CANCEL -> ctx.scheduler().runForEntity(player,
                    () -> player.kick(ctx.messages().component("general.cancelled-kick")), null);
            case REGISTER -> submitPlayRegister(player, session, arg1, arg2, true);
            case LOGIN -> submitPlayLogin(player, session, arg1, true);
            case TOTP -> submitPlayTotp(player, session, arg1, true);
            case FORCE_PW -> {
                if (session.state() != AuthState.AWAITING_FORCED_PW_CHANGE) return;
                if (!arg1.equals(arg2)) {
                    openPlayDialog(player, session, ctx.messages().component("auth.password-mismatch"));
                    return;
                }
                if (!session.tryBeginOp()) return;
                ctx.authService().changePassword(player.getName(), null, arg1.toCharArray(), session.ip(), player.getName(), true)
                        .whenComplete((res, ex) -> {
                            session.endOp();
                            ctx.scheduler().runForEntity(player, () -> {
                                if (ex != null) {
                                    openPlayDialog(player, session, ctx.messages().component("general.internal-error"));
                                    return;
                                }
                                if (res.status() == AuthService.Status.SUCCESS) {
                                    ctx.dialogUi().close(player);
                                    ctx.accounts().findByNameLower(session.nameLower()).whenComplete((opt, ex2) ->
                                            ctx.scheduler().runForEntity(player, () -> {
                                                Account acc = opt != null ? opt.orElse(session.account()) : session.account();
                                                if (acc != null) {
                                                    ctx.authService().recordSuccessfulSession(acc, player.getName(), session.ip());
                                                }
                                                completePlayAuth(player, session, acc, "auth.password-changed");
                                            }, null));
                                } else if (res.status() == AuthService.Status.PASSWORD_POLICY_VIOLATION) {
                                    openPlayDialog(player, session, policyComponent(res.policyViolation()));
                                } else {
                                    openPlayDialog(player, session, ctx.messages().component("general.internal-error"));
                                }
                            }, null);
                        });
            }
        }
    }

    public void submitPlayRegister(Player player, PlayerSession session, String pw, String confirm, boolean fromDialog) {
        Messages msg = ctx.messages();
        if (session.isAuthenticated()) {
            msg.send(player, "auth.already-logged-in");
            return;
        }
        if (session.state() == AuthState.AWAITING_LOGIN || session.state() == AuthState.AWAITING_2FA) {
            msg.send(player, "auth.already-registered");
            return;
        }
        if (!pw.equals(confirm)) {
            if (fromDialog) openPlayDialog(player, session, msg.component("auth.password-mismatch"));
            else msg.send(player, "auth.password-mismatch");
            return;
        }
        Challenge pendingCaptcha = ctx.captchaManager().getPending(session.nameLower());
        if (pendingCaptcha != null) {
            msg.send(player, "captcha.required", Map.of("code", pendingCaptcha.code()));
            return;
        }
        if (!session.tryBeginOp()) return;
        boolean floodgate = ctx.capabilities().isFloodgate(player.getUniqueId());
        ctx.authService().register(player.getName(), player.getUniqueId(), pw.toCharArray(), session.ip(), player.getName(), floodgate)
                .whenComplete((res, ex) -> {
                    session.endOp();
                    ctx.scheduler().runForEntity(player, () -> {
                        if (ex != null) {
                            msg.send(player, "general.internal-error");
                            return;
                        }
                        switch (res.status()) {
                            case SUCCESS -> {
                                if (fromDialog) ctx.dialogUi().close(player);
                                completePlayAuth(player, session, res.account(), "auth.register-success",
                                        PlayerAuthenticatedEvent.AuthMethod.PASSWORD, true);
                            }
                            case ALREADY_REGISTERED -> {
                                session.setState(AuthState.AWAITING_LOGIN);
                                if (fromDialog) openPlayDialog(player, session, msg.component("auth.already-registered"));
                                else msg.send(player, "auth.already-registered");
                            }
                            case PASSWORD_POLICY_VIOLATION -> {
                                Component err = policyComponent(res.policyViolation());
                                if (fromDialog) openPlayDialog(player, session, err);
                                else player.sendMessage(msg.component("prefix").append(err));
                            }
                            case TOO_MANY_ACCOUNTS_PER_IP -> {
                                if (fromDialog) openPlayDialog(player, session, msg.component("auth.too-many-accounts-ip"));
                                else msg.send(player, "auth.too-many-accounts-ip");
                            }
                            case RATE_LIMITED -> player.kick(msg.component("general.rate-limited",
                                    Map.of("seconds", String.valueOf(res.retryAfterSeconds()))));
                            case HASHING_BUSY -> msg.send(player, "general.hashing-busy");
                            default -> msg.send(player, "general.internal-error");
                        }
                    }, null);
                });
    }

    public void submitPlayLogin(Player player, PlayerSession session, String pw, boolean fromDialog) {
        Messages msg = ctx.messages();
        if (session.isAuthenticated()) {
            msg.send(player, "auth.already-logged-in");
            return;
        }
        if (session.state() == AuthState.AWAITING_2FA) {
            msg.send(player, "auth.prompt-2fa");
            return;
        }
        Challenge pendingCaptcha = ctx.captchaManager().getPending(session.nameLower());
        if (pendingCaptcha != null) {
            msg.send(player, "captcha.required", Map.of("code", pendingCaptcha.code()));
            return;
        }
        if (!session.tryBeginOp()) return;
        boolean floodgate = ctx.capabilities().isFloodgate(player.getUniqueId());
        ctx.authService().login(player.getName(), pw.toCharArray(), session.ip(), floodgate)
                .whenComplete((res, ex) -> {
                    session.endOp();
                    ctx.scheduler().runForEntity(player, () -> {
                        if (ex != null) {
                            msg.send(player, "general.internal-error");
                            return;
                        }
                        switch (res.status()) {
                            case SUCCESS -> {
                                if (fromDialog) ctx.dialogUi().close(player);
                                completePlayAuth(player, session, res.account(), "auth.login-success",
                                        PlayerAuthenticatedEvent.AuthMethod.PASSWORD, false);
                            }
                            case NEEDS_2FA -> {
                                session.setAccount(res.account());
                                session.setState(AuthState.AWAITING_2FA);
                                if (fromDialog) openPlayDialog(player, session, null);
                                else sendPrompt(player, session);
                            }
                            case NEEDS_PASSWORD_CHANGE -> {
                                session.setAccount(res.account());
                                session.setState(AuthState.AWAITING_FORCED_PW_CHANGE);
                                if (fromDialog) openPlayDialog(player, session, null);
                                else sendPrompt(player, session);
                            }
                            case NOT_REGISTERED -> {
                                session.setState(AuthState.AWAITING_REGISTER);
                                if (fromDialog) openPlayDialog(player, session, msg.component("auth.not-registered"));
                                else msg.send(player, "auth.not-registered");
                            }
                            case INVALID_CREDENTIALS -> {
                                Challenge triggered = ctx.captchaManager().recordFailure(
                                        session.nameLower(),
                                        ctx.settings().captchaEnabled(),
                                        ctx.settings().captchaTriggerAfterFailures(),
                                        ctx.settings().captchaLength(),
                                        ctx.settings().captchaExpireSeconds());
                                if (triggered != null) {
                                    msg.send(player, "captcha.required", Map.of("code", triggered.code()));
                                } else if (fromDialog) {
                                    openPlayDialog(player, session, msg.component("auth.wrong-password"));
                                } else {
                                    msg.send(player, "auth.wrong-password");
                                }
                            }
                            case RATE_LIMITED -> player.kick(msg.component("general.rate-limited",
                                    Map.of("seconds", String.valueOf(res.retryAfterSeconds()))));
                            case HASHING_BUSY -> msg.send(player, "general.hashing-busy");
                            default -> msg.send(player, "general.internal-error");
                        }
                    }, null);
                });
    }

    public void submitPlayTotp(Player player, PlayerSession session, String code, boolean fromDialog) {
        Messages msg = ctx.messages();
        if (session.state() != AuthState.AWAITING_2FA) {
            msg.send(player, "auth.must-auth-first");
            return;
        }
        if (!session.tryBeginOp()) return;
        ctx.authService().verifyTotp(player.getName(), code.trim(), session.ip())
                .whenComplete((res, ex) -> {
                    session.endOp();
                    ctx.scheduler().runForEntity(player, () -> {
                        if (ex != null) {
                            msg.send(player, "general.internal-error");
                            return;
                        }
                        switch (res.status()) {
                            case SUCCESS -> {
                                if (fromDialog) ctx.dialogUi().close(player);
                                completePlayAuth(player, session, res.account(), "auth.login-success",
                                        PlayerAuthenticatedEvent.AuthMethod.PASSWORD_2FA, false);
                            }
                            case NEEDS_PASSWORD_CHANGE -> {
                                session.setAccount(res.account());
                                session.setState(AuthState.AWAITING_FORCED_PW_CHANGE);
                                if (fromDialog) openPlayDialog(player, session, null);
                                else sendPrompt(player, session);
                            }
                            case INVALID_CODE -> {
                                if (fromDialog) openPlayDialog(player, session, msg.component("totp.invalid-code"));
                                else msg.send(player, "totp.invalid-code");
                            }
                            case TOTP_DECRYPT_ERROR -> {
                                ctx.logger().warning("Could not decrypt 2FA secret for " + player.getName()
                                        + " (secrets.key rotated/mismatch). An admin can run /jl reset2fa " + player.getName());
                                if (fromDialog) openPlayDialog(player, session, msg.component("totp.decrypt-error"));
                                else msg.send(player, "totp.decrypt-error");
                            }
                            case RATE_LIMITED -> player.kick(msg.component("general.rate-limited",
                                    Map.of("seconds", String.valueOf(res.retryAfterSeconds()))));
                            default -> msg.send(player, "general.internal-error");
                        }
                    }, null);
                });
    }

    public void completePlayAuth(Player player, PlayerSession session, @Nullable Account acc, String messageKey) {
        completePlayAuth(player, session, acc, messageKey, PlayerAuthenticatedEvent.AuthMethod.PASSWORD, false);
    }

    public void completePlayAuth(
            Player player,
            PlayerSession session,
            @Nullable Account acc,
            String messageKey,
            PlayerAuthenticatedEvent.AuthMethod method,
            boolean newlyRegistered
    ) {
        ctx.captchaManager().clear(session.nameLower());
        session.setAccount(acc);
        session.setState(AuthState.AUTHENTICATED);
        session.setReminderCancel(null);
        player.clearTitle();
        player.updateCommands();
        ctx.messages().send(player, messageKey, Map.of("player", player.getName()));
        if (acc != null) {
            ctx.notifyProxyState(player, ProxyTokenSigner.MessageType.BACKEND_AUTH_OK, acc.id());
        }
        AccountSnapshot snap = acc != null ? AccountSnapshot.fromAccount(acc) : null;
        if (newlyRegistered) {
            Bukkit.getPluginManager().callEvent(new PlayerRegisteredEvent(player, snap));
        }
        Bukkit.getPluginManager().callEvent(new PlayerAuthenticatedEvent(player, snap, method));
        if (ctx.plugin() instanceof JustLogin jl) {
            jl.notifyUpdateIfAvailable(player);
            jl.notifyMigrationsIfAvailable(player);
        }
    }

    public void openPlayDialog(Player player, PlayerSession session, @Nullable Component error) {
        String nonce = ctx.sessionManager().newNonce();
        ctx.sessionManager().bindPlayDialogNonce(player.getUniqueId(), nonce);
        switch (session.state()) {
            case AWAITING_REGISTER -> ctx.dialogUi().showRegisterDialog(
                    player, player.getName(), ctx.settings().core().minPasswordLength(), nonce, error);
            case AWAITING_LOGIN -> ctx.dialogUi().showLoginDialog(player, player.getName(), nonce, error);
            case AWAITING_2FA -> ctx.dialogUi().showTotpDialog(player, nonce, error);
            case AWAITING_FORCED_PW_CHANGE -> ctx.dialogUi().showForcePasswordChangeDialog(
                    player, ctx.settings().core().minPasswordLength(), nonce, error);
            default -> {}
        }
    }

    public void sendPrompt(Player player, PlayerSession session) {
        Messages msg = ctx.messages();
        switch (session.state()) {
            case AWAITING_REGISTER -> {
                msg.send(player, "auth.prompt-register");
                if (ctx.settings().titleReminder()) {
                    player.showTitle(Title.title(msg.component("auth.title-register"), msg.component("auth.subtitle-register")));
                }
            }
            case AWAITING_LOGIN -> {
                msg.send(player, "auth.prompt-login");
                if (ctx.settings().titleReminder()) {
                    player.showTitle(Title.title(msg.component("auth.title-login"), msg.component("auth.subtitle-login")));
                }
            }
            case AWAITING_2FA -> {
                msg.send(player, "auth.prompt-2fa");
                if (ctx.settings().titleReminder()) {
                    player.showTitle(Title.title(msg.component("auth.title-2fa"), msg.component("auth.subtitle-2fa")));
                }
            }
            case AWAITING_FORCED_PW_CHANGE -> msg.send(player, "auth.prompt-forced-pw");
            default -> {}
        }
    }

    public Component policyComponent(PasswordPolicy.@Nullable Violation v) {
        if (v == null) return ctx.messages().component("general.internal-error");
        return switch (v) {
            case BLANK -> ctx.messages().component("policy.blank");
            case TOO_SHORT -> ctx.messages().component("policy.too-short",
                    Map.of("min", String.valueOf(ctx.settings().core().minPasswordLength())));
            case TOO_LONG -> ctx.messages().component("policy.too-long",
                    Map.of("max", String.valueOf(ctx.settings().core().maxPasswordLength())));
            case SAME_AS_USERNAME -> ctx.messages().component("policy.same-as-username");
            case COMMON_PASSWORD -> ctx.messages().component("policy.common-password");
        };
    }

    public static UUID offlineUuid(String username) {
        return UUID.nameUUIDFromBytes(("OfflinePlayer:" + username).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}

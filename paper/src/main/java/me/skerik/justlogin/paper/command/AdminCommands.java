package me.skerik.justlogin.paper.command;

import com.mojang.brigadier.Command;
import com.mojang.brigadier.arguments.BoolArgumentType;
import com.mojang.brigadier.arguments.IntegerArgumentType;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;
import io.papermc.paper.command.brigadier.CommandSourceStack;
import io.papermc.paper.command.brigadier.Commands;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import me.skerik.justlogin.core.importer.MigrationScanner;
import me.skerik.justlogin.core.importer.MigrationScanner.DetectedSource;
import me.skerik.justlogin.core.importer.MigrationScanner.SourceType;
import me.skerik.justlogin.core.model.Account;
import me.skerik.justlogin.core.model.AuditEntry;
import me.skerik.justlogin.core.security.UsernameValidator;
import me.skerik.justlogin.core.service.AuthService;
import me.skerik.justlogin.core.service.MojangSkinClient;
import me.skerik.justlogin.editor.BytebinClient;
import me.skerik.justlogin.editor.EditorModels;
import me.skerik.justlogin.paper.Context;
import me.skerik.justlogin.paper.JustLogin;
import me.skerik.justlogin.paper.auth.AuthSessionManager.AuthState;
import me.skerik.justlogin.paper.auth.AuthSessionManager.PendingConfigAuth;
import me.skerik.justlogin.paper.auth.AuthSessionManager.PlayerSession;
import me.skerik.justlogin.paper.dialog.ClickData;
import net.kyori.adventure.text.event.ClickEvent;
import org.bukkit.Bukkit;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.entity.Player;
import org.jspecify.annotations.Nullable;

/** Administration, importer, web editor, and optional debug-click commands under {@code /justlogin}. */
public final class AdminCommands {

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final JustLogin plugin;

    public AdminCommands(JustLogin plugin) {
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
        var root = Commands.literal("justlogin")
                .requires(s -> hasAnyPerm(s.getSender()))
                .executes(c -> help(c.getSource().getSender(), null))
                .then(buildHelpNode("help"))
                .then(buildHelpNode("?"))
                .then(Commands.literal("reload")
                        .requires(s -> hasAdminSub(s.getSender(), "reload"))
                        .executes(this::reload))
                .then(Commands.literal("status")
                        .requires(s -> hasAdminSub(s.getSender(), "status"))
                        .executes(c -> helpDetail(c.getSource().getSender(), "jl_status"))
                        .then(Commands.argument("player", StringArgumentType.word())
                                .suggests(this::suggestAccounts)
                                .executes(c -> status(c, StringArgumentType.getString(c, "player")))))
                .then(Commands.literal("audit")
                        .requires(s -> hasAdminSub(s.getSender(), "audit"))
                        .executes(c -> audit(c, 15))
                        .then(Commands.argument("limit", IntegerArgumentType.integer(1, 100))
                                .suggests(this::suggestAuditLimits)
                                .executes(c -> audit(c, IntegerArgumentType.getInteger(c, "limit")))))
                .then(Commands.literal("unregister")
                        .requires(s -> hasAdminSub(s.getSender(), "unregister"))
                        .executes(c -> helpDetail(c.getSource().getSender(), "jl_unregister"))
                        .then(Commands.argument("player", StringArgumentType.word())
                                .suggests(this::suggestAccounts)
                                .executes(c -> adminUnregister(c, StringArgumentType.getString(c, "player")))))
                .then(buildChangePasswordNode("changepassword"))
                .then(buildChangePasswordNode("changepass"))
                .then(buildForcePwNode("forcechangepassword"))
                .then(buildForcePwNode("forcepw"))
                .then(Commands.literal("reset2fa")
                        .requires(s -> hasAdminSub(s.getSender(), "reset2fa"))
                        .executes(c -> helpDetail(c.getSource().getSender(), "jl_reset2fa"))
                        .then(Commands.argument("player", StringArgumentType.word())
                                .suggests(this::suggestAccounts)
                                .executes(c -> adminReset2fa(c, StringArgumentType.getString(c, "player")))))
                .then(Commands.literal("setpremium")
                        .requires(s -> hasAdminSub(s.getSender(), "setpremium"))
                        .executes(c -> helpDetail(c.getSource().getSender(), "jl_setpremium"))
                        .then(Commands.argument("player", StringArgumentType.word())
                                .suggests(this::suggestAccounts)
                                .executes(c -> helpDetail(c.getSource().getSender(), "jl_setpremium"))
                                .then(Commands.argument("premium", BoolArgumentType.bool())
                                        .executes(c -> adminSetPremium(
                                                c,
                                                StringArgumentType.getString(c, "player"),
                                                BoolArgumentType.getBool(c, "premium"))))))
                .then(Commands.literal("rename")
                        .requires(s -> hasAdminSub(s.getSender(), "rename"))
                        .executes(c -> helpDetail(c.getSource().getSender(), "jl_rename"))
                        .then(Commands.argument("oldPlayer", StringArgumentType.word())
                                .suggests(this::suggestAccounts)
                                .executes(c -> helpDetail(c.getSource().getSender(), "jl_rename"))
                                .then(Commands.argument("newPlayer", StringArgumentType.word())
                                        .suggests(this::suggestRenameNew)
                                        .executes(c -> adminRename(
                                                c,
                                                StringArgumentType.getString(c, "oldPlayer"),
                                                StringArgumentType.getString(c, "newPlayer"))))))
                .then(Commands.literal("merge")
                        .requires(s -> hasAdminSub(s.getSender(), "merge"))
                        .executes(c -> helpDetail(c.getSource().getSender(), "jl_merge"))
                        .then(Commands.argument("source", StringArgumentType.word())
                                .suggests(this::suggestAccounts)
                                .executes(c -> helpDetail(c.getSource().getSender(), "jl_merge"))
                                .then(Commands.argument("target", StringArgumentType.word())
                                        .suggests(this::suggestMergeTarget)
                                        .executes(c -> adminMerge(
                                                c,
                                                StringArgumentType.getString(c, "source"),
                                                StringArgumentType.getString(c, "target"))))))
                .then(Commands.literal("gui")
                        .requires(s -> hasAdminSub(s.getSender(), "gui"))
                        .executes(c -> adminGui(c, 1))
                        .then(Commands.argument("page", IntegerArgumentType.integer(1))
                                .suggests(this::suggestPages)
                                .executes(c -> adminGui(c, IntegerArgumentType.getInteger(c, "page")))))
                .then(Commands.literal("import")
                        .requires(s -> hasAdminSub(s.getSender(), "import"))
                        .executes(c -> scanAndShowMigrations(c.getSource().getSender()))
                        .then(flagsArg(c -> runAutoImportAll(c.getSource().getSender(), parseFlags(c))))
                        .then(Commands.literal("auto")
                                .executes(c -> runAutoImportAll(c.getSource().getSender(), ImportFlags.NONE))
                                .then(flagsArg(c -> runAutoImportAll(c.getSource().getSender(), parseFlags(c)))))
                        .then(buildImportNode("authme", SourceType.AUTHME, "authme", "plugins/AuthMe/authme.db"))
                        .then(buildImportNode("fastlogin", SourceType.FASTLOGIN, "premium", "plugins/FastLogin/FastLogin.db"))
                        .then(buildImportNode("librelogin", SourceType.LIBRELOGIN, "librepremium_data", "plugins/LibreLogin/user-data.db"))
                        .then(buildImportNode("loginsecurity", SourceType.LOGINSECURITY, "ls_players", "plugins/LoginSecurity/LoginSecurity.db"))
                        .then(buildImportNode("nlogin", SourceType.NLOGIN, "nlogin", "plugins/nLogin/nlogin.db"))
                        .then(buildImportNode("openlogin", SourceType.OPENLOGIN, "openlogin", "plugins/OpeNLogin/accounts.db"))
                        .then(buildImportNode("limboauth", SourceType.LIMBOAUTH, "AUTH", "plugins/LimboAuth/limboauth.db"))
                        .then(buildImportNode("authy", SourceType.AUTHY, "players", "plugins/Authy/data.db")))
                .then(Commands.literal("editor")
                        .requires(s -> hasEditorPerm(s.getSender()))
                        .executes(c -> editorCreate(c, 1))
                        .then(Commands.argument("page", IntegerArgumentType.integer(1))
                                .suggests(this::suggestPages)
                                .executes(c -> editorCreate(c, IntegerArgumentType.getInteger(c, "page")))))
                .then(Commands.literal("applyedits")
                        .requires(s -> hasEditorPerm(s.getSender()))
                        .executes(c -> helpDetail(c.getSource().getSender(), "jl_applyedits"))
                        .then(Commands.literal("confirm").executes(this::editorConfirm))
                        .then(Commands.argument("code", StringArgumentType.word())
                                .suggests(this::suggestApplyEditsCode)
                                .executes(c -> editorPrepare(c, StringArgumentType.getString(c, "code")))))
                .then(Commands.literal("skin")
                        .requires(s -> hasAdminSub(s.getSender(), "skin"))
                        .executes(c -> helpDetail(c.getSource().getSender(), "jl_skin"))
                        .then(Commands.argument("player", StringArgumentType.word())
                                .suggests(this::suggestAccounts)
                                .executes(c -> helpDetail(c.getSource().getSender(), "jl_skin"))
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
                                        .executes(c -> adminSkin(
                                                c,
                                                StringArgumentType.getString(c, "player"),
                                                StringArgumentType.getString(c, "target"))))));

        if (Boolean.getBoolean("justlogin.debug")) {
            root.then(Commands.literal("debug-click")
                    .requires(s -> s.getSender() instanceof ConsoleCommandSender)
                    .then(Commands.argument("player", StringArgumentType.word())
                            .then(Commands.argument("action", StringArgumentType.word())
                                    .executes(c -> debugClick(c, StringArgumentType.getString(c, "player"),
                                            StringArgumentType.getString(c, "action"), "", ""))
                                    .then(Commands.argument("arg1", StringArgumentType.word())
                                            .executes(c -> debugClick(c, StringArgumentType.getString(c, "player"),
                                                    StringArgumentType.getString(c, "action"),
                                                    StringArgumentType.getString(c, "arg1"), ""))
                                            .then(Commands.argument("arg2", StringArgumentType.greedyString())
                                                    .executes(c -> debugClick(c, StringArgumentType.getString(c, "player"),
                                                            StringArgumentType.getString(c, "action"),
                                                            StringArgumentType.getString(c, "arg1"),
                                                            StringArgumentType.getString(c, "arg2"))))))));
        }

        commands.register(root.build(), "JustLogin administration and web editor", List.of("jl", "auth"));
    }

    private com.mojang.brigadier.builder.LiteralArgumentBuilder<CommandSourceStack> buildHelpNode(String literal) {
        return Commands.literal(literal)
                .requires(s -> hasAnyPerm(s.getSender()))
                .executes(c -> help(c.getSource().getSender(), null))
                .then(Commands.argument("topic", StringArgumentType.greedyString())
                        .suggests(this::suggestHelpTopics)
                        .executes(c -> help(c.getSource().getSender(), StringArgumentType.getString(c, "topic"))));
    }

    private com.mojang.brigadier.builder.LiteralArgumentBuilder<CommandSourceStack> buildChangePasswordNode(String literal) {
        return Commands.literal(literal)
                .requires(s -> hasAdminSub(s.getSender(), "changepass"))
                .executes(c -> helpDetail(c.getSource().getSender(), "jl_changepass"))
                .then(Commands.argument("player", StringArgumentType.word())
                        .suggests(this::suggestAccounts)
                        .executes(c -> helpDetail(c.getSource().getSender(), "jl_changepass"))
                        .then(Commands.argument("newPassword", StringArgumentType.greedyString())
                                .suggests((c, b) -> {
                                    if (b.getRemaining().isEmpty()) {
                                        b.suggest("<newPassword>");
                                    }
                                    return b.buildFuture();
                                })
                                .executes(c -> adminChangePw(
                                        c,
                                        StringArgumentType.getString(c, "player"),
                                        StringArgumentType.getString(c, "newPassword")))));
    }

    private com.mojang.brigadier.builder.LiteralArgumentBuilder<CommandSourceStack> buildForcePwNode(String literal) {
        return Commands.literal(literal)
                .requires(s -> hasAdminSub(s.getSender(), "forcepw"))
                .executes(c -> helpDetail(c.getSource().getSender(), "jl_forcepw"))
                .then(Commands.argument("player", StringArgumentType.word())
                        .suggests(this::suggestAccounts)
                        .executes(c -> helpDetail(c.getSource().getSender(), "jl_forcepw"))
                        .then(Commands.argument("force", BoolArgumentType.bool())
                                .executes(c -> adminForcePw(
                                        c,
                                        StringArgumentType.getString(c, "player"),
                                        BoolArgumentType.getBool(c, "force")))));
    }

    private com.mojang.brigadier.builder.LiteralArgumentBuilder<CommandSourceStack> buildImportNode(
            String name, SourceType type, String defaultTable, String defaultPath) {
        return Commands.literal(name)
                .executes(c -> runAutoImportSingle(c.getSource().getSender(), type, ImportFlags.NONE))
                .then(Commands.literal("auto")
                        .executes(c -> runAutoImportSingle(c.getSource().getSender(), type, ImportFlags.NONE))
                        .then(flagsArg(c -> runAutoImportSingle(c.getSource().getSender(), type, parseFlags(c)))))
                .then(flagsArg(c -> runAutoImportSingle(c.getSource().getSender(), type, parseFlags(c))))
                .then(Commands.literal("sqlite")
                        .executes(c -> helpDetail(c.getSource().getSender(), "jl_import"))
                        .then(Commands.argument("path", StringArgumentType.greedyString())
                                .suggests((c, b) -> {
                                    if (defaultPath.toLowerCase(Locale.ROOT).startsWith(b.getRemainingLowerCase())) {
                                        b.suggest(defaultPath);
                                    }
                                    return b.buildFuture();
                                })
                                .executes(c -> runSqliteImport(
                                        c.getSource().getSender(), type,
                                        StringArgumentType.getString(c, "path"), defaultTable))))
                .then(Commands.literal("mysql")
                        .executes(c -> helpDetail(c.getSource().getSender(), "jl_import"))
                        .then(Commands.argument("host", StringArgumentType.word())
                                .suggests((c, b) -> {
                                    if ("127.0.0.1".startsWith(b.getRemainingLowerCase())) b.suggest("127.0.0.1");
                                    if ("localhost".startsWith(b.getRemainingLowerCase())) b.suggest("localhost");
                                    return b.buildFuture();
                                })
                                .executes(c -> helpDetail(c.getSource().getSender(), "jl_import"))
                                .then(Commands.argument("port", IntegerArgumentType.integer(1, 65535))
                                        .suggests((c, b) -> {
                                            if ("3306".startsWith(b.getRemainingLowerCase())) b.suggest(3306);
                                            return b.buildFuture();
                                        })
                                        .executes(c -> helpDetail(c.getSource().getSender(), "jl_import"))
                                        .then(Commands.argument("database", StringArgumentType.word())
                                                .suggests((c, b) -> {
                                                    if (defaultTable.startsWith(b.getRemainingLowerCase())) b.suggest(defaultTable);
                                                    return b.buildFuture();
                                                })
                                                .executes(c -> helpDetail(c.getSource().getSender(), "jl_import"))
                                                .then(Commands.argument("user", StringArgumentType.word())
                                                        .suggests((c, b) -> {
                                                            if ("root".startsWith(b.getRemainingLowerCase())) b.suggest("root");
                                                            return b.buildFuture();
                                                        })
                                                        .executes(c -> helpDetail(c.getSource().getSender(), "jl_import"))
                                                        .then(Commands.argument("password", StringArgumentType.word())
                                                                .suggests((c, b) -> {
                                                                    if (b.getRemaining().isEmpty()) b.suggest("<password>");
                                                                    return b.buildFuture();
                                                                })
                                                                .executes(c -> runMysqlImport(c, type, defaultTable, ImportFlags.NONE))
                                                                .then(Commands.argument("options", StringArgumentType.greedyString())
                                                                        .suggests((c, b) -> {
                                                                            String rem = b.getRemainingLowerCase();
                                                                            int sp = rem.lastIndexOf(' ');
                                                                            String last = rem.substring(sp + 1);
                                                                            for (String o : List.of("--dry-run", "--ssl-mode=trust",
                                                                                    "--ssl-mode=disable", "--ssl-mode=verify-ca",
                                                                                    "--ssl-mode=verify-full",
                                                                                    "--keep-offline-uuid", "--rewrite-uuid")) {
                                                                                if (o.startsWith(last)) {
                                                                                    b.createOffset(b.getStart() + sp + 1).suggest(o);
                                                                                }
                                                                            }
                                                                            return b.buildFuture();
                                                                        })
                                                                        .executes(c -> {
                                                                            // [table] [--dry-run] [--ssl-mode=<mode>] [--keep-offline-uuid]
                                                                            ImportFlags f = ImportFlags.parse(
                                                                                    StringArgumentType.getString(c, "options"));
                                                                            String table = f.table() != null ? f.table() : defaultTable;
                                                                            return runMysqlImport(c, type, table, f);
                                                                        }))))))));
    }

    /** Optional trailing flags: {@code --dry-run}, {@code --ssl-mode=<mode>}, {@code --keep-offline-uuid}. */
    private com.mojang.brigadier.builder.RequiredArgumentBuilder<CommandSourceStack, String> flagsArg(
            com.mojang.brigadier.Command<CommandSourceStack> exec) {
        return Commands.argument("flags", StringArgumentType.greedyString())
                .suggests((c, b) -> {
                    String rem = b.getRemainingLowerCase();
                    int sp = rem.lastIndexOf(' ');
                    String last = rem.substring(sp + 1);
                    for (String o : List.of("--dry-run", "--ssl-mode=trust", "--ssl-mode=disable",
                            "--keep-offline-uuid", "--rewrite-uuid")) {
                        if (o.startsWith(last)) b.createOffset(b.getStart() + sp + 1).suggest(o);
                    }
                    return b.buildFuture();
                })
                .executes(exec);
    }

    private static ImportFlags parseFlags(CommandContext<CommandSourceStack> c) {
        return ImportFlags.parse(StringArgumentType.getString(c, "flags"));
    }

    /**
     * @param error unknown token / invalid value (shown to the sender), {@code null} when valid
     * @param preserveGameUuid {@code TRUE} = {@code --keep-offline-uuid}, {@code FALSE} = {@code --rewrite-uuid},
     *                         {@code null} = follow FastLogin's {@code premiumUuid} config
     */
    record ImportFlags(boolean dryRun, @Nullable String sslMode, @Nullable Boolean preserveGameUuid,
                       @Nullable String table, @Nullable String error) {
        static final ImportFlags NONE = new ImportFlags(false, null, null, null, null);

        static ImportFlags parse(String raw) {
            boolean dry = false;
            String ssl = null;
            Boolean keep = null;
            String table = null;
            String error = null;
            for (String tok : raw.strip().split("\\s+")) {
                if (tok.isEmpty()) continue;
                String lower = tok.toLowerCase(Locale.ROOT);
                if (lower.equals("--dry-run")) {
                    dry = true;
                } else if (lower.equals("--keep-offline-uuid") || lower.equals("--preserve-game-uuid")) {
                    keep = Boolean.TRUE;
                } else if (lower.equals("--rewrite-uuid")) {
                    keep = Boolean.FALSE;
                } else if (lower.startsWith("--ssl-mode=")) {
                    String v = tok.substring("--ssl-mode=".length());
                    ssl = MigrationScanner.normalizeSslMode(v);
                    if (ssl == null) error = tok;
                } else if (lower.startsWith("--")) {
                    error = tok;
                } else if (table == null && tok.matches("^[a-zA-Z0-9_]{1,64}$")) {
                    table = tok;
                } else {
                    error = tok;
                }
            }
            return new ImportFlags(dry, ssl, keep, table, error);
        }
    }

    private boolean rejectFlags(Context ctx, CommandSender sender, ImportFlags f) {
        if (f.error() == null) return false;
        ctx.messages().send(sender, "admin.import-bad-flag", Map.of("flag", f.error()));
        return true;
    }

    private MigrationScanner.ScanOptions scanOptions(Context ctx, ImportFlags f) {
        String fallback = ctx.settings().dbConfig().sslMode();
        return new MigrationScanner.ScanOptions(f.sslMode(), fallback, f.preserveGameUuid());
    }

    private java.util.concurrent.CompletableFuture<com.mojang.brigadier.suggestion.Suggestions> suggestHelpTopics(
            CommandContext<CommandSourceStack> c,
            com.mojang.brigadier.suggestion.SuggestionsBuilder b) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = plugin.context();
        boolean preAuthLocked = (sender instanceof Player p)
                && (ctx == null || !ctx.sessionManager().isAuthenticated(p.getUniqueId()));
        String rem = b.getRemainingLowerCase();
        for (String topic : HelpRenderer.suggestTopicsFor(sender, preAuthLocked)) {
            if (topic.toLowerCase(Locale.ROOT).startsWith(rem)) {
                b.suggest(topic);
            }
        }
        return b.buildFuture();
    }

    private java.util.concurrent.CompletableFuture<com.mojang.brigadier.suggestion.Suggestions> suggestAccounts(
            CommandContext<CommandSourceStack> c,
            com.mojang.brigadier.suggestion.SuggestionsBuilder b) {
        return suggestAccountsExcluding(b, null);
    }

    private java.util.concurrent.CompletableFuture<com.mojang.brigadier.suggestion.Suggestions> suggestMergeTarget(
            CommandContext<CommandSourceStack> c,
            com.mojang.brigadier.suggestion.SuggestionsBuilder b) {
        String source = null;
        try {
            source = StringArgumentType.getString(c, "source");
        } catch (IllegalArgumentException ignored) {
        }
        return suggestAccountsExcluding(b, source);
    }

    private java.util.concurrent.CompletableFuture<com.mojang.brigadier.suggestion.Suggestions> suggestRenameNew(
            CommandContext<CommandSourceStack> c,
            com.mojang.brigadier.suggestion.SuggestionsBuilder b) {
        if (b.getRemaining().isEmpty()) {
            b.suggest("<newName>");
        }
        return b.buildFuture();
    }

    private java.util.concurrent.CompletableFuture<com.mojang.brigadier.suggestion.Suggestions> suggestAuditLimits(
            CommandContext<CommandSourceStack> c,
            com.mojang.brigadier.suggestion.SuggestionsBuilder b) {
        String rem = b.getRemainingLowerCase();
        for (int limit : new int[] { 10, 15, 25, 50, 100 }) {
            if (Integer.toString(limit).startsWith(rem)) {
                b.suggest(limit);
            }
        }
        return b.buildFuture();
    }

    private java.util.concurrent.CompletableFuture<com.mojang.brigadier.suggestion.Suggestions> suggestPages(
            CommandContext<CommandSourceStack> c,
            com.mojang.brigadier.suggestion.SuggestionsBuilder b) {
        String rem = b.getRemainingLowerCase();
        for (int page : new int[] { 1, 2, 3, 4, 5 }) {
            if (Integer.toString(page).startsWith(rem)) {
                b.suggest(page);
            }
        }
        return b.buildFuture();
    }

    private java.util.concurrent.CompletableFuture<com.mojang.brigadier.suggestion.Suggestions> suggestApplyEditsCode(
            CommandContext<CommandSourceStack> c,
            com.mojang.brigadier.suggestion.SuggestionsBuilder b) {
        String rem = b.getRemainingLowerCase();
        if ("confirm".startsWith(rem)) {
            b.suggest("confirm");
        }
        if (rem.isEmpty()) {
            b.suggest("<code>");
        }
        return b.buildFuture();
    }

    private java.util.concurrent.CompletableFuture<com.mojang.brigadier.suggestion.Suggestions> suggestAccountsExcluding(
            com.mojang.brigadier.suggestion.SuggestionsBuilder b,
            @Nullable String excludeName) {
        String rem = b.getRemainingLowerCase();
        String excludeLower = excludeName == null ? null : excludeName.toLowerCase(Locale.ROOT);
        java.util.Set<String> seenLower = new java.util.HashSet<>();
        for (Player online : Bukkit.getOnlinePlayers()) {
            String name = online.getName();
            String lower = name.toLowerCase(Locale.ROOT);
            if ((excludeLower == null || !lower.equals(excludeLower)) && lower.startsWith(rem)) {
                if (seenLower.add(lower)) {
                    b.suggest(name);
                }
            }
        }
        Context ctx = plugin.context();
        if (ctx == null) {
            return b.buildFuture();
        }
        return ctx.accounts().suggestNames(rem, 40).thenApply(names -> {
            for (String name : names) {
                String lower = name.toLowerCase(Locale.ROOT);
                if ((excludeLower == null || !lower.equals(excludeLower)) && seenLower.add(lower)) {
                    b.suggest(name);
                }
            }
            return b.build();
        });
    }

    private static boolean hasAdminSub(CommandSender sender, String sub) {
        return sender.hasPermission("justlogin.admin") || sender.hasPermission("justlogin.admin." + sub);
    }

    private static boolean hasAnyPerm(CommandSender sender) {
        if (!(sender instanceof Player) || sender.hasPermission("justlogin.use")) return true;
        if (hasEditorPerm(sender)) return true;
        return hasAdminSub(sender, "reload") || hasAdminSub(sender, "status") || hasAdminSub(sender, "audit")
                || hasAdminSub(sender, "unregister") || hasAdminSub(sender, "changepass")
                || hasAdminSub(sender, "forcepw") || hasAdminSub(sender, "reset2fa")
                || hasAdminSub(sender, "setpremium") || hasAdminSub(sender, "rename")
                || hasAdminSub(sender, "merge") || hasAdminSub(sender, "gui")
                || hasAdminSub(sender, "import");
    }

    private static boolean hasEditorPerm(CommandSender sender) {
        return sender.hasPermission("justlogin.editor") || sender.hasPermission("justlogin.admin");
    }

    private int help(CommandSender sender, @Nullable String topic) {
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        boolean preAuthLocked = (sender instanceof Player p)
                && !ctx.sessionManager().isAuthenticated(p.getUniqueId());
        boolean bedrock = (sender instanceof Player p)
                && ctx.capabilities().isFloodgate(p.getUniqueId());
        ctx.helpRenderer().render(sender, topic, preAuthLocked, bedrock);
        return Command.SINGLE_SUCCESS;
    }

    private int helpDetail(CommandSender sender, String commandId) {
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        boolean bedrock = (sender instanceof Player p)
                && ctx.capabilities().isFloodgate(p.getUniqueId());
        ctx.helpRenderer().renderCommandDetail(sender, commandId, bedrock);
        return Command.SINGLE_SUCCESS;
    }

    private int reload(CommandContext<CommandSourceStack> c) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        plugin.reloadPluginConfig();
        ctx.messages().send(sender, "admin.reloaded");
        return Command.SINGLE_SUCCESS;
    }

    private int status(CommandContext<CommandSourceStack> c, String target) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        String lower = UsernameValidator.normalizeLower(target);
        ctx.accounts().findByNameLower(lower).whenComplete((opt, ex) -> runOnSenderThread(ctx, sender, () -> {
            if (opt == null || opt.isEmpty()) {
                ctx.messages().send(sender, "admin.account-not-found", Map.of("player", target));
                return;
            }
            Account a = opt.get();
            PlayerSession s = ctx.sessionManager().getSessionByName(target);
            String stateStr = s != null ? s.state().name() : "OFFLINE";
            ctx.messages().send(sender, "admin.status-header", Map.of("player", a.lastName()));
            ctx.messages().sendRaw(sender, "admin.status-line", Map.of(
                    "id", String.valueOf(a.id()),
                    "uuid", a.gameUuid().toString(),
                    "algo", a.hashAlgo().name(),
                    "premium", String.valueOf(a.premium()),
                    "pending", String.valueOf(a.premiumPending()),
                    "totp", String.valueOf(a.hasTotp()),
                    "forcePw", String.valueOf(a.forcePasswordChange()),
                    "state", stateStr));
        }));
        return Command.SINGLE_SUCCESS;
    }

    private int audit(CommandContext<CommandSourceStack> c, int limit) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        ctx.audit().recent(limit).whenComplete((rows, ex) -> runOnSenderThread(ctx, sender, () -> {
            if (rows == null || rows.isEmpty()) {
                ctx.messages().send(sender, "admin.audit-empty");
                return;
            }
            ctx.messages().send(sender, "admin.audit-header");
            for (AuditEntry e : rows) {
                ctx.messages().sendRaw(sender, "admin.audit-line", Map.of(
                        "time", TIME_FMT.format(Instant.ofEpochMilli(e.timestamp())),
                        "actor", e.actor(),
                        "action", e.action(),
                        "target", e.target(),
                        "details", e.details() == null ? "-" : e.details()));
            }
        }));
        return Command.SINGLE_SUCCESS;
    }

    private int adminUnregister(CommandContext<CommandSourceStack> c, String target) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        ctx.authService().adminUnregister(target, sender.getName()).whenComplete((res, ex) -> runOnSenderThread(ctx, sender, () -> {
            if (res == null || res.status() == AuthService.Status.NOT_REGISTERED) {
                ctx.messages().send(sender, "admin.account-not-found", Map.of("player", target));
                return;
            }
            ctx.messages().send(sender, "admin.unregistered", Map.of("player", target));
            Player online = Bukkit.getPlayerExact(target);
            if (online != null) {
                ctx.scheduler().runForEntity(online, () -> {
                    ctx.sessionManager().removePlayerSession(online.getUniqueId());
                    online.kick(ctx.messages().component("auth.unregistered"));
                }, null);
            }
        }));
        return Command.SINGLE_SUCCESS;
    }

    private int adminChangePw(CommandContext<CommandSourceStack> c, String target, String newPw) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        ctx.authService().changePassword(target, null, newPw.toCharArray(), sender.getName(), true)
                .whenComplete((res, ex) -> runOnSenderThread(ctx, sender, () -> {
                    if (res == null || res.status() == AuthService.Status.NOT_REGISTERED) {
                        ctx.messages().send(sender, "admin.account-not-found", Map.of("player", target));
                    } else if (res.status() == AuthService.Status.PASSWORD_POLICY_VIOLATION) {
                        sender.sendMessage(ctx.messages().component("prefix").append(ctx.coordinator().policyComponent(res.policyViolation())));
                    } else if (res.status() == AuthService.Status.SUCCESS) {
                        ctx.messages().send(sender, "admin.password-updated", Map.of("player", target));
                        refreshOnlinePlayerSession(ctx, target);
                    } else {
                        ctx.messages().send(sender, "general.internal-error");
                    }
                }));
        return Command.SINGLE_SUCCESS;
    }

    private int adminForcePw(CommandContext<CommandSourceStack> c, String target, boolean force) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        ctx.authService().adminSetForcePasswordChange(target, force, sender.getName())
                .whenComplete((res, ex) -> runOnSenderThread(ctx, sender, () -> {
                    if (res == null || res.status() == AuthService.Status.NOT_REGISTERED) {
                        ctx.messages().send(sender, "admin.account-not-found", Map.of("player", target));
                    } else {
                        ctx.messages().send(sender, "admin.force-pw-updated",
                                Map.of("player", target, "value", String.valueOf(force)));
                        refreshOnlinePlayerSession(ctx, target);
                    }
                }));
        return Command.SINGLE_SUCCESS;
    }

    private int adminReset2fa(CommandContext<CommandSourceStack> c, String target) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        ctx.authService().adminResetTotp(target, sender.getName())
                .whenComplete((res, ex) -> runOnSenderThread(ctx, sender, () -> {
                    if (res == null || res.status() == AuthService.Status.NOT_REGISTERED) {
                        ctx.messages().send(sender, "admin.account-not-found", Map.of("player", target));
                    } else {
                        ctx.messages().send(sender, "admin.totp-reset", Map.of("player", target));
                        refreshOnlinePlayerSession(ctx, target);
                    }
                }));
        return Command.SINGLE_SUCCESS;
    }

    private int adminSetPremium(CommandContext<CommandSourceStack> c, String target, boolean premium) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        ctx.authService().adminSetPremium(target, premium, sender.getName())
                .whenComplete((res, ex) -> runOnSenderThread(ctx, sender, () -> {
                    if (res == null || res.status() == AuthService.Status.NOT_REGISTERED) {
                        ctx.messages().send(sender, "admin.account-not-found", Map.of("player", target));
                    } else {
                        ctx.messages().send(sender, "admin.premium-updated",
                                Map.of("player", target, "value", String.valueOf(premium)));
                        refreshOnlinePlayerSession(ctx, target);
                    }
                }));
        return Command.SINGLE_SUCCESS;
    }

    private int adminRename(CommandContext<CommandSourceStack> c, String oldName, String newName) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        ctx.authService().renameAccount(oldName, newName, sender.getName())
                .whenComplete((res, ex) -> runOnSenderThread(ctx, sender, () -> {
                    if (res == null || ex != null) {
                        ctx.messages().send(sender, "general.internal-error");
                        return;
                    }
                    switch (res.status()) {
                        case SUCCESS -> ctx.messages().send(sender, "admin.renamed",
                                Map.of("old", oldName, "new", newName));
                        case NOT_REGISTERED -> ctx.messages().send(sender, "admin.account-not-found",
                                Map.of("player", oldName));
                        case TARGET_ALREADY_EXISTS -> ctx.messages().send(sender, "admin.rename-conflict",
                                Map.of("new", newName));
                        case INVALID_USERNAME -> ctx.messages().send(sender, "general.invalid-username");
                        default -> ctx.messages().send(sender, "general.internal-error");
                    }
                }));
        return Command.SINGLE_SUCCESS;
    }

    private int adminMerge(CommandContext<CommandSourceStack> c, String sourceName, String targetName) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        ctx.authService().mergeAccounts(sourceName, targetName, sender.getName())
                .whenComplete((res, ex) -> runOnSenderThread(ctx, sender, () -> {
                    if (res == null || ex != null) {
                        ctx.messages().send(sender, "general.internal-error");
                        return;
                    }
                    switch (res.status()) {
                        case SUCCESS -> ctx.messages().send(sender, "admin.merged",
                                Map.of("source", sourceName, "target", targetName));
                        case CANNOT_MERGE_SELF -> ctx.messages().send(sender, "admin.merge-same");
                        case NOT_REGISTERED -> ctx.messages().send(sender, "admin.merge-missing",
                                Map.of("source", sourceName, "target", targetName));
                        default -> ctx.messages().send(sender, "general.internal-error");
                    }
                }));
        return Command.SINGLE_SUCCESS;
    }

    private int adminGui(CommandContext<CommandSourceStack> c, int page) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        if (!(sender instanceof Player player)) {
            ctx.messages().send(sender, "general.players-only");
            return Command.SINGLE_SUCCESS;
        }
        ctx.adminGui().open(player, page);
        return Command.SINGLE_SUCCESS;
    }

    private int scanAndShowMigrations(CommandSender sender) {
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        Path pluginsDir = plugin.getDataFolder().toPath().toAbsolutePath().normalize().getParent();
        ctx.scheduler().runAsync(() -> {
            List<DetectedSource> detected = MigrationScanner.scan(pluginsDir);
            ctx.setDetectedMigrations(detected);
            runOnSenderThread(ctx, sender, () -> {
                if (!ctx.activeConflictingPlugins().isEmpty()) {
                    ctx.messages().send(sender, "admin.migration-conflict-warning",
                            Map.of("plugins", String.join(", ", ctx.activeConflictingPlugins())));
                }
                if (detected.isEmpty()) {
                    ctx.messages().send(sender, "admin.migration-none-found");
                    helpDetail(sender, "jl_import");
                    return;
                }
                ctx.messages().send(sender, "admin.migration-detected-header",
                        Map.of("count", String.valueOf(detected.size())));
                for (DetectedSource src : detected) {
                    ctx.messages().sendRaw(sender, "admin.migration-detected-line",
                            Map.of("source", src.displayName(), "summary", src.summary()));
                }
                ctx.messages().sendRaw(sender, "admin.migration-detected-auto-btn");
            });
        });
        return Command.SINGLE_SUCCESS;
    }

    private int runAutoImportAll(CommandSender sender, ImportFlags flags) {
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        if (rejectFlags(ctx, sender, flags)) return Command.SINGLE_SUCCESS;
        boolean dryRun = flags.dryRun();
        MigrationScanner.ScanOptions opts = scanOptions(ctx, flags);
        Path dataDir = plugin.getDataFolder().toPath().toAbsolutePath().normalize();
        Path pluginsDir = dataDir.getParent();
        ctx.scheduler().runAsync(() -> {
            List<DetectedSource> detected = MigrationScanner.scan(pluginsDir, opts);
            ctx.setDetectedMigrations(detected);
            if (detected.isEmpty()) {
                runOnSenderThread(ctx, sender, () -> ctx.messages().send(sender, "admin.migration-none-found"));
                return;
            }
            String targets = detected.stream().map(DetectedSource::displayName).reduce((a, b) -> a + " + " + b).orElse("auto");
            runOnSenderThread(ctx, sender, () -> ctx.messages().send(sender, "admin.import-started",
                    Map.of("source", targets, "target", dryRun ? "auto (--dry-run)" : "auto")));
            MigrationScanner.importAll(detected, ctx.accounts(), ctx.audit(), ctx.secrets(),
                    sender.getName(), dryRun, dataDir, System.currentTimeMillis())
                    .whenComplete((summary, ex) -> handleAutoSummary(ctx, sender, summary, ex, !dryRun));
        });
        return Command.SINGLE_SUCCESS;
    }

    private int runAutoImportSingle(CommandSender sender, SourceType type, ImportFlags flags) {
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        if (rejectFlags(ctx, sender, flags)) return Command.SINGLE_SUCCESS;
        boolean dryRun = flags.dryRun();
        MigrationScanner.ScanOptions opts = scanOptions(ctx, flags);
        Path dataDir = plugin.getDataFolder().toPath().toAbsolutePath().normalize();
        Path pluginsDir = dataDir.getParent();
        ctx.scheduler().runAsync(() -> {
            List<DetectedSource> detected = MigrationScanner.scan(pluginsDir, opts);
            DetectedSource match = detected.stream().filter(s -> s.type() == type).findFirst().orElse(null);
            if (match == null) {
                runOnSenderThread(ctx, sender, () -> {
                    ctx.messages().send(sender, "admin.migration-none-found");
                    helpDetail(sender, "jl_import");
                });
                return;
            }
            runOnSenderThread(ctx, sender, () -> ctx.messages().send(sender, "admin.import-started",
                    Map.of("source", match.displayName(), "target", match.summary() + (dryRun ? " (--dry-run)" : ""))));
            MigrationScanner.importSingle(match, ctx.accounts(), ctx.audit(), ctx.secrets(),
                    sender.getName(), dryRun, dataDir, System.currentTimeMillis())
                    .whenComplete((summary, ex) -> handleAutoSummary(ctx, sender, summary, ex, false));
        });
        return Command.SINGLE_SUCCESS;
    }

    private int runSqliteImport(CommandSender sender, SourceType type, String rawPath, String defaultTable) {
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        // Trailing "--flag" tokens belong to the options, everything before them is the (possibly spaced) path.
        String[] toks = rawPath.strip().split("\\s+");
        int end = toks.length;
        while (end > 1 && toks[end - 1].startsWith("--")) end--;
        String pathStr = String.join(" ", java.util.Arrays.copyOfRange(toks, 0, end));
        ImportFlags flags = ImportFlags.parse(String.join(" ", java.util.Arrays.copyOfRange(toks, end, toks.length)));
        if (rejectFlags(ctx, sender, flags)) return Command.SINGLE_SUCCESS;
        Path dataDir = plugin.getDataFolder().toPath().toAbsolutePath().normalize();
        DetectedSource src = withFastLoginUuidMode(
                DetectedSource.sqlite(type, Path.of(pathStr), defaultTable), flags);
        startAndRun(ctx, sender, src, flags.dryRun(), dataDir, pathStr);
        return Command.SINGLE_SUCCESS;
    }

    private int runMysqlImport(CommandContext<CommandSourceStack> c, SourceType type, String table, ImportFlags flags) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        if (rejectFlags(ctx, sender, flags)) return Command.SINGLE_SUCCESS;
        String host = StringArgumentType.getString(c, "host");
        int port = IntegerArgumentType.getInteger(c, "port");
        String db = StringArgumentType.getString(c, "database");
        String user = StringArgumentType.getString(c, "user");
        String pass = StringArgumentType.getString(c, "password");
        Path dataDir = plugin.getDataFolder().toPath().toAbsolutePath().normalize();
        // Explicit --ssl-mode wins, otherwise JustLogin's storage.mariadb.ssl-mode, otherwise the driver default.
        String ssl = flags.sslMode() != null ? flags.sslMode() : ctx.settings().dbConfig().sslMode();
        DetectedSource src = withFastLoginUuidMode(
                DetectedSource.mysql(type, host, port, db, user, pass, table, ssl), flags);
        startAndRun(ctx, sender, src, flags.dryRun(), dataDir, host + ":" + port + "/" + db);
        return Command.SINGLE_SUCCESS;
    }

    /** Manual FastLogin imports: flag > plugins/FastLogin/config.yml {@code premiumUuid} > rewrite (FastLogin default). */
    private DetectedSource withFastLoginUuidMode(DetectedSource src, ImportFlags flags) {
        if (src.type() != SourceType.FASTLOGIN) return src;
        boolean preserve;
        if (flags.preserveGameUuid() != null) {
            preserve = flags.preserveGameUuid();
        } else {
            Path pluginsDir = plugin.getDataFolder().toPath().toAbsolutePath().normalize().getParent();
            preserve = !MigrationScanner.fastLoginPremiumUuid(pluginsDir);
        }
        return src.withPreserveGameUuid(preserve);
    }

    private void startAndRun(Context ctx, CommandSender sender, DetectedSource src, boolean dryRun,
                             Path dataDir, String target) {
        String shown = src.type() == SourceType.FASTLOGIN
                ? target + " [game_uuid=" + (src.preserveGameUuid() ? "keep-offline" : "rewrite-to-mojang") + "]"
                : target;
        ctx.messages().send(sender, "admin.import-started",
                Map.of("source", src.type().displayName(), "target", shown + (dryRun ? " (--dry-run)" : "")));
        MigrationScanner.importSingle(src, ctx.accounts(), ctx.audit(), ctx.secrets(),
                sender.getName(), dryRun, dataDir, System.currentTimeMillis())
                .whenComplete((summary, ex) -> handleAutoSummary(ctx, sender, summary, ex, false));
    }

    private void handleAutoSummary(
            Context ctx,
            CommandSender sender,
            MigrationScanner.@Nullable AutoMigrationSummary summary,
            @Nullable Throwable ex,
            boolean clearDetectedOnSuccess
    ) {
        runOnSenderThread(ctx, sender, () -> {
            if (ex != null || summary == null) {
                ctx.messages().send(sender, "admin.import-failed",
                        Map.of("error", ex != null ? String.valueOf(ex.getMessage()) : "unknown"));
                return;
            }
            if (clearDetectedOnSuccess) {
                ctx.setDetectedMigrations(List.of());
            }
            ctx.messages().send(sender, "admin.import-auto-done", Map.of(
                    "imported", String.valueOf(summary.totalImported()),
                    "updated", String.valueOf(summary.totalUpdated()),
                    "existing", String.valueOf(summary.totalSkippedExisting()),
                    "invalid", String.valueOf(summary.totalSkippedInvalid())));
            for (MigrationScanner.SourceResult r : summary.results()) {
                if (r.source().type() == SourceType.FASTLOGIN) {
                    ctx.messages().send(sender, r.source().preserveGameUuid()
                            ? "admin.import-fastlogin-uuid-kept" : "admin.import-fastlogin-uuid-rewritten");
                }
            }
            if (summary.reportFile() != null) {
                ctx.messages().send(sender, "admin.import-report-saved",
                        Map.of("file", "plugins/JustLogin/" + summary.reportFile().getFileName()));
            }
        });
    }

    private int editorCreate(CommandContext<CommandSourceStack> c, int page) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        ctx.messages().send(sender, "editor.creating");
        BytebinClient relay = new BytebinClient(ctx.effectiveEditorRelayUrl());
        ctx.editorService().createSession(
                page, ctx.settings().editorPageSize(), ctx.effectiveEditorWebUrl(),
                relay, ctx.settings().editorTtlSeconds() * 1000L)
                .whenComplete((res, ex) -> runOnSenderThread(ctx, sender, () -> {
                    if (ex != null || res == null) {
                        ctx.messages().send(sender, "editor.failed",
                                Map.of("error", ex != null ? String.valueOf(ex.getMessage()) : "unknown"));
                        return;
                    }
                    var link = ctx.messages().component("editor.created-link", Map.of(
                            "count", String.valueOf(res.exportedCount()),
                            "total", String.valueOf(res.totalAccounts()),
                            "url", res.editorUrl()))
                            .clickEvent(ClickEvent.openUrl(res.editorUrl()));
                    sender.sendMessage(ctx.messages().component("prefix").append(link));
                    ctx.messages().sendRaw(sender, "editor.created-code", Map.of("url", res.editorUrl()));
                    ctx.messages().send(sender, "editor.created-hint", Map.of("code", res.blobKey()));
                }));
        return Command.SINGLE_SUCCESS;
    }

    private int editorPrepare(CommandContext<CommandSourceStack> c, String code) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        String actorKey = actorKey(sender);
        ctx.messages().send(sender, "editor.downloading", Map.of("code", code));
        BytebinClient relay = new BytebinClient(ctx.effectiveEditorRelayUrl());
        ctx.editorService().prepareApply(actorKey, code, relay).whenComplete((plan, ex) -> runOnSenderThread(ctx, sender, () -> {
            if (ex != null || plan == null) {
                ctx.messages().send(sender, "editor.failed",
                        Map.of("error", ex != null ? String.valueOf(ex.getMessage()) : "unknown"));
                return;
            }
            if (plan.isEmpty()) {
                ctx.messages().send(sender, "editor.no-changes");
                return;
            }
            ctx.messages().send(sender, "editor.plan-summary", Map.of(
                    "changes", String.valueOf(plan.changes().size()),
                    "conflicts", String.valueOf(plan.conflicts().size())));
            for (EditorModels.PlannedChange ch : plan.changes()) {
                String summary = ch.kind() == EditorModels.PlannedChange.ChangeKind.DELETE
                        ? "DELETE"
                        : "premium=" + ch.newPremium() + ", forcePw=" + ch.newForcePasswordChange();
                ctx.messages().sendRaw(sender, "editor.plan-change-line", Map.of(
                        "target", ch.name(),
                        "summary", summary));
                if (ch.warningNoPassword()) {
                    ctx.messages().sendRaw(sender, "editor.plan-warning-no-password", Map.of("target", ch.name()));
                }
            }
            for (EditorModels.ConflictEntry conf : plan.conflicts()) {
                ctx.messages().sendRaw(sender, "editor.plan-conflict-line", Map.of(
                        "target", conf.name(),
                        "reason", conf.reason()));
            }
            if (!plan.changes().isEmpty()) {
                ctx.messages().send(sender, "editor.plan-confirm");
            }
        }));
        return Command.SINGLE_SUCCESS;
    }

    private int editorConfirm(CommandContext<CommandSourceStack> c) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        String actorKey = actorKey(sender);
        if (ctx.editorService().getPendingPlan(actorKey) == null) {
            ctx.messages().send(sender, "editor.no-pending-plan");
            return Command.SINGLE_SUCCESS;
        }
        ctx.editorService().confirmAndApply(actorKey, sender.getName()).whenComplete((rep, ex) ->
                runOnSenderThread(ctx, sender, () -> {
                    if (ex != null || rep == null) {
                        ctx.messages().send(sender, "editor.failed",
                                Map.of("error", ex != null ? String.valueOf(ex.getMessage()) : "unknown"));
                        return;
                    }
                    ctx.messages().send(sender, "editor.applied", Map.of(
                            "applied", String.valueOf(rep.applied()),
                            "skipped", String.valueOf(rep.skippedConflicts())));
                    for (String affectedName : rep.affectedNames()) {
                        refreshOnlinePlayerSession(ctx, affectedName);
                    }
                }));
        return Command.SINGLE_SUCCESS;
    }

    private int adminSkin(CommandContext<CommandSourceStack> c, String targetPlayer, String skinTarget) {
        CommandSender sender = c.getSource().getSender();
        Context ctx = readyContext(sender);
        if (ctx == null) return Command.SINGLE_SUCCESS;
        if (!ctx.settings().skinsEnabled()) {
            ctx.messages().send(sender, "skins.disabled");
            return Command.SINGLE_SUCCESS;
        }
        boolean reset = SkinCommands.isResetKeyword(skinTarget);
        if (!reset && !SkinCommands.isValidMojangUsername(skinTarget)) {
            ctx.messages().send(sender, "skins.invalid-target");
            return Command.SINGLE_SUCCESS;
        }
        String lower = UsernameValidator.normalizeLower(targetPlayer);
        ctx.accounts().findByNameLower(lower).whenComplete((opt, ex) -> {
            if (ex != null || opt == null) {
                runOnSenderThread(ctx, sender, () -> ctx.messages().send(sender, "general.internal-error"));
                return;
            }
            if (opt.isEmpty()) {
                runOnSenderThread(ctx, sender, () ->
                        ctx.messages().send(sender, "admin.account-not-found", Map.of("player", targetPlayer)));
                return;
            }
            Account acc = opt.get();
            if (reset) {
                SkinCommands.clearAndResolveDefaultSkin(ctx, acc, sender.getName(), "ADMIN_SKIN_RESET")
                        .whenComplete((skin, ex2) -> runOnSenderThread(ctx, sender, () -> {
                            if (ex2 != null) {
                                ctx.messages().send(sender, "general.internal-error");
                                return;
                            }
                            Player online = Bukkit.getPlayerExact(acc.lastName());
                            if (online != null) {
                                ctx.scheduler().runForEntity(online, () -> {
                                    if (!online.isOnline()) return;
                                    SkinCommands.applyLiveSkin(online,
                                            skin != null ? skin.value() : null,
                                            skin != null ? skin.signature() : null);
                                }, null);
                            }
                            refreshOnlinePlayerSession(ctx, acc.lastName());
                            ctx.messages().send(sender, "skins.admin-reset", Map.of("player", acc.lastName()));
                        }));
                return;
            }
            SkinCommands.fetchAndSaveCustomSkin(ctx, acc, skinTarget, sender.getName(), "ADMIN_SKIN_SET")
                    .whenComplete((res, ex2) -> runOnSenderThread(ctx, sender, () -> {
                        if (ex2 != null || res == null) {
                            ctx.messages().send(sender, "skins.mojang-unavailable");
                            return;
                        }
                        switch (res.status()) {
                            case FOUND -> {
                                MojangSkinClient.SkinData skin = res.skin();
                                if (skin == null) {
                                    ctx.messages().send(sender, "skins.mojang-unavailable");
                                    return;
                                }
                                Player online = Bukkit.getPlayerExact(acc.lastName());
                                if (online != null) {
                                    ctx.scheduler().runForEntity(online, () -> {
                                        if (!online.isOnline()) return;
                                        SkinCommands.applyLiveSkin(online, skin.value(), skin.signature());
                                    }, null);
                                }
                                refreshOnlinePlayerSession(ctx, acc.lastName());
                                ctx.messages().send(sender, "skins.admin-changed",
                                        Map.of("player", acc.lastName(), "skin", skin.ownerName()));
                            }
                            case NOT_FOUND -> ctx.messages().send(sender, "skins.not-found", Map.of("skin", skinTarget));
                            case RATE_LIMITED, UNAVAILABLE -> ctx.messages().send(sender, "skins.mojang-unavailable");
                        }
                    }));
        });
        return Command.SINGLE_SUCCESS;
    }

    private void refreshOnlinePlayerSession(Context ctx, String targetName) {
        Player online = Bukkit.getPlayerExact(targetName);
        if (online == null) return;
        String lower = UsernameValidator.normalizeLower(targetName);
        ctx.accounts().findByNameLower(lower).whenComplete((opt, ex) ->
                ctx.scheduler().runForEntity(online, () -> {
                    if (!online.isOnline()) return;
                    PlayerSession s = ctx.sessionManager().getSession(online.getUniqueId());
                    if (s == null) return;
                    if (opt == null || opt.isEmpty()) {
                        ctx.sessionManager().removePlayerSession(online.getUniqueId());
                        online.kick(ctx.messages().component("auth.unregistered"));
                        return;
                    }
                    Account updated = opt.get();
                    s.setAccount(updated);
                    if (updated.forcePasswordChange() && s.isAuthenticated()) {
                        s.setState(AuthState.AWAITING_FORCED_PW_CHANGE);
                        s.setAnchorLocation(online.getLocation());
                        online.updateCommands();
                        ctx.messages().send(online, "auth.force-password-change");
                        ctx.coordinator().sendPrompt(online, s);
                    }
                }, null));
    }

    private int debugClick(CommandContext<CommandSourceStack> c, String targetName, String actionRaw, String a1, String a2) {
        Context ctx = readyContext(c.getSource().getSender());
        if (ctx == null) return Command.SINGLE_SUCCESS;
        ClickData.Action action;
        try {
            action = ClickData.Action.valueOf(actionRaw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            c.getSource().getSender().sendMessage("Invalid debug action: " + actionRaw);
            return Command.SINGLE_SUCCESS;
        }
        PendingConfigAuth cfgPending = ctx.sessionManager().getConfigByName(targetName);
        if (cfgPending != null) {
            ctx.scheduler().runAsync(() -> ctx.coordinator().handleConfigDialogAction(cfgPending, action, a1, a2));
            return Command.SINGLE_SUCCESS;
        }
        PlayerSession playSession = ctx.sessionManager().getSessionByName(targetName);
        Player player = Bukkit.getPlayerExact(targetName);
        if (playSession != null && player != null) {
            ctx.scheduler().runAsync(() -> ctx.coordinator().handlePlayDialogAction(player, playSession, action, a1, a2));
            return Command.SINGLE_SUCCESS;
        }
        c.getSource().getSender().sendMessage("No pending config or play dialog for " + targetName);
        return Command.SINGLE_SUCCESS;
    }

    private void runOnSenderThread(Context ctx, CommandSender sender, Runnable task) {
        if (sender instanceof Player p) {
            ctx.scheduler().runForEntity(p, task, null);
        } else {
            ctx.scheduler().runGlobal(task);
        }
    }

    private static String actorKey(CommandSender sender) {
        return sender instanceof Player p ? "player:" + p.getUniqueId() : "console";
    }
}

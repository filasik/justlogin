package me.skerik.justlogin.paper.command;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.bukkit.command.CommandSender;
import org.jspecify.annotations.Nullable;

/**
 * Single source of truth registry for all JustLogin player and administrator commands (Section 14).
 * Used by {@link HelpRenderer} and unit tests verifying Brigadier command tree and localization parity.
 */
public final class CommandDoc {

    public enum Section {
        ACCOUNT,
        TOTP,
        PREMIUM,
        EMAIL,
        OTHER,
        ADMIN;

        public String titleKey() {
            return "help.sec." + name();
        }
    }

    public enum Availability {
        ALWAYS,
        EMAIL_ENABLED,
        CAPTCHA_ENABLED,
        PREMIUM_CAPABLE,
        SKINS_ENABLED
    }

    public record Entry(
            String id,
            String primaryLiteral,
            String topicKey,
            Section section,
            String permission,
            List<String> aliases,
            Availability availability,
            boolean preAuthAllowed,
            boolean hasSensitiveArgs
    ) {
        public Entry {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(primaryLiteral, "primaryLiteral");
            Objects.requireNonNull(topicKey, "topicKey");
            Objects.requireNonNull(section, "section");
            Objects.requireNonNull(permission, "permission");
            aliases = List.copyOf(Objects.requireNonNull(aliases, "aliases"));
            Objects.requireNonNull(availability, "availability");
        }

        public String syntaxKey() {
            return "help.cmd." + id + ".syntax";
        }

        public String descKey() {
            return "help.cmd." + id + ".desc";
        }

        public String exampleKey() {
            return "help.cmd." + id + ".example";
        }

        public String noteKey() {
            return "help.cmd." + id + ".note";
        }

        public boolean isPermitted(CommandSender sender) {
            if (sender.hasPermission(permission)) {
                return true;
            }
            return section == Section.ADMIN && sender.hasPermission("justlogin.admin");
        }

        /**
         * Returns the command string for {@code suggest_command} click events (never {@code run_command}
         * for commands with passwords or destructive actions).
         */
        public String suggestCommand() {
            return switch (id) {
                case "logout", "2fa_setup", "2fa_cancel", "premium", "email_clear", "jl_help", "jl_reload", "jl_gui", "jl_editor" ->
                        primaryLiteral;
                default -> primaryLiteral + " ";
            };
        }
    }

    public static final List<Entry> ALL = List.of(
            // ACCOUNT
            new Entry(
                    "register",
                    "/register",
                    "register",
                    Section.ACCOUNT,
                    "justlogin.use",
                    List.of("reg"),
                    Availability.ALWAYS,
                    true,
                    true
            ),
            new Entry(
                    "login",
                    "/login",
                    "login",
                    Section.ACCOUNT,
                    "justlogin.use",
                    List.of("l"),
                    Availability.ALWAYS,
                    true,
                    true
            ),
            new Entry(
                    "logout",
                    "/logout",
                    "logout",
                    Section.ACCOUNT,
                    "justlogin.use",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    false
            ),
            new Entry(
                    "changepassword",
                    "/changepassword",
                    "changepassword",
                    Section.ACCOUNT,
                    "justlogin.use",
                    List.of("changepass", "cp"),
                    Availability.ALWAYS,
                    false,
                    true
            ),
            new Entry(
                    "unregister",
                    "/unregister",
                    "unregister",
                    Section.ACCOUNT,
                    "justlogin.use",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    true
            ),

            // TOTP
            new Entry(
                    "2fa_setup",
                    "/2fa setup",
                    "2fa setup",
                    Section.TOTP,
                    "justlogin.2fa",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    false
            ),
            new Entry(
                    "2fa_cancel",
                    "/2fa cancel",
                    "2fa cancel",
                    Section.TOTP,
                    "justlogin.2fa",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    false
            ),
            new Entry(
                    "2fa_confirm",
                    "/2fa confirm",
                    "2fa confirm",
                    Section.TOTP,
                    "justlogin.2fa",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    false
            ),
            new Entry(
                    "2fa_verify",
                    "/2fa verify",
                    "2fa verify",
                    Section.TOTP,
                    "justlogin.use",
                    List.of(),
                    Availability.ALWAYS,
                    true,
                    false
            ),
            new Entry(
                    "2fa_disable",
                    "/2fa disable",
                    "2fa disable",
                    Section.TOTP,
                    "justlogin.2fa",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    true
            ),

            // PREMIUM
            new Entry(
                    "premium",
                    "/premium",
                    "premium",
                    Section.PREMIUM,
                    "justlogin.premium",
                    List.of(),
                    Availability.PREMIUM_CAPABLE,
                    false,
                    false
            ),
            new Entry(
                    "unpremium",
                    "/unpremium",
                    "unpremium",
                    Section.PREMIUM,
                    "justlogin.premium",
                    List.of(),
                    Availability.PREMIUM_CAPABLE,
                    false,
                    true
            ),

            // EMAIL
            new Entry(
                    "email_set",
                    "/email set",
                    "email set",
                    Section.EMAIL,
                    "justlogin.email",
                    List.of(),
                    Availability.EMAIL_ENABLED,
                    false,
                    true
            ),
            new Entry(
                    "email_confirm",
                    "/email confirm",
                    "email confirm",
                    Section.EMAIL,
                    "justlogin.email",
                    List.of(),
                    Availability.EMAIL_ENABLED,
                    false,
                    false
            ),
            new Entry(
                    "email_clear",
                    "/email clear",
                    "email clear",
                    Section.EMAIL,
                    "justlogin.email",
                    List.of(),
                    Availability.EMAIL_ENABLED,
                    false,
                    false
            ),
            new Entry(
                    "email_recover",
                    "/email recover",
                    "email recover",
                    Section.EMAIL,
                    "justlogin.email",
                    List.of(),
                    Availability.EMAIL_ENABLED,
                    true,
                    true
            ),

            // OTHER
            new Entry(
                    "skin",
                    "/skin",
                    "skin",
                    Section.OTHER,
                    "justlogin.skin",
                    List.of("skins"),
                    Availability.SKINS_ENABLED,
                    false,
                    false
            ),
            new Entry(
                    "captcha",
                    "/captcha",
                    "captcha",
                    Section.OTHER,
                    "justlogin.use",
                    List.of(),
                    Availability.CAPTCHA_ENABLED,
                    true,
                    false
            ),
            new Entry(
                    "jl_help",
                    "/jl help",
                    "help",
                    Section.OTHER,
                    "justlogin.use",
                    List.of("justlogin help", "jl ?"),
                    Availability.ALWAYS,
                    true,
                    false
            ),

            // ADMIN
            new Entry(
                    "jl_reload",
                    "/jl reload",
                    "reload",
                    Section.ADMIN,
                    "justlogin.admin.reload",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    false
            ),
            new Entry(
                    "jl_status",
                    "/jl status",
                    "status",
                    Section.ADMIN,
                    "justlogin.admin.status",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    false
            ),
            new Entry(
                    "jl_audit",
                    "/jl audit",
                    "audit",
                    Section.ADMIN,
                    "justlogin.admin.audit",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    false
            ),
            new Entry(
                    "jl_unregister",
                    "/jl unregister",
                    "jl unregister",
                    Section.ADMIN,
                    "justlogin.admin.unregister",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    false
            ),
            new Entry(
                    "jl_changepass",
                    "/jl changepass",
                    "changepass",
                    Section.ADMIN,
                    "justlogin.admin.changepass",
                    List.of("changepassword"),
                    Availability.ALWAYS,
                    false,
                    true
            ),
            new Entry(
                    "jl_forcepw",
                    "/jl forcepw",
                    "forcepw",
                    Section.ADMIN,
                    "justlogin.admin.forcepw",
                    List.of("forcechangepassword"),
                    Availability.ALWAYS,
                    false,
                    false
            ),
            new Entry(
                    "jl_reset2fa",
                    "/jl reset2fa",
                    "reset2fa",
                    Section.ADMIN,
                    "justlogin.admin.reset2fa",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    false
            ),
            new Entry(
                    "jl_setpremium",
                    "/jl setpremium",
                    "setpremium",
                    Section.ADMIN,
                    "justlogin.admin.setpremium",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    false
            ),
            new Entry(
                    "jl_rename",
                    "/jl rename",
                    "rename",
                    Section.ADMIN,
                    "justlogin.admin.rename",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    false
            ),
            new Entry(
                    "jl_merge",
                    "/jl merge",
                    "merge",
                    Section.ADMIN,
                    "justlogin.admin.merge",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    false
            ),
            new Entry(
                    "jl_gui",
                    "/jl gui",
                    "gui",
                    Section.ADMIN,
                    "justlogin.admin.gui",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    false
            ),
            new Entry(
                    "jl_import",
                    "/jl import",
                    "import",
                    Section.ADMIN,
                    "justlogin.admin.import",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    true
            ),
            new Entry(
                    "jl_editor",
                    "/jl editor",
                    "editor",
                    Section.ADMIN,
                    "justlogin.editor",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    false
            ),
            new Entry(
                    "jl_applyedits",
                    "/jl applyedits",
                    "applyedits",
                    Section.ADMIN,
                    "justlogin.editor",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    false
            ),
            new Entry(
                    "jl_skin",
                    "/jl skin",
                    "skin",
                    Section.ADMIN,
                    "justlogin.admin.skin",
                    List.of(),
                    Availability.ALWAYS,
                    false,
                    false
            )
    );

    private CommandDoc() {
    }

    public static Optional<Entry> findById(@Nullable String id) {
        if (id == null || id.isBlank()) {
            return Optional.empty();
        }
        String norm = id.strip().toLowerCase(Locale.ROOT);
        for (Entry e : ALL) {
            if (e.id().equalsIgnoreCase(norm)) {
                return Optional.of(e);
            }
        }
        return Optional.empty();
    }

    /**
     * Looks up a command entry by ID, literal, topic key, subcommand name, or alias.
     */
    public static Optional<Entry> findByQuery(@Nullable String query) {
        List<Entry> matches = findAllByQuery(query);
        return matches.isEmpty() ? Optional.empty() : Optional.of(matches.getFirst());
    }

    /**
     * Returns all matching entries for a query (e.g. {@code "2fa"} returns all TOTP subcommands,
     * {@code "email"} returns all 4 email subcommands, and specific queries return the matching entry).
     */
    public static List<Entry> findAllByQuery(@Nullable String query) {
        String q = normalizeQuery(query);
        if (q.isEmpty()) {
            return List.of();
        }

        // 1. Direct match on id, primaryLiteral, or topicKey before stripping "/jl "
        List<Entry> direct = new ArrayList<>();
        for (Entry e : ALL) {
            if (matchesPrimary(e, q)) {
                direct.add(e);
            }
        }
        if (!direct.isEmpty()) {
            return List.copyOf(direct);
        }

        // 2. Direct match on aliases before stripping "/jl "
        for (Entry e : ALL) {
            if (matchesAlias(e, q)) {
                direct.add(e);
            }
        }
        if (!direct.isEmpty()) {
            return List.copyOf(direct);
        }

        // 3. Strip leading "justlogin ", "jl ", or "auth " prefix and match again (preferring /jl subcommands first)
        String stripped = stripRootPrefix(q);
        if (!stripped.equals(q)) {
            for (Entry e : ALL) {
                if (e.id().startsWith("jl_") && (matchesPrimary(e, stripped) || matchesAlias(e, stripped))) {
                    direct.add(e);
                }
            }
            if (!direct.isEmpty()) {
                return List.copyOf(direct);
            }
            for (Entry e : ALL) {
                if (matchesPrimary(e, stripped) || matchesAlias(e, stripped)) {
                    direct.add(e);
                }
            }
            if (!direct.isEmpty()) {
                return List.copyOf(direct);
            }
        }

        // 4. Multi-subcommand command groups ("2fa", "totp", "email")
        if (stripped.equals("2fa") || stripped.equals("totp")) {
            return forSection(Section.TOTP);
        }
        if (stripped.equals("email")) {
            return forSection(Section.EMAIL);
        }

        return List.of();
    }

    public static Optional<Section> findSection(@Nullable String query) {
        String q = stripRootPrefix(normalizeQuery(query));
        if (q.isEmpty()) {
            return Optional.empty();
        }
        return switch (q) {
            case "account", "accounts" -> Optional.of(Section.ACCOUNT);
            case "totp", "2fa" -> Optional.of(Section.TOTP);
            case "premium" -> Optional.of(Section.PREMIUM);
            case "email" -> Optional.of(Section.EMAIL);
            case "other" -> Optional.of(Section.OTHER);
            case "admin", "administration" -> Optional.of(Section.ADMIN);
            default -> Optional.empty();
        };
    }

    public static List<Entry> forSection(Section section) {
        Objects.requireNonNull(section, "section");
        List<Entry> out = new ArrayList<>();
        for (Entry e : ALL) {
            if (e.section() == section) {
                out.add(e);
            }
        }
        return List.copyOf(out);
    }

    public static List<Entry> bySection(Section section) {
        return forSection(section);
    }

    /**
     * Returns all top-level Brigadier command literals registered by JustLogin on Paper.
     */
    public static Set<String> topLevelLiterals() {
        Set<String> set = new LinkedHashSet<>();
        for (Entry e : ALL) {
            String raw = stripLeadingSlash(e.primaryLiteral());
            int sp = raw.indexOf(' ');
            String root = sp > 0 ? raw.substring(0, sp) : raw;
            if (root.equals("jl")) {
                set.add("justlogin");
            } else {
                set.add(root);
            }
        }
        return Collections.unmodifiableSet(set);
    }

    /**
     * Returns all {@code /justlogin} ({@code /jl}) subcommand literals (including aliases like
     * {@code changepassword}, {@code forcechangepassword}, and {@code ?}) for Brigadier tree verification.
     */
    public static Set<String> adminSubcommandLiterals() {
        Set<String> set = new LinkedHashSet<>();
        for (Entry e : ALL) {
            String raw = stripLeadingSlash(e.primaryLiteral());
            if (raw.startsWith("jl ")) {
                String sub = raw.substring("jl ".length()).strip();
                if (!sub.isEmpty()) {
                    set.add(sub);
                }
                for (String alias : e.aliases()) {
                    String normAlias = stripLeadingSlash(alias);
                    if (normAlias.startsWith("justlogin ")) {
                        set.add(normAlias.substring("justlogin ".length()).strip());
                    } else if (normAlias.startsWith("jl ")) {
                        set.add(normAlias.substring("jl ".length()).strip());
                    } else if (!normAlias.contains(" ")) {
                        set.add(normAlias);
                    }
                }
            }
        }
        return Collections.unmodifiableSet(set);
    }

    /**
     * Returns all {@code /2fa} subcommand literals.
     */
    public static Set<String> twoFactorSubcommandLiterals() {
        Set<String> set = new LinkedHashSet<>();
        for (Entry e : forSection(Section.TOTP)) {
            String raw = stripLeadingSlash(e.primaryLiteral());
            if (raw.startsWith("2fa ")) {
                set.add(raw.substring("2fa ".length()).strip());
            }
        }
        return Collections.unmodifiableSet(set);
    }

    /**
     * Returns all {@code /email} subcommand literals.
     */
    public static Set<String> emailSubcommandLiterals() {
        Set<String> set = new LinkedHashSet<>();
        for (Entry e : forSection(Section.EMAIL)) {
            String raw = stripLeadingSlash(e.primaryLiteral());
            if (raw.startsWith("email ")) {
                set.add(raw.substring("email ".length()).strip());
            }
        }
        return Collections.unmodifiableSet(set);
    }

    /**
     * Returns all localization message keys required by {@link CommandDoc} and {@link HelpRenderer}.
     */
    public static List<String> requiredMessageKeys() {
        List<String> keys = new ArrayList<>();
        keys.add("help.header");
        keys.add("help.preauth-header");
        keys.add("help.footer");
        keys.add("help.page-prev");
        keys.add("help.page-next");
        keys.add("help.unknown-topic");
        keys.add("help.disabled.email");
        keys.add("help.disabled.captcha");
        keys.add("help.disabled.premium");
        keys.add("help.detail.header");
        keys.add("help.detail.syntax");
        keys.add("help.detail.aliases");
        keys.add("help.detail.permission");
        keys.add("help.detail.example");
        keys.add("help.detail.note");
        for (Section s : Section.values()) {
            keys.add(s.titleKey());
        }
        for (Entry e : ALL) {
            keys.add(e.syntaxKey());
            keys.add(e.descKey());
            keys.add(e.exampleKey());
            keys.add(e.noteKey());
        }
        return List.copyOf(keys);
    }

    private static boolean matchesPrimary(Entry e, String q) {
        if (e.id().equalsIgnoreCase(q)) {
            return true;
        }
        if (stripLeadingSlash(e.primaryLiteral()).equalsIgnoreCase(q)) {
            return true;
        }
        return e.topicKey().equalsIgnoreCase(q);
    }

    private static boolean matchesAlias(Entry e, String q) {
        for (String alias : e.aliases()) {
            String norm = stripLeadingSlash(alias);
            if (norm.equalsIgnoreCase(q) || stripRootPrefix(norm).equalsIgnoreCase(q)) {
                return true;
            }
        }
        return false;
    }

    private static String normalizeQuery(@Nullable String query) {
        if (query == null) {
            return "";
        }
        String s = stripLeadingSlash(query.strip()).toLowerCase(Locale.ROOT);
        return s.replaceAll("\\s+", " ");
    }

    private static String stripLeadingSlash(String s) {
        int i = 0;
        while (i < s.length() && s.charAt(i) == '/') {
            i++;
        }
        return s.substring(i).strip();
    }

    private static String stripRootPrefix(String q) {
        if (q.startsWith("justlogin ")) {
            return q.substring("justlogin ".length()).strip();
        }
        if (q.startsWith("jl ")) {
            return q.substring("jl ".length()).strip();
        }
        if (q.startsWith("auth ")) {
            return q.substring("auth ".length()).strip();
        }
        return q;
    }
}

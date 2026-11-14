package me.skerik.justlogin.paper.command;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import me.skerik.justlogin.paper.command.CommandDoc.Availability;
import me.skerik.justlogin.paper.command.CommandDoc.Entry;
import me.skerik.justlogin.paper.command.CommandDoc.Section;
import me.skerik.justlogin.paper.config.Messages;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.TextComponent;
import net.kyori.adventure.text.event.ClickEvent;
import net.kyori.adventure.text.event.HoverEvent;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.jspecify.annotations.Nullable;

/**
 * Renders interactive MiniMessage help pages, command detail cards, pre-auth help, and console/Bedrock views
 * from {@link CommandDoc} and localized {@code help.*} templates (Plan Section 14).
 */
public final class HelpRenderer {

    private static final int MAX_ENTRIES_PER_PAGE = 9;
    private static final PlainTextComponentSerializer PLAIN = PlainTextComponentSerializer.plainText();

    private final Messages messages;
    private final String pluginVersion;
    private final boolean emailEnabled;
    private final boolean captchaEnabled;
    private final boolean premiumCapable;
    private final boolean skinsEnabled;

    public HelpRenderer(
            Messages messages,
            String pluginVersion,
            boolean emailEnabled,
            boolean captchaEnabled,
            boolean premiumCapable
    ) {
        this(messages, pluginVersion, emailEnabled, captchaEnabled, premiumCapable, true);
    }

    public HelpRenderer(
            Messages messages,
            String pluginVersion,
            boolean emailEnabled,
            boolean captchaEnabled,
            boolean premiumCapable,
            boolean skinsEnabled
    ) {
        this.messages = Objects.requireNonNull(messages, "messages");
        this.pluginVersion = Objects.requireNonNull(pluginVersion, "pluginVersion");
        this.emailEnabled = emailEnabled;
        this.captchaEnabled = captchaEnabled;
        this.premiumCapable = premiumCapable;
        this.skinsEnabled = skinsEnabled;
    }

    public void render(CommandSender sender, @Nullable String arg) {
        render(sender, arg, false, false);
    }

    public void render(
            CommandSender sender,
            @Nullable String arg,
            boolean preAuthLocked,
            boolean bedrockClient
    ) {
        boolean interactive = (sender instanceof Player) && !bedrockClient;

        if (preAuthLocked) {
            renderPreAuth(sender, interactive);
            return;
        }

        String trimmed = arg == null ? "" : arg.strip();
        int requestedPage = parsePositiveInt(trimmed);

        if (!trimmed.isEmpty() && requestedPage <= 0) {
            renderTopicOrCommand(sender, trimmed, interactive);
            return;
        }

        List<List<SectionBlock>> pages = buildSectionPages(sender);
        int totalPages = Math.max(1, pages.size());
        int page = requestedPage <= 0 ? 1 : Math.min(requestedPage, totalPages);

        messages.sendRaw(sender, "help.header", Map.of(
                "version", pluginVersion,
                "page", String.valueOf(page),
                "pages", String.valueOf(totalPages)
        ));

        if (!pages.isEmpty()) {
            List<SectionBlock> blocks = pages.get(page - 1);
            for (SectionBlock block : blocks) {
                Component secHeader = Component.text("│ ", NamedTextColor.DARK_GRAY)
                        .append(messages.component(block.section().titleKey()));
                sender.sendMessage(secHeader);
                for (Entry entry : block.entries()) {
                    sender.sendMessage(renderCommandLine(entry, interactive, false));
                }
            }
        }

        if (totalPages > 1) {
            sender.sendMessage(buildPaginationBar(page, totalPages, interactive));
        }

        messages.sendRaw(sender, "help.footer", Map.of(
                "version", pluginVersion,
                "page", String.valueOf(page),
                "pages", String.valueOf(totalPages)
        ));
    }

    /**
     * Renders the detailed card for a specific command (e.g. when an incomplete command like {@code /jl rename}
     * is executed without required arguments).
     */
    public void renderCommandDetail(CommandSender sender, String commandId) {
        renderCommandDetail(sender, commandId, false);
    }

    public void renderCommandDetail(CommandSender sender, String commandId, boolean bedrockClient) {
        boolean interactive = (sender instanceof Player) && !bedrockClient;
        Optional<Entry> entryOpt = CommandDoc.findById(commandId)
                .or(() -> CommandDoc.findByQuery(commandId));
        if (entryOpt.isEmpty()) {
            messages.send(sender, "help.unknown-topic", Map.of("topic", commandId));
            return;
        }
        renderEntryDetail(sender, entryOpt.get(), interactive, true);
    }

    public List<String> suggestTopics(CommandSender sender) {
        return suggestTopics(sender, false);
    }

    public List<String> suggestTopics(CommandSender sender, boolean preAuthLocked) {
        return suggestTopicsFor(sender, preAuthLocked);
    }

    public static List<String> suggestTopicsFor(CommandSender sender, boolean preAuthLocked) {
        Set<String> out = new LinkedHashSet<>();
        if (preAuthLocked) {
            for (Entry e : CommandDoc.ALL) {
                if (e.preAuthAllowed() && e.isPermitted(sender)) {
                    out.add(primaryTopicToken(e));
                }
            }
            return List.copyOf(out);
        }

        out.add("1");
        out.add("2");
        if (hasAnySectionEntries(sender, Section.ADMIN)) {
            out.add("3");
        }

        for (Section s : Section.values()) {
            if (hasAnySectionEntries(sender, s)) {
                out.add(s.name().toLowerCase(Locale.ROOT));
            }
        }

        if (hasAnySectionEntries(sender, Section.TOTP)) {
            out.add("2fa");
        }
        if (hasAnySectionEntries(sender, Section.EMAIL)) {
            out.add("email");
        }

        for (Entry e : CommandDoc.ALL) {
            if (!e.isPermitted(sender)) {
                continue;
            }
            out.add(primaryTopicToken(e));
            for (String alias : e.aliases()) {
                if (!alias.contains(" ") && !alias.equals("?")) {
                    out.add(alias.toLowerCase(Locale.ROOT));
                }
            }
        }
        return List.copyOf(out);
    }

    public boolean isAvailable(Entry entry) {
        return disabledReasonKey(entry) == null;
    }

    public @Nullable String disabledReasonKey(Entry entry) {
        return switch (entry.availability()) {
            case ALWAYS -> null;
            case EMAIL_ENABLED -> emailEnabled ? null : "help.disabled.email";
            case CAPTCHA_ENABLED -> captchaEnabled ? null : "help.disabled.captcha";
            case PREMIUM_CAPABLE -> premiumCapable ? null : "help.disabled.premium";
            case SKINS_ENABLED -> skinsEnabled ? null : "help.disabled.skins";
        };
    }

    private void renderPreAuth(CommandSender sender, boolean interactive) {
        messages.sendRaw(sender, "help.preauth-header", Map.of("version", pluginVersion));
        for (Entry entry : CommandDoc.ALL) {
            if (entry.preAuthAllowed() && entry.isPermitted(sender)) {
                // Pre-auth help never leaks server configuration (treat all pre-auth commands as active)
                sender.sendMessage(renderCommandLine(entry, interactive, true));
            }
        }
        messages.sendRaw(sender, "help.footer", Map.of(
                "version", pluginVersion,
                "page", "1",
                "pages", "1"
        ));
    }

    private void renderTopicOrCommand(CommandSender sender, String query, boolean interactive) {
        List<Entry> matched = CommandDoc.findAllByQuery(query).stream()
                .filter(e -> e.isPermitted(sender))
                .toList();
        if (!matched.isEmpty()) {
            for (int i = 0; i < matched.size(); i++) {
                renderEntryDetail(sender, matched.get(i), interactive, i == matched.size() - 1);
            }
            return;
        }

        Optional<Section> secOpt = CommandDoc.findSection(query);
        if (secOpt.isPresent()) {
            Section sec = secOpt.get();
            List<Entry> secEntries = CommandDoc.forSection(sec).stream()
                    .filter(e -> e.isPermitted(sender))
                    .toList();
            if (!secEntries.isEmpty()) {
                messages.sendRaw(sender, "help.header", Map.of(
                        "version", pluginVersion,
                        "page", "1",
                        "pages", "1"
                ));
                Component secHeader = Component.text("│ ", NamedTextColor.DARK_GRAY)
                        .append(messages.component(sec.titleKey()));
                sender.sendMessage(secHeader);
                for (Entry entry : secEntries) {
                    sender.sendMessage(renderCommandLine(entry, interactive, false));
                }
                messages.sendRaw(sender, "help.footer", Map.of(
                        "version", pluginVersion,
                        "page", "1",
                        "pages", "1"
                ));
                return;
            }
        }

        messages.send(sender, "help.unknown-topic", Map.of("topic", query));
    }

    private void renderEntryDetail(CommandSender sender, Entry entry, boolean interactive, boolean includeFooter) {
        String syntaxPlain = PLAIN.serialize(messages.component(entry.syntaxKey()));
        String descPlain = PLAIN.serialize(messages.component(entry.descKey()));
        String examplePlain = PLAIN.serialize(messages.component(entry.exampleKey()));
        String notePlain = PLAIN.serialize(messages.component(entry.noteKey()));
        String aliasesStr = entry.aliases().isEmpty() ? "-" : String.join(", ", entry.aliases());

        messages.sendRaw(sender, "help.detail.header", Map.of("command", entry.primaryLiteral()));

        Component descLine = Component.text("│ ", NamedTextColor.DARK_GRAY)
                .append(Component.text(descPlain, NamedTextColor.GRAY));
        String disabledKey = disabledReasonKey(entry);
        if (disabledKey != null) {
            descLine = descLine.append(Component.space()).append(messages.component(disabledKey));
        }
        sender.sendMessage(descLine);

        Component syntaxLine = messages.component("help.detail.syntax", Map.of("syntax", syntaxPlain));
        if (interactive) {
            syntaxLine = syntaxLine.clickEvent(ClickEvent.suggestCommand(entry.suggestCommand()));
        }
        sender.sendMessage(syntaxLine);

        if (!entry.aliases().isEmpty()) {
            messages.sendRaw(sender, "help.detail.aliases", Map.of("aliases", aliasesStr));
        }

        messages.sendRaw(sender, "help.detail.permission", Map.of("permission", entry.permission()));

        Component exampleLine = messages.component("help.detail.example", Map.of("example", examplePlain));
        if (interactive) {
            exampleLine = exampleLine.clickEvent(ClickEvent.suggestCommand(entry.suggestCommand()));
        }
        sender.sendMessage(exampleLine);

        if (!notePlain.isEmpty() && !notePlain.equals("-")) {
            messages.sendRaw(sender, "help.detail.note", Map.of("note", notePlain));
        }

        if (includeFooter) {
            messages.sendRaw(sender, "help.footer", Map.of(
                    "version", pluginVersion,
                    "page", "1",
                    "pages", "1"
            ));
        }
    }

    private Component renderCommandLine(Entry entry, boolean interactive, boolean forceAvailable) {
        String syntaxPlain = PLAIN.serialize(messages.component(entry.syntaxKey()));
        String descPlain = PLAIN.serialize(messages.component(entry.descKey()));
        String disabledKey = forceAvailable ? null : disabledReasonKey(entry);
        boolean disabled = disabledKey != null;

        if (!interactive) {
            TextComponent.Builder b = Component.text()
                    .append(Component.text("│  ", NamedTextColor.DARK_GRAY))
                    .append(Component.text(
                            String.format("%-30s ", syntaxPlain),
                            disabled ? NamedTextColor.DARK_GRAY : NamedTextColor.WHITE));
            if (disabled) {
                b.append(messages.component(disabledKey))
                        .append(Component.text(" - " + descPlain, NamedTextColor.DARK_GRAY));
            } else {
                b.append(Component.text("- " + descPlain, NamedTextColor.GRAY));
            }
            return b.build();
        }

        TextComponent.Builder line = Component.text()
                .append(Component.text("│ ", NamedTextColor.DARK_GRAY))
                .append(Component.text("▸ ", disabled ? NamedTextColor.DARK_GRAY : NamedTextColor.AQUA))
                .append(formatColoredSyntax(syntaxPlain, disabled));

        if (disabled) {
            line.append(Component.space()).append(messages.component(disabledKey));
        } else {
            line.append(Component.text(" — ", NamedTextColor.DARK_GRAY))
                    .append(Component.text(descPlain, NamedTextColor.GRAY));
        }

        return line.build()
                .clickEvent(ClickEvent.suggestCommand(entry.suggestCommand()))
                .hoverEvent(HoverEvent.showText(buildHoverComponent(entry, syntaxPlain, descPlain, disabledKey)));
    }

    private Component buildHoverComponent(
            Entry entry,
            String syntaxPlain,
            String descPlain,
            @Nullable String disabledKey
    ) {
        String examplePlain = PLAIN.serialize(messages.component(entry.exampleKey()));
        String notePlain = PLAIN.serialize(messages.component(entry.noteKey()));
        String aliasesStr = entry.aliases().isEmpty() ? "-" : String.join(", ", entry.aliases());

        TextComponent.Builder hover = Component.text()
                .append(Component.text(entry.primaryLiteral(), NamedTextColor.AQUA))
                .append(Component.newline())
                .append(Component.text(descPlain, NamedTextColor.GRAY))
                .append(Component.newline())
                .append(messages.component("help.detail.syntax", Map.of("syntax", syntaxPlain)))
                .append(Component.newline())
                .append(messages.component("help.detail.permission", Map.of("permission", entry.permission())))
                .append(Component.newline())
                .append(messages.component("help.detail.example", Map.of("example", examplePlain)));

        if (!entry.aliases().isEmpty()) {
            hover.append(Component.newline())
                    .append(messages.component("help.detail.aliases", Map.of("aliases", aliasesStr)));
        }
        if (!notePlain.isEmpty() && !notePlain.equals("-")) {
            hover.append(Component.newline())
                    .append(messages.component("help.detail.note", Map.of("note", notePlain)));
        }
        if (disabledKey != null) {
            hover.append(Component.newline())
                    .append(messages.component(disabledKey));
        }
        return hover.build();
    }

    private Component buildPaginationBar(int page, int totalPages, boolean interactive) {
        Component prev = page > 1
                ? messages.component("help.page-prev")
                : Component.text("«", NamedTextColor.DARK_GRAY);
        Component next = page < totalPages
                ? messages.component("help.page-next")
                : Component.text("»", NamedTextColor.DARK_GRAY);

        if (interactive) {
            if (page > 1) {
                String prevCmd = "/jl help " + (page - 1);
                prev = prev.clickEvent(ClickEvent.runCommand(prevCmd))
                        .hoverEvent(HoverEvent.showText(Component.text(prevCmd, NamedTextColor.GRAY)));
            }
            if (page < totalPages) {
                String nextCmd = "/jl help " + (page + 1);
                next = next.clickEvent(ClickEvent.runCommand(nextCmd))
                        .hoverEvent(HoverEvent.showText(Component.text(nextCmd, NamedTextColor.GRAY)));
            }
        }

        return Component.text("│ ", NamedTextColor.DARK_GRAY)
                .append(prev)
                .append(Component.text(" · " + page + "/" + totalPages + " · ", NamedTextColor.DARK_GRAY))
                .append(next);
    }

    private static Component formatColoredSyntax(String syntaxPlain, boolean disabled) {
        if (disabled) {
            return Component.text(syntaxPlain, NamedTextColor.DARK_GRAY);
        }
        String[] tokens = syntaxPlain.split(" ");
        TextComponent.Builder b = Component.text();
        for (int i = 0; i < tokens.length; i++) {
            if (i > 0) {
                b.append(Component.space());
            }
            String tok = tokens[i];
            if (tok.startsWith("<") && tok.endsWith(">")) {
                b.append(Component.text(tok, NamedTextColor.AQUA));
            } else if (tok.startsWith("[") && tok.endsWith("]")) {
                b.append(Component.text(tok, NamedTextColor.GRAY));
            } else {
                b.append(Component.text(tok, NamedTextColor.WHITE));
            }
        }
        return b.build();
    }

    private static List<List<SectionBlock>> buildSectionPages(CommandSender sender) {
        List<List<SectionBlock>> pages = new ArrayList<>();
        List<SectionBlock> currentPage = new ArrayList<>();
        int currentCount = 0;

        for (Section section : Section.values()) {
            List<Entry> permitted = CommandDoc.forSection(section).stream()
                    .filter(e -> e.isPermitted(sender))
                    .toList();
            if (permitted.isEmpty()) {
                continue;
            }
            if (!currentPage.isEmpty() && currentCount + permitted.size() > MAX_ENTRIES_PER_PAGE) {
                pages.add(List.copyOf(currentPage));
                currentPage = new ArrayList<>();
                currentCount = 0;
            }
            currentPage.add(new SectionBlock(section, permitted));
            currentCount += permitted.size();
        }

        if (!currentPage.isEmpty()) {
            pages.add(List.copyOf(currentPage));
        }
        return List.copyOf(pages);
    }

    private static boolean hasAnySectionEntries(CommandSender sender, Section section) {
        for (Entry e : CommandDoc.forSection(section)) {
            if (e.isPermitted(sender)) {
                return true;
            }
        }
        return false;
    }

    private static String primaryTopicToken(Entry entry) {
        String topic = entry.topicKey();
        if (topic.startsWith("jl ")) {
            return entry.id();
        }
        int sp = topic.indexOf(' ');
        return sp > 0 ? topic.substring(0, sp) : topic;
    }

    private static int parsePositiveInt(String s) {
        if (s.isEmpty() || s.length() > 4) {
            return -1;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return -1;
            }
        }
        try {
            int val = Integer.parseInt(s);
            return val > 0 ? val : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private record SectionBlock(Section section, List<Entry> entries) {
    }
}

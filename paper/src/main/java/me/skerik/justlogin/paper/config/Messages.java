package me.skerik.justlogin.paper.config;

import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.kyori.adventure.audience.Audience;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.kyori.adventure.text.minimessage.tag.resolver.Placeholder;
import net.kyori.adventure.text.minimessage.tag.resolver.TagResolver;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

/**
 * Loads MiniMessage templates from {@code messages_<lang>.yml} with English fallback and safe untrusted placeholder escaping.
 */
public final class Messages {

    private static final MiniMessage MM = MiniMessage.miniMessage();
    private static final Pattern BRACE_PLACEHOLDER = Pattern.compile("\\{([a-zA-Z0-9_.-]+)}");

    private final JavaPlugin plugin;
    private volatile YamlConfiguration messages = new YamlConfiguration();
    private volatile YamlConfiguration fallback = new YamlConfiguration();
    private volatile String prefix = "";

    public Messages(JavaPlugin plugin) {
        this.plugin = plugin;
    }

    public void load(String language) {
        saveDefault("messages_en.yml");
        saveDefault("messages_cs.yml");
        saveDefault("messages_sk.yml");

        YamlConfiguration fb = loadBundled("messages_en.yml");
        YamlConfiguration langYaml = new YamlConfiguration();
        String fileName = "messages_" + sanitizeLang(language) + ".yml";
        File target = new File(plugin.getDataFolder(), fileName);
        if (target.exists()) {
            langYaml = YamlConfiguration.loadConfiguration(target);
        } else {
            YamlConfiguration bundled = loadBundled(fileName);
            langYaml = bundled.getKeys(true).isEmpty() ? fb : bundled;
        }
        this.fallback = fb;
        this.messages = langYaml;
        this.prefix = raw("prefix");
    }

    /** Standalone helper for tests using pre-loaded configurations. */
    public static Component renderTemplate(String template, Map<String, String> placeholders) {
        List<TagResolver> resolvers = new ArrayList<>(placeholders.size());
        String rewritten = rewritePlaceholders(template, placeholders, resolvers);
        return MM.deserialize(rewritten, TagResolver.resolver(resolvers));
    }

    public String raw(String key) {
        String value = messages.getString(key);
        if (value != null) return value;
        String fb = fallback.getString(key);
        return fb != null ? fb : "<red>Missing message: " + key + "</red>";
    }

    public Component component(String key, Map<String, String> placeholders) {
        return renderTemplate(raw(key), placeholders);
    }

    public Component component(String key) {
        return MM.deserialize(raw(key));
    }

    public Component prefixed(String key, Map<String, String> placeholders) {
        return MM.deserialize(prefix).append(component(key, placeholders));
    }

    public Component prefixed(String key) {
        return MM.deserialize(prefix).append(component(key));
    }

    public void send(Audience audience, String key) {
        audience.sendMessage(prefixed(key));
    }

    public void send(Audience audience, String key, Map<String, String> placeholders) {
        audience.sendMessage(prefixed(key, placeholders));
    }

    public void sendRaw(Audience audience, String key) {
        audience.sendMessage(component(key));
    }

    public void sendRaw(Audience audience, String key, Map<String, String> placeholders) {
        audience.sendMessage(component(key, placeholders));
    }

    private static String rewritePlaceholders(String template, Map<String, String> placeholders, List<TagResolver> resolvers) {
        if (placeholders.isEmpty()) return template;
        Matcher m = BRACE_PLACEHOLDER.matcher(template);
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            String key = m.group(1);
            if (!placeholders.containsKey(key)) {
                m.appendReplacement(out, Matcher.quoteReplacement(m.group(0)));
                continue;
            }
            String val = placeholders.get(key);
            if (isInsideTagAttribute(template, m.start())) {
                // Escape quotes/angle brackets when substituting inside MiniMessage tag attributes like <click:open_url:'{url}'>
                m.appendReplacement(out, Matcher.quoteReplacement(sanitizeAttributeValue(val)));
            } else {
                String tagName = "jl_" + key.toLowerCase(java.util.Locale.ROOT).replaceAll("[^a-z0-9_]", "_");
                resolvers.add(Placeholder.unparsed(tagName, val == null ? "" : val));
                m.appendReplacement(out, "<" + tagName + ">");
            }
        }
        m.appendTail(out);
        return out.toString();
    }

    private static boolean isInsideTagAttribute(String s, int pos) {
        int lastLt = s.lastIndexOf('<', pos);
        int lastGt = s.lastIndexOf('>', pos);
        return lastLt > lastGt;
    }

    private static String sanitizeAttributeValue(String val) {
        if (val == null) return "";
        return val.replace("'", "%27").replace("\"", "%22").replace("<", "%3C").replace(">", "%3E");
    }

    private void saveDefault(String name) {
        File f = new File(plugin.getDataFolder(), name);
        if (!f.exists() && plugin.getResource(name) != null) {
            plugin.saveResource(name, false);
        }
    }

    private YamlConfiguration loadBundled(String name) {
        YamlConfiguration y = new YamlConfiguration();
        try (InputStream in = plugin.getResource(name)) {
            if (in != null) {
                y.load(new InputStreamReader(in, StandardCharsets.UTF_8));
            }
        } catch (Exception e) {
            plugin.getLogger().warning("Could not load bundled " + name + ": " + e.getMessage());
        }
        return y;
    }

    private static String sanitizeLang(String lang) {
        if (lang == null || lang.isBlank()) return "en";
        return lang.replaceAll("[^a-zA-Z0-9_-]", "");
    }
}

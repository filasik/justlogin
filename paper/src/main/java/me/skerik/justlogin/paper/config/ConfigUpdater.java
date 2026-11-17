package me.skerik.justlogin.paper.config;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.bukkit.configuration.InvalidConfigurationException;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

/**
 * Adds newly introduced keys and comments to {@code config.yml} on upgrade while preserving user values.
 */
public final class ConfigUpdater {

    public static final String VERSION_KEY = "config-version";
    public static final Map<String, String> RENAMES = Map.of(
            "language", "locale",
            "updates.check", "update-check",
            "database", "storage",
            "proxy.auto-detect-mojang", "premium.auto-detect-mojang",
            "proxy.mojang-cache-seconds", "premium.mojang-cache-seconds",
            "skins.restore-cracked-by-name", "skins.restore-by-name"
    );

    private ConfigUpdater() {
    }

    public static int update(JavaPlugin plugin) {
        Path file = plugin.getDataFolder().toPath().resolve("config.yml");
        YamlConfiguration defaults = new YamlConfiguration();
        try (InputStream in = plugin.getResource("config.yml")) {
            if (in == null) return 0;
            defaults.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        } catch (IOException | InvalidConfigurationException e) {
            plugin.getLogger().warning("Built-in config.yml is broken: " + e.getMessage());
            return 0;
        }
        YamlConfiguration user = new YamlConfiguration();
        try {
            user.load(file.toFile());
        } catch (IOException | InvalidConfigurationException e) {
            plugin.getLogger().warning("Cannot read config.yml for update check: " + e.getMessage());
            return 0;
        }
        int have = user.getInt(VERSION_KEY, 0);
        if (have >= defaults.getInt(VERSION_KEY, 1)) return 0;
        try {
            Files.copy(file, file.resolveSibling("config.yml.bak-v" + have), StandardCopyOption.REPLACE_EXISTING);
            int added = migrate(user, RENAMES) + merge(user, defaults);
            user.save(file.toFile());
            plugin.getLogger().info("config.yml updated to version " + user.getInt(VERSION_KEY)
                    + ": " + added + " new option(s) added");
            return added;
        } catch (IOException e) {
            plugin.getLogger().warning("Cannot update config.yml: " + e.getMessage());
            return 0;
        }
    }

    public static int migrate(YamlConfiguration user, Map<String, String> renames) {
        int moved = 0;
        for (Map.Entry<String, String> rename : renames.entrySet()) {
            if (!user.contains(rename.getKey(), true)) continue;
            user.set(rename.getValue(), user.get(rename.getKey()));
            user.set(rename.getKey(), null);
            moved++;
        }
        if ("https://filasik.github.io/justLogin/editor/".equals(user.getString("editor.web-url"))) {
            user.set("editor.web-url", "https://justlogin.net");
            moved++;
        }
        String relay = user.getString("editor.relay-url");
        if ("https://bytebin.lucko.me".equals(relay) || "https://bytebin.lucko.me/".equals(relay)) {
            user.set("editor.relay-url", "https://bytebin.justlogin.net");
            moved++;
        }
        return moved;
    }

    public static int merge(YamlConfiguration user, YamlConfiguration defaults) {
        int added = 0;
        for (String key : defaults.getKeys(true)) {
            if (key.equals(VERSION_KEY)) continue;
            if (user.contains(key, true)) {
                if (user.getComments(key).isEmpty()) {
                    List<String> comments = new ArrayList<>(defaults.getComments(key));
                    while (!comments.isEmpty() && comments.getFirst() == null) comments.removeFirst();
                    user.setComments(key, comments);
                }
                continue;
            }
            if (defaults.isConfigurationSection(key)) {
                user.createSection(key);
            } else {
                user.set(key, defaults.get(key));
                added++;
            }
            user.setComments(key, defaults.getComments(key));
            user.setInlineComments(key, defaults.getInlineComments(key));
        }
        user.set(VERSION_KEY, defaults.getInt(VERSION_KEY, 1));
        user.setComments(VERSION_KEY, defaults.getComments(VERSION_KEY));
        return added;
    }
}

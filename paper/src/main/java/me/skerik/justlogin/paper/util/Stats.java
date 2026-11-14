package me.skerik.justlogin.paper.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;
import java.util.Properties;
import me.skerik.justlogin.paper.config.Settings;
import org.bstats.bukkit.Metrics;
import org.bstats.charts.SimplePie;
import org.bukkit.plugin.java.JavaPlugin;
import org.jspecify.annotations.Nullable;

/**
 * bStats anonymous statistics. Off when {@code metrics: false} in config.yml, when bStats is disabled globally
 * (plugins/bStats/config.yml), or when this build carries no bStats id (bstatsId=0 in gradle.properties, a local build).
 */
public final class Stats implements AutoCloseable {

    private final @Nullable Metrics metrics;

    private Stats(@Nullable Metrics metrics) {
        this.metrics = metrics;
    }

    public static Stats start(JavaPlugin plugin, Settings settings) {
        if (!settings.metrics()) return new Stats(null);
        int id = pluginId(plugin);
        if (id <= 0) return new Stats(null);
        Metrics m = new Metrics(plugin, id);
        m.addCustomChart(new SimplePie("locale", settings::language));
        m.addCustomChart(new SimplePie("storage", () -> settings.dbConfig().dialect().name().toLowerCase(Locale.ROOT)));
        m.addCustomChart(new SimplePie("login_ui", () -> settings.loginUi().name().toLowerCase(Locale.ROOT)));
        m.addCustomChart(new SimplePie("proxy_mode", () -> settings.proxyMode().name().toLowerCase(Locale.ROOT)));
        return new Stats(m);
    }

    public boolean active() {
        return metrics != null;
    }

    private static int pluginId(JavaPlugin plugin) {
        Properties props = new Properties();
        try (InputStream in = plugin.getResource("build.properties")) {
            if (in == null) return 0;
            props.load(in);
            return Integer.parseInt(props.getProperty("bstats-id", "0").strip());
        } catch (IOException | NumberFormatException e) {
            return 0;
        }
    }

    @Override
    public void close() {
        if (metrics != null) {
            metrics.shutdown();
        }
    }
}

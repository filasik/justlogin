package me.skerik.justlogin.paper.util;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import me.skerik.justlogin.paper.config.Settings;
import org.bukkit.configuration.file.YamlConfiguration;

/**
 * Validates Paper/Spigot forwarding settings when {@code proxy.enabled=true} and fails closed on misconfiguration
 * (Threat model #1: prevents backend IP/UUID spoofing bypasses).
 */
public final class ProxyStartupCheck {

    public record CheckResult(boolean healthy, List<String> errors, List<String> warnings) {
    }

    private ProxyStartupCheck() {
    }

    public static CheckResult evaluate(Settings settings, Path serverRoot) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        if (!settings.proxyEnabled()) {
            if (settings.proxyMode() != Settings.ProxyMode.STANDALONE) {
                warnings.add("proxy.mode is set to " + settings.proxyMode() + " while proxy.enabled=false (running standalone).");
            }
            if (isPaperProxyForwardingEnabled(serverRoot)) {
                warnings.add("Paper/Spigot proxy forwarding is enabled while proxy.enabled=false; standalone premium Netty interception is paused.");
            }
            return new CheckResult(true, errors, warnings);
        }

        if (settings.proxyMode() == Settings.ProxyMode.STANDALONE) {
            errors.add("proxy.enabled=true cannot use proxy.mode=standalone. Set mode to 'velocity' or 'bungee'.");
        }
        if (settings.proxySharedSecret() == null || settings.proxySharedSecret().isBlank()) {
            errors.add("proxy.shared-secret is empty while proxy.enabled=true. Configure a shared secret matching the proxy.");
        } else if (settings.proxySharedSecret().length() < 16) {
            errors.add("proxy.shared-secret must be at least 16 characters long.");
        }

        if (settings.requireForwardingConfig()) {
            switch (settings.proxyMode()) {
                case VELOCITY -> {
                    Path paperGlobal = serverRoot.resolve("config/paper-global.yml");
                    if (!Files.exists(paperGlobal)) {
                        errors.add("config/paper-global.yml not found; cannot verify Paper Velocity forwarding.");
                    } else {
                        YamlConfiguration pg = YamlConfiguration.loadConfiguration(paperGlobal.toFile());
                        if (!pg.getBoolean("proxies.velocity.enabled", false)) {
                            errors.add("proxies.velocity.enabled is false in config/paper-global.yml while JustLogin proxy.mode=velocity.");
                        }
                        if (pg.getString("proxies.velocity.secret", "").isBlank()) {
                            errors.add("proxies.velocity.secret is blank in config/paper-global.yml.");
                        }
                    }
                }
                case BUNGEE -> {
                    Path spigot = serverRoot.resolve("spigot.yml");
                    if (!Files.exists(spigot)) {
                        errors.add("spigot.yml not found; cannot verify settings.bungeecord.");
                    } else {
                        YamlConfiguration sp = YamlConfiguration.loadConfiguration(spigot.toFile());
                        if (!sp.getBoolean("settings.bungeecord", false)) {
                            errors.add("settings.bungeecord is false in spigot.yml while JustLogin proxy.mode=bungee.");
                        } else {
                            warnings.add("Using legacy BungeeCord forwarding: firewall backend ports and install BungeeGuard.");
                        }
                    }
                }
                case STANDALONE -> {}
            }
        }

        return new CheckResult(errors.isEmpty(), errors, warnings);
    }

    public static boolean isPaperProxyForwardingEnabled(Path serverRoot) {
        if (serverRoot == null) return false;
        Path paperGlobal = serverRoot.resolve("config/paper-global.yml");
        if (Files.exists(paperGlobal)) {
            YamlConfiguration pg = YamlConfiguration.loadConfiguration(paperGlobal.toFile());
            if (pg.getBoolean("proxies.velocity.enabled", false)) {
                return true;
            }
        }
        Path spigot = serverRoot.resolve("spigot.yml");
        if (Files.exists(spigot)) {
            YamlConfiguration sp = YamlConfiguration.loadConfiguration(spigot.toFile());
            if (sp.getBoolean("settings.bungeecord", false)) {
                return true;
            }
        }
        return false;
    }
}

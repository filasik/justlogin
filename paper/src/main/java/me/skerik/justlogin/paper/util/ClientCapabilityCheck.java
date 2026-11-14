package me.skerik.justlogin.paper.util;

import java.lang.reflect.Method;
import java.util.UUID;
import org.bukkit.Bukkit;
import org.bukkit.plugin.Plugin;
import org.jspecify.annotations.Nullable;

/**
 * Optional soft integration checks for Bedrock (Floodgate) and legacy Java clients (ViaVersion &lt; 1.21.7 / protocol 771)
 * without hard compile dependencies.
 */
public final class ClientCapabilityCheck {

    /** Minecraft 1.21.7 protocol version (first version introducing Dialogs). */
    public static final int PROTOCOL_1_21_7 = 771;

    private final @Nullable Object floodgateApi;
    private final @Nullable Method isFloodgatePlayer;
    private final @Nullable Object viaApi;
    private final @Nullable Method getPlayerVersion;

    public ClientCapabilityCheck() {
        Object fg = null;
        Method fgMethod = null;
        Plugin fgPlugin = Bukkit.getPluginManager().getPlugin("floodgate");
        if (fgPlugin != null) {
            try {
                Class<?> apiClass = Class.forName("org.geysermc.floodgate.api.FloodgateApi");
                fg = apiClass.getMethod("getInstance").invoke(null);
                fgMethod = apiClass.getMethod("isFloodgatePlayer", UUID.class);
            } catch (Throwable ignored) {
                fg = null;
                fgMethod = null;
            }
        }
        this.floodgateApi = fg;
        this.isFloodgatePlayer = fgMethod;

        Object via = null;
        Method viaMethod = null;
        Plugin viaPlugin = Bukkit.getPluginManager().getPlugin("ViaVersion");
        if (viaPlugin != null) {
            try {
                Class<?> viaClass = Class.forName("com.viaversion.viaversion.api.Via");
                via = viaClass.getMethod("getAPI").invoke(null);
                viaMethod = via.getClass().getMethod("getPlayerVersion", UUID.class);
            } catch (Throwable ignored) {
                via = null;
                viaMethod = null;
            }
        }
        this.viaApi = via;
        this.getPlayerVersion = viaMethod;
    }

    public boolean supportsDialogs(@Nullable UUID uuid) {
        if (uuid == null) return true;
        if (isFloodgate(uuid)) return false;
        int proto = viaProtocolVersion(uuid);
        return proto < 0 || proto >= PROTOCOL_1_21_7;
    }

    public boolean isFloodgate(@Nullable UUID uuid) {
        if (uuid == null || floodgateApi == null || isFloodgatePlayer == null) return false;
        try {
            return Boolean.TRUE.equals(isFloodgatePlayer.invoke(floodgateApi, uuid));
        } catch (Throwable ignored) {
            return false;
        }
    }

    public int viaProtocolVersion(@Nullable UUID uuid) {
        if (uuid == null || viaApi == null || getPlayerVersion == null) return -1;
        try {
            Object res = getPlayerVersion.invoke(viaApi, uuid);
            return res instanceof Integer i ? i : -1;
        } catch (Throwable ignored) {
            return -1;
        }
    }
}

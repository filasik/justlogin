package me.skerik.justlogin.paper.totp;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Optional;
import org.bukkit.Bukkit;
import org.bukkit.Material;
import org.bukkit.entity.Player;
import org.bukkit.inventory.ItemStack;

/** Mojang-mapped Paper adapter. Never allocates a server map or modifies a real inventory slot. */
final class QrMapPackets {
    private final Constructor<?> mapId;
    private final Constructor<?> patch;
    private final Constructor<?> mapPacket;
    private final Constructor<?> slotPacket;
    private final Method itemCopy;
    private final Method setComponent;
    private final Object mapComponent;
    private final Method getHandle;
    private final Field connection;
    private final Method send;

    QrMapPackets() throws ReflectiveOperationException {
        Class<?> id = Class.forName("net.minecraft.world.level.saveddata.maps.MapId");
        Class<?> patchType = Class.forName("net.minecraft.world.level.saveddata.maps.MapItemSavedData$MapPatch");
        Class<?> stack = Class.forName("net.minecraft.world.item.ItemStack");
        Class<?> component = Class.forName("net.minecraft.core.component.DataComponentType");
        mapId = id.getConstructor(int.class);
        patch = patchType.getConstructor(int.class, int.class, int.class, int.class, byte[].class);
        mapPacket = Class.forName("net.minecraft.network.protocol.game.ClientboundMapItemDataPacket")
                .getConstructor(id, byte.class, boolean.class, Optional.class, Optional.class);
        slotPacket = Class.forName("net.minecraft.network.protocol.game.ClientboundSetPlayerInventoryPacket")
                .getConstructor(int.class, stack);
        String craft = Bukkit.getServer().getClass().getPackageName();
        itemCopy = Class.forName(craft + ".inventory.CraftItemStack").getMethod("asNMSCopy", ItemStack.class);
        setComponent = stack.getMethod("set", component, Object.class);
        mapComponent = Class.forName("net.minecraft.core.component.DataComponents").getField("MAP_ID").get(null);
        getHandle = Class.forName(craft + ".entity.CraftPlayer").getMethod("getHandle");
        connection = Class.forName("net.minecraft.server.level.ServerPlayer").getField("connection");
        send = connection.getType().getMethod("send", Class.forName("net.minecraft.network.protocol.Packet"));
    }

    Object inventoryPacket(int slot, ItemStack item) throws ReflectiveOperationException {
        return slotPacket.newInstance(slot, itemCopy.invoke(null, item));
    }

    void show(Player player, int slot, int id, byte[] pixels) throws ReflectiveOperationException {
        Object stack = itemCopy.invoke(null, new ItemStack(Material.FILLED_MAP));
        setComponent.invoke(stack, mapComponent, mapId.newInstance(id));
        send(player, slotPacket.newInstance(slot, stack));
        sendPixels(player, id, pixels);
    }

    void erase(Player player, int id) throws ReflectiveOperationException {
        byte[] white = new byte[QrMapImage.SIZE * QrMapImage.SIZE];
        Arrays.fill(white, QrMapImage.WHITE);
        sendPixels(player, id, white);
    }

    private void sendPixels(Player player, int id, byte[] pixels) throws ReflectiveOperationException {
        Object update = patch.newInstance(0, 0, QrMapImage.SIZE, QrMapImage.SIZE, pixels.clone());
        send(player, mapPacket.newInstance(mapId.newInstance(id), (byte) 0, true,
                Optional.empty(), Optional.of(update)));
    }

    void send(Player player, Object packet) throws ReflectiveOperationException {
        send.invoke(connection.get(getHandle.invoke(player)), packet);
    }
}

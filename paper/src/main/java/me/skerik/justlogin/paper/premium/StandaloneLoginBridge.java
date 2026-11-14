package me.skerik.justlogin.paper.premium;

import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import net.kyori.adventure.key.Key;
import net.kyori.adventure.text.Component;
import org.bukkit.Bukkit;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.jspecify.annotations.Nullable;

/**
 * Isolated reflective bridge to Paper's internal Netty channel pipeline and login packets ({@code 1.21.7–26.x}).
 * Keeps all Paper/Mojang internal lookups in one place and fails gracefully if an unsupported fork is used.
 */
public final class StandaloneLoginBridge implements LoginBridge {

    private final KeyPair keyPair;
    private final byte[] publicKeyEncoded;

    private final Method addChannelListener;
    private final Method removeChannelListener;
    private final Class<?> listenerInterface;

    private final Class<?> helloPacketClass;
    private final Method helloNameMethod;
    private final Method helloProfileIdMethod;
    private final Constructor<?> helloCtor;

    private final Constructor<?> clientHelloCtor;
    private final boolean clientHelloTakesShouldAuth;

    private final Class<?> keyPacketClass;
    private final Method keyChallengeValidMethod;
    private final Method keySecretMethod;

    private final Class<?> connectionClass;
    private final Method connectionSetEncryptionKey;
    private final Field connectionChannelField;
    private final Field loginConnListenerField;
    private final Field loginListenerConnectionField;

    private final @Nullable Constructor<?> disconnectPacketCtor;
    private final @Nullable Method adventureAsVanilla;

    private StandaloneLoginBridge(
            KeyPair keyPair,
            Method addChannelListener,
            Method removeChannelListener,
            Class<?> listenerInterface,
            Class<?> helloPacketClass,
            Method helloNameMethod,
            Method helloProfileIdMethod,
            Constructor<?> helloCtor,
            Constructor<?> clientHelloCtor,
            boolean clientHelloTakesShouldAuth,
            Class<?> keyPacketClass,
            Method keyChallengeValidMethod,
            Method keySecretMethod,
            Class<?> connectionClass,
            Method connectionSetEncryptionKey,
            Field connectionChannelField,
            Field loginConnListenerField,
            Field loginListenerConnectionField,
            @Nullable Constructor<?> disconnectPacketCtor,
            @Nullable Method adventureAsVanilla
    ) {
        this.keyPair = keyPair;
        this.publicKeyEncoded = keyPair.getPublic().getEncoded();
        this.addChannelListener = addChannelListener;
        this.removeChannelListener = removeChannelListener;
        this.listenerInterface = listenerInterface;
        this.helloPacketClass = helloPacketClass;
        this.helloNameMethod = helloNameMethod;
        this.helloProfileIdMethod = helloProfileIdMethod;
        this.helloCtor = helloCtor;
        this.clientHelloCtor = clientHelloCtor;
        this.clientHelloTakesShouldAuth = clientHelloTakesShouldAuth;
        this.keyPacketClass = keyPacketClass;
        this.keyChallengeValidMethod = keyChallengeValidMethod;
        this.keySecretMethod = keySecretMethod;
        this.connectionClass = connectionClass;
        this.connectionSetEncryptionKey = connectionSetEncryptionKey;
        this.connectionChannelField = connectionChannelField;
        this.loginConnListenerField = loginConnListenerField;
        this.loginListenerConnectionField = loginListenerConnectionField;
        this.disconnectPacketCtor = disconnectPacketCtor;
        this.adventureAsVanilla = adventureAsVanilla;
    }

    public static @Nullable StandaloneLoginBridge tryCreate(Logger logger) {
        try {
            Class<?> holderClass = Class.forName("io.papermc.paper.network.ChannelInitializeListenerHolder");
            Class<?> listenerIface = Class.forName("io.papermc.paper.network.ChannelInitializeListener");
            Method addListener = holderClass.getMethod("addListener", Key.class, listenerIface);
            Method removeListener = holderClass.getMethod("removeListener", Key.class);

            Class<?> helloClass = Class.forName("net.minecraft.network.protocol.login.ServerboundHelloPacket");
            Method helloName = findFirstMethod(helloClass, "name", "getName");
            Method helloUuid = findFirstMethod(helloClass, "profileId", "getProfileId");
            Constructor<?> helloCtor = helloClass.getConstructor(String.class, UUID.class);

            Class<?> clientHelloClass = Class.forName("net.minecraft.network.protocol.login.ClientboundHelloPacket");
            Constructor<?> clientHelloCtor;
            boolean takesShouldAuth;
            try {
                clientHelloCtor = clientHelloClass.getConstructor(String.class, byte[].class, byte[].class, boolean.class);
                takesShouldAuth = true;
            } catch (NoSuchMethodException e) {
                clientHelloCtor = clientHelloClass.getConstructor(String.class, byte[].class, byte[].class);
                takesShouldAuth = false;
            }

            Class<?> keyClass = Class.forName("net.minecraft.network.protocol.login.ServerboundKeyPacket");
            Method keyChallengeValid = keyClass.getMethod("isChallengeValid", byte[].class, PrivateKey.class);
            Method keySecret = keyClass.getMethod("getSecretKey", PrivateKey.class);

            Class<?> connClass = Class.forName("net.minecraft.network.Connection");
            Method setEncKey = connClass.getMethod("setEncryptionKey", SecretKey.class);
            Field connChannel = findFieldByType(connClass, Channel.class);

            Class<?> paperLoginConnClass = Class.forName("io.papermc.paper.connection.PaperPlayerLoginConnection");
            Class<?> serverLoginListenerClass = Class.forName("net.minecraft.server.network.ServerLoginPacketListenerImpl");
            Field loginConnListener = findFieldByType(paperLoginConnClass, serverLoginListenerClass);
            Field loginListenerConn = findFieldByType(serverLoginListenerClass, connClass);

            KeyPair serverKeyPair = resolveServerKeyPair();

            Constructor<?> disconnectCtor = null;
            Method asVanilla = null;
            try {
                Class<?> nmsComp = Class.forName("net.minecraft.network.chat.Component");
                Class<?> discClass = Class.forName("net.minecraft.network.protocol.login.ClientboundLoginDisconnectPacket");
                Class<?> advClass = Class.forName("io.papermc.paper.adventure.PaperAdventure");
                disconnectCtor = discClass.getConstructor(nmsComp);
                asVanilla = advClass.getMethod("asVanilla", Component.class);
            } catch (Throwable ignored) {
                disconnectCtor = null;
                asVanilla = null;
            }

            return new StandaloneLoginBridge(
                    serverKeyPair,
                    addListener,
                    removeListener,
                    listenerIface,
                    helloClass,
                    helloName,
                    helloUuid,
                    helloCtor,
                    clientHelloCtor,
                    takesShouldAuth,
                    keyClass,
                    keyChallengeValid,
                    keySecret,
                    connClass,
                    setEncKey,
                    connChannel,
                    loginConnListener,
                    loginListenerConn,
                    disconnectCtor,
                    asVanilla
            );
        } catch (Throwable t) {
            logger.warning("Standalone Netty premium hook could not initialize on this server build ("
                    + t.getClass().getSimpleName() + ": " + t.getMessage() + "). Falling back to proxy/password mode.");
            return null;
        }
    }

    private static KeyPair resolveServerKeyPair() throws Exception {
        try {
            Object server = Bukkit.getServer();
            Method getMcServer = server.getClass().getMethod("getServer");
            Object mcServer = getMcServer.invoke(server);
            Method getKeyPair = mcServer.getClass().getMethod("getKeyPair");
            Object kpObj = getKeyPair.invoke(mcServer);
            if (kpObj instanceof KeyPair kp && kp.getPublic() != null && kp.getPrivate() != null) {
                return kp;
            }
        } catch (Throwable ignored) {
        }
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(1024);
        return gen.generateKeyPair();
    }

    private static Method findFirstMethod(Class<?> owner, String... names) throws NoSuchMethodException {
        for (String name : names) {
            try {
                Method m = owner.getMethod(name);
                m.setAccessible(true);
                return m;
            } catch (NoSuchMethodException ignored) {
            }
        }
        throw new NoSuchMethodException(owner.getName() + " has none of " + String.join(", ", names));
    }

    private static Field findFieldByType(Class<?> owner, Class<?> targetType) throws NoSuchFieldException {
        for (Class<?> cur = owner; cur != null; cur = cur.getSuperclass()) {
            for (Field f : cur.getDeclaredFields()) {
                if (targetType.isAssignableFrom(f.getType())) {
                    f.setAccessible(true);
                    return f;
                }
            }
        }
        throw new NoSuchFieldException("No field of type " + targetType.getName() + " in " + owner.getName());
    }

    public void registerChannelListener(Key key, Consumer<Channel> onInit) throws Exception {
        Object proxy = Proxy.newProxyInstance(
                listenerInterface.getClassLoader(),
                new Class<?>[]{listenerInterface},
                (p, method, args) -> {
                    if ("afterInitChannel".equals(method.getName()) && args != null && args.length == 1
                            && args[0] instanceof Channel ch) {
                        onInit.accept(ch);
                        return null;
                    }
                    if ("equals".equals(method.getName()) && args != null && args.length == 1) {
                        return p == args[0];
                    }
                    if ("hashCode".equals(method.getName())) {
                        return System.identityHashCode(p);
                    }
                    if ("toString".equals(method.getName())) {
                        return "JustLoginChannelInitializeListener[" + key + "]";
                    }
                    return null;
                }
        );
        addChannelListener.invoke(null, key, proxy);
    }

    public void unregisterChannelListener(Key key) {
        try {
            removeChannelListener.invoke(null, key);
        } catch (Throwable ignored) {
        }
    }

    public byte[] publicKeyEncoded() {
        return publicKeyEncoded;
    }

    public @Nullable HelloPacketInfo inspectHelloPacket(Object msg) {
        if (!helloPacketClass.isInstance(msg)) return null;
        try {
            String name = (String) helloNameMethod.invoke(msg);
            UUID profileId = (UUID) helloProfileIdMethod.invoke(msg);
            if (name == null) return null;
            return new HelloPacketInfo(name, profileId);
        } catch (Throwable ignored) {
            return null;
        }
    }

    public Object newHelloPacket(String canonicalName, UUID mojangUuid, Object originalFallback) {
        try {
            return helloCtor.newInstance(canonicalName, mojangUuid);
        } catch (Throwable ignored) {
            return originalFallback;
        }
    }

    public Object newEncryptionRequestPacket(byte[] verifyToken) throws Exception {
        if (clientHelloTakesShouldAuth) {
            return clientHelloCtor.newInstance("", publicKeyEncoded, verifyToken, true);
        }
        return clientHelloCtor.newInstance("", publicKeyEncoded, verifyToken);
    }

    public boolean isKeyPacket(Object msg) {
        return keyPacketClass.isInstance(msg);
    }

    public @Nullable SecretKey decryptVerifiedKeyPacket(Object msg, byte[] expectedChallenge) {
        if (!keyPacketClass.isInstance(msg)) return null;
        try {
            PrivateKey priv = keyPair.getPrivate();
            Boolean valid = (Boolean) keyChallengeValidMethod.invoke(msg, expectedChallenge, priv);
            if (!Boolean.TRUE.equals(valid)) {
                return null;
            }
            return (SecretKey) keySecretMethod.invoke(msg, priv);
        } catch (Throwable ignored) {
            return null;
        }
    }

    public void enableEncryption(Channel channel, SecretKey secretKey) throws Exception {
        Object packetHandler = channel.pipeline().get("packet_handler");
        if (packetHandler == null || !connectionClass.isInstance(packetHandler)) {
            throw new IllegalStateException("Missing net.minecraft.network.Connection packet_handler on channel");
        }
        connectionSetEncryptionKey.invoke(packetHandler, secretKey);
    }

    public @Nullable Channel extractChannel(AsyncPlayerPreLoginEvent event) {
        try {
            Object loginConn = event.getConnection();
            Object listener = loginConnListenerField.get(loginConn);
            if (listener == null) return null;
            Object conn = loginListenerConnectionField.get(listener);
            if (conn == null) return null;
            return (Channel) connectionChannelField.get(conn);
        } catch (Throwable ignored) {
            return null;
        }
    }

    public void sendDisconnect(ChannelHandlerContext ctx, Component message) {
        if (disconnectPacketCtor != null && adventureAsVanilla != null && ctx.channel().isActive()) {
            try {
                Object nmsComp = adventureAsVanilla.invoke(null, message);
                Object pkt = disconnectPacketCtor.newInstance(nmsComp);
                ctx.channel().writeAndFlush(pkt).addListener(ChannelFutureListener.CLOSE);
                return;
            } catch (Throwable ignored) {
            }
        }
        ctx.close();
    }
}

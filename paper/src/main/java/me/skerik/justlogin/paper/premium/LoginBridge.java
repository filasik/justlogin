package me.skerik.justlogin.paper.premium;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import java.util.UUID;
import java.util.function.Consumer;
import javax.crypto.SecretKey;
import net.kyori.adventure.key.Key;
import net.kyori.adventure.text.Component;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.jspecify.annotations.Nullable;

/**
 * Abstraction over Paper's internal Netty channel pipeline and login packets so
 * {@link StandalonePremiumManager} can run without hard NMS compile dependencies and be unit-tested.
 */
public interface LoginBridge {

    record HelloPacketInfo(String username, @Nullable UUID profileId) {
    }

    void registerChannelListener(Key key, Consumer<Channel> onInit) throws Exception;

    void unregisterChannelListener(Key key);

    byte[] publicKeyEncoded();

    @Nullable HelloPacketInfo inspectHelloPacket(Object msg);

    Object newHelloPacket(String canonicalName, UUID mojangUuid, Object originalFallback);

    Object newEncryptionRequestPacket(byte[] verifyToken) throws Exception;

    boolean isKeyPacket(Object msg);

    @Nullable SecretKey decryptVerifiedKeyPacket(Object msg, byte[] expectedChallenge);

    void enableEncryption(Channel channel, SecretKey secretKey) throws Exception;

    @Nullable Channel extractChannel(AsyncPlayerPreLoginEvent event);

    void sendDisconnect(ChannelHandlerContext ctx, Component message);
}

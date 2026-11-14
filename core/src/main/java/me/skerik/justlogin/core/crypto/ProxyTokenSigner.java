package me.skerik.justlogin.core.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKey;
import org.jspecify.annotations.Nullable;

/**
 * Signs and verifies {@code justlogin:auth} proxy plugin messages with HMAC-SHA256, timestamp, and one-time nonce
 * (threat model #2: untrusted clients can forge raw plugin messages, so unsigned messages are always rejected).
 */
public final class ProxyTokenSigner {

    public static final String CHANNEL = "justlogin:auth";
    private static final int PROTOCOL_VERSION = 1;
    private static final long MAX_AGE_MILLIS = 30_000L;
    private static final SecureRandom RNG = new SecureRandom();

    public enum MessageType {
        AUTH_OK,
        PREMIUM_VERIFIED,
        LOGOUT,
        BACKEND_AUTH_OK
    }

    public record VerifiedMessage(
            MessageType type, long accountId, String nameLower, UUID gameUuid, long issuedAt, String targetServer) {
        public VerifiedMessage(MessageType type, long accountId, String nameLower, UUID gameUuid, long issuedAt) {
            this(type, accountId, nameLower, gameUuid, issuedAt, "");
        }
    }

    private final SecretKey proxySecret;
    private final Map<String, Long> seenNonces = new ConcurrentHashMap<>();

    public ProxyTokenSigner(SecretKey proxySecret) {
        this.proxySecret = proxySecret;
    }

    public byte[] sign(MessageType type, long accountId, String nameLower, UUID gameUuid, long nowMillis) {
        return sign(type, accountId, nameLower, gameUuid, "", nowMillis);
    }

    public byte[] sign(
            MessageType type, long accountId, String nameLower, UUID gameUuid, String targetServer, long nowMillis) {
        byte[] nonceBytes = new byte[16];
        RNG.nextBytes(nonceBytes);
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);

        byte[] payload = encodePayload(type, accountId, nameLower, gameUuid,
                targetServer == null ? "" : targetServer, nowMillis, nonce);
        byte[] hmac = IpHmac.hmacSha256(proxySecret, payload);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream out = new DataOutputStream(baos)) {
            out.writeInt(payload.length);
            out.write(payload);
            out.writeInt(hmac.length);
            out.write(hmac);
            out.flush();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public @Nullable VerifiedMessage verify(byte[] raw, long nowMillis) {
        return verify(raw, null, nowMillis);
    }

    public @Nullable VerifiedMessage verify(byte[] raw, @Nullable String expectedTargetServer, long nowMillis) {
        if (raw == null || raw.length < 16 || raw.length > 4096) return null;
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(raw))) {
            int payloadLen = in.readInt();
            if (payloadLen <= 0 || payloadLen > 2048) return null;
            byte[] payload = in.readNBytes(payloadLen);
            if (payload.length != payloadLen) return null;
            int hmacLen = in.readInt();
            if (hmacLen != 32) return null;
            byte[] receivedHmac = in.readNBytes(hmacLen);
            if (receivedHmac.length != 32 || in.read() != -1) return null;

            byte[] expectedHmac = IpHmac.hmacSha256(proxySecret, payload);
            if (!MessageDigest.isEqual(expectedHmac, receivedHmac)) return null;

            DataInputStream pin = new DataInputStream(new ByteArrayInputStream(payload));
            int version = pin.readByte() & 0xFF;
            if (version != PROTOCOL_VERSION) return null;
            int typeOrd = pin.readByte() & 0xFF;
            MessageType[] types = MessageType.values();
            if (typeOrd >= types.length) return null;
            long accountId = pin.readLong();
            String nameLower = pin.readUTF();
            UUID gameUuid = new UUID(pin.readLong(), pin.readLong());
            long issuedAt = pin.readLong();
            String nonce = pin.readUTF();
            String targetServer = pin.available() > 0 ? pin.readUTF() : "";

            if (expectedTargetServer != null && !expectedTargetServer.isEmpty()
                    && !targetServer.isEmpty() && !expectedTargetServer.equalsIgnoreCase(targetServer)) {
                return null;
            }
            if (Math.abs(nowMillis - issuedAt) > MAX_AGE_MILLIS) return null;
            pruneExpiredNonces(nowMillis);
            if (seenNonces.putIfAbsent(nonce, issuedAt + MAX_AGE_MILLIS) != null) return null;

            return new VerifiedMessage(types[typeOrd], accountId, nameLower, gameUuid, issuedAt, targetServer);
        } catch (IOException e) {
            return null;
        }
    }

    private void pruneExpiredNonces(long nowMillis) {
        if (seenNonces.size() < 256) return;
        Iterator<Map.Entry<String, Long>> it = seenNonces.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue() < nowMillis) it.remove();
        }
    }

    private static byte[] encodePayload(MessageType type, long accountId, String nameLower, UUID gameUuid,
                                        String targetServer, long issuedAt, String nonce) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream out = new DataOutputStream(baos)) {
            out.writeByte(PROTOCOL_VERSION);
            out.writeByte(type.ordinal());
            out.writeLong(accountId);
            out.writeUTF(nameLower.getBytes(StandardCharsets.UTF_8).length <= 64 ? nameLower : nameLower.substring(0, 32));
            out.writeLong(gameUuid.getMostSignificantBits());
            out.writeLong(gameUuid.getLeastSignificantBits());
            out.writeLong(issuedAt);
            out.writeUTF(nonce);
            String safeTarget = targetServer.getBytes(StandardCharsets.UTF_8).length <= 64
                    ? targetServer
                    : targetServer.substring(0, 32);
            out.writeUTF(safeTarget);
            out.flush();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}

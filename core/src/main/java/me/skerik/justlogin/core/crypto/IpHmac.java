package me.skerik.justlogin.core.crypto;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/** Keyed HMAC-SHA256 hashing for IP addresses (prevents brute-forcing IPv4 space from a DB dump). */
public final class IpHmac {

    private IpHmac() {
    }

    public static String hashIp(SecretKey key, String ip) {
        String normalized = normalizeIp(ip);
        byte[] digest = hmacSha256(key, normalized.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    public static boolean isUnknownIp(String raw) {
        String norm = normalizeIp(raw);
        return "unknown".equals(norm) || norm.isEmpty();
    }

    public static String normalizeIp(String raw) {
        if (raw == null || raw.isBlank()) return "unknown";
        String s = raw.strip().toLowerCase(Locale.ROOT);
        if (s.startsWith("/")) s = s.substring(1);
        if (s.startsWith("[") && s.endsWith("]")) s = s.substring(1, s.length() - 1);
        int zone = s.indexOf('%');
        if (zone > 0) s = s.substring(0, zone);
        return s;
    }

    public static String extractIp(SocketAddress address) {
        if (address instanceof InetSocketAddress inet) {
            InetAddress addr = inet.getAddress();
            return addr != null ? normalizeIp(addr.getHostAddress()) : normalizeIp(inet.getHostString());
        }
        return address == null ? "unknown" : normalizeIp(address.toString());
    }

    public static byte[] hmacSha256(SecretKey key, byte[] message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}

package me.skerik.justlogin.core.crypto;

import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * RFC 6238 TOTP (6 digits, 30s period, HMAC-SHA1) with time-step replay protection and single-use backup codes.
 */
public final class TotpService {

    public static final int PERIOD_SECONDS = 30;
    public static final int DIGITS = 6;

    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final String BACKUP_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private static final SecureRandom RNG = new SecureRandom();

    private TotpService() {
    }

    public record VerifyResult(boolean valid, long matchedStep) {
    }

    public static String generateSecret() {
        byte[] bytes = new byte[20];
        RNG.nextBytes(bytes);
        return encodeBase32(bytes);
    }

    public static String provisioningUri(String issuer, String accountName, String base32Secret) {
        String encIssuer = urlEncode(issuer);
        String encAccount = urlEncode(accountName);
        return "otpauth://totp/" + encIssuer + ":" + encAccount
                + "?secret=" + base32Secret
                + "&issuer=" + encIssuer
                + "&digits=" + DIGITS
                + "&period=" + PERIOD_SECONDS;
    }

    public static VerifyResult verifyCode(String base32Secret, String rawCode, long epochSeconds, long lastUsedStep, int windowSteps) {
        if (rawCode == null) return new VerifyResult(false, -1);
        String code = rawCode.replaceAll("\\s+", "");
        if (code.length() != DIGITS || !code.chars().allMatch(Character::isDigit)) {
            return new VerifyResult(false, -1);
        }
        byte[] secretBytes = decodeBase32(base32Secret);
        long currentStep = Math.floorDiv(epochSeconds, PERIOD_SECONDS);
        int window = Math.max(0, Math.min(3, windowSteps));
        byte[] candidateBytes = code.getBytes(StandardCharsets.US_ASCII);

        long matched = -1;
        for (int offset = -window; offset <= window; offset++) {
            long step = currentStep + offset;
            if (step < 0) continue;
            String expected = generateCodeForStep(secretBytes, step);
            if (MessageDigest.isEqual(candidateBytes, expected.getBytes(StandardCharsets.US_ASCII))) {
                matched = step;
                break;
            }
        }
        if (matched < 0) return new VerifyResult(false, -1);
        // Replay protection (threat model #11): reject codes from the same or older time step already consumed
        if (matched <= lastUsedStep) return new VerifyResult(false, -1);
        return new VerifyResult(true, matched);
    }

    public static String generateCodeForStep(byte[] secretBytes, long step) {
        try {
            byte[] counter = ByteBuffer.allocate(8).putLong(step).array();
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secretBytes, "HmacSHA1"));
            byte[] hmac = mac.doFinal(counter);
            int offset = hmac[hmac.length - 1] & 0x0F;
            int binary = ((hmac[offset] & 0x7F) << 24)
                    | ((hmac[offset + 1] & 0xFF) << 16)
                    | ((hmac[offset + 2] & 0xFF) << 8)
                    | (hmac[offset + 3] & 0xFF);
            int otp = binary % 1_000_000;
            return String.format(Locale.ROOT, "%06d", otp);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA1 unavailable", e);
        }
    }

    public static List<String> generateBackupCodes(int count) {
        List<String> codes = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            StringBuilder sb = new StringBuilder(9);
            for (int j = 0; j < 8; j++) {
                if (j == 4) sb.append('-');
                sb.append(BACKUP_ALPHABET.charAt(RNG.nextInt(BACKUP_ALPHABET.length())));
            }
            codes.add(sb.toString());
        }
        return codes;
    }

    public static String hashBackupCode(SecretKey hmacKey, String rawCode) {
        String normalized = normalizeBackupCode(rawCode);
        byte[] mac = IpHmac.hmacSha256(hmacKey, ("backup:" + normalized).getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(mac);
    }

    public static boolean matchesBackupCode(SecretKey hmacKey, String rawCode, String storedHash) {
        String normalized = normalizeBackupCode(rawCode);
        if (normalized.length() < 6) return false;
        String computed = hashBackupCode(hmacKey, normalized);
        return IpHmac.constantTimeEquals(computed, storedHash);
    }

    public static String normalizeBackupCode(String raw) {
        return raw == null ? "" : raw.replaceAll("[\\s-]+", "").toUpperCase(Locale.ROOT);
    }

    public static String encodeBase32(byte[] data) {
        StringBuilder out = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                out.append(BASE32.charAt((buffer >> (bitsLeft - 5)) & 0x1F));
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            out.append(BASE32.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        }
        return out.toString();
    }

    public static byte[] decodeBase32(String input) {
        if (input == null || input.isBlank()) throw new IllegalArgumentException("Empty base32 secret");
        String clean = input.strip().replace("=", "").replaceAll("\\s+", "").toUpperCase(Locale.ROOT);
        byte[] out = new byte[clean.length() * 5 / 8];
        int buffer = 0;
        int bitsLeft = 0;
        int index = 0;
        for (int i = 0; i < clean.length(); i++) {
            int val = BASE32.indexOf(clean.charAt(i));
            if (val < 0) throw new IllegalArgumentException("Invalid Base32 char");
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                out[index++] = (byte) ((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        return Arrays.copyOf(out, index);
    }

    private static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}

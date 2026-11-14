package me.skerik.justlogin.core.crypto;

import com.password4j.Argon2Function;
import com.password4j.BcryptFunction;
import com.password4j.Password;
import com.password4j.types.Argon2;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import me.skerik.justlogin.core.model.CoreSettings;
import me.skerik.justlogin.core.model.HashAlgorithm;
import org.jspecify.annotations.Nullable;

/**
 * Password hashing and constant-time verification.
 * Defaults to Argon2id; legacy formats (BCrypt, AuthMe SHA256, SHA512, PBKDF2-SHA256) verify and signal
 * {@link VerifyResult#needsRehash()} so accounts automatically upgrade on their next login.
 */
public final class PasswordHasher {

    private final int memoryKib;
    private final int iterations;
    private final int parallelism;
    private final Argon2Function defaultArgon2;

    public PasswordHasher(CoreSettings settings) {
        this(settings.argon2MemoryKib(), settings.argon2Iterations(), settings.argon2Parallelism());
    }

    public PasswordHasher(int memoryKib, int iterations, int parallelism) {
        this.memoryKib = Math.max(4096, memoryKib);
        this.iterations = Math.max(1, iterations);
        this.parallelism = Math.max(1, parallelism);
        this.defaultArgon2 = Argon2Function.getInstance(
                this.memoryKib, this.iterations, this.parallelism, 32, Argon2.ID, Argon2Function.ARGON2_VERSION_13);
    }

    public record HashedPassword(String hash, HashAlgorithm algorithm) {
    }

    public record VerifyResult(boolean valid, boolean needsRehash) {
        public static final VerifyResult INVALID = new VerifyResult(false, false);
    }

    public HashedPassword hash(char[] password) {
        String encoded = Password.hash(CharBuffer.wrap(password)).addRandomSalt(16).with(defaultArgon2).getResult();
        return new HashedPassword(encoded, HashAlgorithm.ARGON2ID);
    }

    public VerifyResult verify(char[] password, @Nullable String storedHash, HashAlgorithm declaredAlgo) {
        if (password == null || password.length == 0 || storedHash == null || storedHash.isBlank()) {
            return VerifyResult.INVALID;
        }
        String normalized = normalizeLegacyHash(storedHash.strip(), null, null);
        HashAlgorithm effective = detectAlgorithm(normalized, declaredAlgo);
        return switch (effective) {
            case ARGON2ID -> verifyArgon2(password, normalized);
            case BCRYPT -> verifyBcrypt(password, normalized);
            case AUTHME_SHA256 -> new VerifyResult(verifyAuthMeSha256(password, normalized), true);
            case SHA512 -> new VerifyResult(verifySaltedDigest(password, normalized, "$SHA512$", "SHA-512"), true);
            case PBKDF2_SHA256 -> new VerifyResult(verifyPbkdf2Sha256(password, normalized), true);
            case NONE -> VerifyResult.INVALID;
        };
    }

    public static HashAlgorithm detectAlgorithm(String storedHash, HashAlgorithm fallback) {
        if (storedHash == null || storedHash.isBlank()) return fallback;
        String normalized = normalizeLegacyHash(storedHash.strip(), null, null);
        if (normalized.startsWith("$argon2")) return HashAlgorithm.ARGON2ID;
        if (normalized.startsWith("$2a$") || normalized.startsWith("$2b$")
                || normalized.startsWith("$2x$") || normalized.startsWith("$2y$")) {
            return HashAlgorithm.BCRYPT;
        }
        if (normalized.startsWith("$SHA$")) return HashAlgorithm.AUTHME_SHA256;
        if (normalized.startsWith("$SHA512$")) return HashAlgorithm.SHA512;
        if (normalized.startsWith("pbkdf2_sha256$") || normalized.startsWith("$pbkdf2-sha256$")) {
            return HashAlgorithm.PBKDF2_SHA256;
        }
        return fallback;
    }

    /**
     * Normalizes legacy password hash strings across AuthMe, LibreLogin (BCrypt-2A, Argon-2ID, SHA-256, SHA-512),
     * LoginSecurity, nLogin (including reversed {@code $SHA512$<hash>$<salt>}), LimboAuth, JPremium, and Authy
     * into canonical formats recognized by {@link #detectAlgorithm(String, HashAlgorithm)}.
     */
    public static String normalizeLegacyHash(
            String rawHash, @Nullable String separateSalt, @Nullable String algoHint) {
        if (rawHash == null || rawHash.isBlank()) return "";
        String h = rawHash.strip();
        String salt = separateSalt == null ? "" : separateSalt.strip();
        String algoUpper = algoHint == null ? "" : algoHint.strip().toUpperCase(Locale.ROOT);

        // 1. LibreLogin Argon-2ID split format: "<version>,<iterations>,<memory>$<base64Hash>" + base64 salt
        if (!h.startsWith("$") && h.contains("$") && !salt.isEmpty()) {
            int dollar = h.indexOf('$');
            String meta = h.substring(0, dollar);
            String restPart = h.substring(dollar + 1);
            if (meta.matches("^\\d+,\\d+,\\d+$") && !restPart.isEmpty()) {
                String[] parts = meta.split(",");
                String cleanSalt = stripBase64Padding(salt);
                String cleanHash = stripBase64Padding(restPart);
                return "$argon2id$v=" + parts[0] + "$m=" + parts[2] + ",t=" + parts[1] + ",p=1$"
                        + cleanSalt + "$" + cleanHash;
            }
            // 2. LibreLogin BCrypt-2A split format: "<cost>$<31-char-hash>" + 22-char salt
            if (meta.matches("^\\d{2}$") && !restPart.isEmpty()) {
                String ver = "2a";
                if (algoUpper.startsWith("BCRYPT-") && algoUpper.length() == 9) {
                    ver = algoUpper.substring("BCRYPT-".length()).toLowerCase(Locale.ROOT);
                }
                return "$" + ver + "$" + meta + "$" + salt + restPart;
            }
        }

        // 3. JPremium BCrypt format: "BCRYPT$<cost>$<salt+hash>"
        if (h.regionMatches(true, 0, "BCRYPT$", 0, "BCRYPT$".length())) {
            return "$2a$" + h.substring("BCRYPT$".length());
        }

        // 4. Prefixed SHA-256 / SHA-512 variants ($SHA$, $SHA256$, SHA256$, SHA$, $SHA512$, SHA512$)
        String upper = h.toUpperCase(Locale.ROOT);
        if (upper.startsWith("$SHA$") || upper.startsWith("$SHA256$") || upper.startsWith("SHA256$")
                || upper.startsWith("SHA$") || upper.startsWith("$SHA512$") || upper.startsWith("SHA512$")) {
            String withoutLeadingDollar = h.startsWith("$") ? h.substring(1) : h;
            String[] parts = withoutLeadingDollar.split("\\$");
            String tag = parts[0].toUpperCase(Locale.ROOT);
            boolean hint512 = tag.equals("SHA512") || algoUpper.contains("512");
            if (parts.length == 3) {
                String p1 = parts[1];
                String p2 = parts[2];
                // Check for 128-hex SHA-512 (either standard salt$hash or nLogin's reversed hash$salt)
                if (isHexOfLength(p1, 128) && !isHexOfLength(p2, 128)) {
                    return "$SHA512$" + p2 + "$" + p1.toLowerCase(Locale.ROOT);
                }
                if (isHexOfLength(p2, 128)) {
                    return "$SHA512$" + p1 + "$" + p2.toLowerCase(Locale.ROOT);
                }
                // Check for 64-hex SHA-256 (either standard salt$hash or reversed hash$salt)
                if (isHexOfLength(p1, 64) && !isHexOfLength(p2, 64)) {
                    return "$SHA$" + p2 + "$" + p1.toLowerCase(Locale.ROOT);
                }
                if (isHexOfLength(p2, 64)) {
                    return "$SHA$" + p1 + "$" + p2.toLowerCase(Locale.ROOT);
                }
                return (hint512 ? "$SHA512$" : "$SHA$") + p1 + "$" + p2;
            } else if (parts.length == 2) {
                String digest = parts[1];
                boolean is512 = isHexOfLength(digest, 128) || hint512;
                if (isHexOfLength(digest, 64) || isHexOfLength(digest, 128)) {
                    return (is512 ? "$SHA512$" : "$SHA$") + salt + "$" + digest.toLowerCase(Locale.ROOT);
                }
            }
        }

        // 5. Raw hex digest (LibreLogin SHA-256/SHA-512, AuthMe with separate salt column, Authy unsalted SHA-256)
        if (!h.startsWith("$")) {
            if (isHexOfLength(h, 64)) {
                return "$SHA$" + salt + "$" + h.toLowerCase(Locale.ROOT);
            }
            if (isHexOfLength(h, 128)) {
                return "$SHA512$" + salt + "$" + h.toLowerCase(Locale.ROOT);
            }
        }

        return h;
    }

    private static String stripBase64Padding(String s) {
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '=') {
            end--;
        }
        return s.substring(0, end);
    }

    private static boolean isHexOfLength(String s, int expectedLen) {
        if (s == null || s.length() != expectedLen) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) return false;
        }
        return true;
    }

    private VerifyResult verifyArgon2(char[] password, String storedHash) {
        try {
            Argon2Function fn = Argon2Function.getInstanceFromHash(storedHash);
            boolean ok = Password.check(CharBuffer.wrap(password), storedHash).with(fn);
            if (!ok) return VerifyResult.INVALID;
            boolean outdated = fn.getVariant() != Argon2.ID
                    || fn.getMemory() < memoryKib
                    || fn.getIterations() < iterations
                    || fn.getParallelism() < parallelism;
            return new VerifyResult(true, outdated);
        } catch (RuntimeException e) {
            return VerifyResult.INVALID;
        }
    }

    private VerifyResult verifyBcrypt(char[] password, String storedHash) {
        try {
            BcryptFunction fn = BcryptFunction.getInstanceFromHash(storedHash);
            boolean ok = Password.check(CharBuffer.wrap(password), storedHash).with(fn);
            return new VerifyResult(ok, ok);
        } catch (RuntimeException e) {
            return VerifyResult.INVALID;
        }
    }

    /** AuthMe Reloaded SHA256 format: {@code $SHA$<salt>$<sha256(sha256(password) + salt)>}. */
    private static boolean verifyAuthMeSha256(char[] password, String storedHash) {
        return verifySaltedDigest(password, storedHash, "$SHA$", "SHA-256");
    }

    private static boolean verifySaltedDigest(char[] password, String storedHash, String prefix, String jcaAlgo) {
        if (!storedHash.startsWith(prefix)) return false;
        String rest = storedHash.substring(prefix.length());
        int sep = rest.indexOf('$');
        if (sep < 0 || sep >= rest.length() - 1) return false;
        String salt = rest.substring(0, sep);
        String expectedHex = rest.substring(sep + 1).toLowerCase(Locale.ROOT);
        int expectedLen = jcaAlgo.equals("SHA-512") ? 128 : 64;
        if (isHexOfLength(salt, expectedLen) && !isHexOfLength(expectedHex, expectedLen)) {
            String tmp = salt;
            salt = expectedHex;
            expectedHex = tmp.toLowerCase(Locale.ROOT);
        }
        byte[] pwBytes = charsToUtf8Bytes(password);
        try {
            MessageDigest md = MessageDigest.getInstance(jcaAlgo);
            String innerHex = HexFormat.of().formatHex(md.digest(pwBytes));
            if (salt.isEmpty()) {
                // Unsalted SHA-256 / SHA-512 (e.g. Authy, LibreLogin with null salt, or MoonAuth double-SHA)
                boolean plainMatch = IpHmac.constantTimeEquals(innerHex, expectedHex);
                String doubleHex = HexFormat.of().formatHex(md.digest(innerHex.getBytes(StandardCharsets.UTF_8)));
                boolean doubleMatch = IpHmac.constantTimeEquals(doubleHex, expectedHex);
                return plainMatch || doubleMatch;
            }
            byte[] combined = (innerHex + salt).getBytes(StandardCharsets.UTF_8);
            String outerHex = HexFormat.of().formatHex(md.digest(combined));
            if (IpHmac.constantTimeEquals(outerHex, expectedHex)) {
                return true;
            }
            // Fallback for single-round salted SHA(password + salt) used by some legacy plugins (LogIt, SHA256_P)
            byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);
            md.reset();
            md.update(pwBytes);
            String singleSuffixHex = HexFormat.of().formatHex(md.digest(saltBytes));
            return IpHmac.constantTimeEquals(singleSuffixHex, expectedHex);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(jcaAlgo + " unavailable", e);
        } finally {
            Arrays.fill(pwBytes, (byte) 0);
        }
    }

    /**
     * Supports both {@code pbkdf2_sha256$<iterations>$<salt>$<base64>} and AuthMe's
     * {@code pbkdf2_sha256$<iterations>$<salt>$<hex/base64>}.
     */
    private static boolean verifyPbkdf2Sha256(char[] password, String storedHash) {
        String[] parts = storedHash.startsWith("$")
                ? storedHash.substring(1).split("\\$")
                : storedHash.split("\\$");
        if (parts.length != 4) return false;
        int iters;
        try {
            iters = Integer.parseInt(parts[1]);
            if (iters < 1 || iters > 5_000_000) return false;
        } catch (NumberFormatException e) {
            return false;
        }
        String saltStr = parts[2];
        String expected = parts[3];

        try {
            byte[] expectedBytes;
            boolean isHex = expected.matches("^[0-9a-fA-F]+$") && expected.length() % 2 == 0 && expected.length() >= 32;
            if (isHex) {
                expectedBytes = HexFormat.of().parseHex(expected);
            } else {
                expectedBytes = Base64.getDecoder().decode(expected);
            }
            PBEKeySpec spec = new PBEKeySpec(password, saltStr.getBytes(StandardCharsets.UTF_8), iters, expectedBytes.length * 8);
            try {
                SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                byte[] derived = skf.generateSecret(spec).getEncoded();
                return MessageDigest.isEqual(derived, expectedBytes);
            } finally {
                spec.clearPassword();
            }
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            return false;
        }
    }

    private static byte[] charsToUtf8Bytes(char[] chars) {
        ByteBuffer bb = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
        byte[] out = new byte[bb.remaining()];
        bb.get(out);
        return out;
    }
}

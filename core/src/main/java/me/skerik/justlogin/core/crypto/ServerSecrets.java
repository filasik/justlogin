package me.skerik.justlogin.core.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Properties;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cryptographic keys stored outside the database ({@code secrets.key} with {@code 0600} permissions when supported).
 * Protects IP hashes, encrypted TOTP secrets, and signed proxy messages against a database leak.
 */
public final class ServerSecrets {

    private static final SecureRandom RNG = new SecureRandom();

    private final SecretKey hmacKey;
    private final SecretKey totpKey;
    private final SecretKey proxySecret;

    private ServerSecrets(byte[] hmacKeyBytes, byte[] totpKeyBytes, byte[] proxySecretBytes) {
        this.hmacKey = new SecretKeySpec(hmacKeyBytes, "HmacSHA256");
        this.totpKey = new SecretKeySpec(totpKeyBytes, "AES");
        this.proxySecret = new SecretKeySpec(proxySecretBytes, "HmacSHA256");
    }

    public static ServerSecrets generateEphemeral() {
        return new ServerSecrets(randomKey(32), randomKey(32), randomKey(32));
    }

    public static ServerSecrets fromKeys(byte[] hmacKeyBytes, byte[] totpKeyBytes, byte[] proxySecretBytes) {
        if (hmacKeyBytes.length < 16 || totpKeyBytes.length != 32 || proxySecretBytes.length < 16) {
            throw new IllegalArgumentException("Invalid key lengths");
        }
        return new ServerSecrets(hmacKeyBytes.clone(), totpKeyBytes.clone(), proxySecretBytes.clone());
    }

    public static ServerSecrets loadOrCreate(Path file) throws IOException {
        Properties props = new Properties();
        boolean changed = false;
        if (Files.exists(file)) {
            try (InputStream in = Files.newInputStream(file)) {
                props.load(in);
            }
        } else {
            Files.createDirectories(file.toAbsolutePath().getParent());
            changed = true;
        }
        byte[] hmac = decodeOrGenerate(props, "hmac-key");
        if (!props.containsKey("hmac-key")) {
            props.setProperty("hmac-key", Base64.getEncoder().encodeToString(hmac));
            changed = true;
        }
        byte[] totp = decodeOrGenerate(props, "totp-key");
        if (!props.containsKey("totp-key")) {
            props.setProperty("totp-key", Base64.getEncoder().encodeToString(totp));
            changed = true;
        }
        byte[] proxy = decodeOrGenerate(props, "proxy-secret");
        if (!props.containsKey("proxy-secret")) {
            props.setProperty("proxy-secret", Base64.getEncoder().encodeToString(proxy));
            changed = true;
        }
        if (changed) {
            Path parent = file.toAbsolutePath().getParent();
            Files.createDirectories(parent);
            Path tmp = Files.createTempFile(parent, "secrets-", ".tmp");
            restrictPermissions(tmp);
            try (OutputStream out = Files.newOutputStream(tmp)) {
                props.store(out, "JustLogin cryptographic secrets - NEVER share or commit this file");
            }
            try {
                Files.move(tmp, file,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                Files.move(tmp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            restrictPermissions(file);
        }
        return new ServerSecrets(hmac, totp, proxy);
    }

    private static byte[] decodeOrGenerate(Properties props, String key) {
        String raw = props.getProperty(key);
        if (raw == null || raw.isBlank()) return randomKey(32);
        byte[] decoded = Base64.getDecoder().decode(raw.strip());
        if (decoded.length != 32) {
            throw new IllegalStateException("Secret '" + key + "' in secrets.key must be 32 bytes (256 bits)");
        }
        return decoded;
    }

    private static byte[] randomKey(int bytes) {
        byte[] out = new byte[bytes];
        RNG.nextBytes(out);
        return out;
    }

    private static void restrictPermissions(Path file) {
        try {
            Set<PosixFilePermission> perms = EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(file, perms);
        } catch (UnsupportedOperationException | IOException ignored) {
            // Non-POSIX filesystems (Windows) ignore POSIX permissions
        }
    }

    public SecretKey hmacKey() {
        return hmacKey;
    }

    public SecretKey totpKey() {
        return totpKey;
    }

    public SecretKey proxySecret() {
        return proxySecret;
    }

    public static boolean isPlaceholderSecret(String sharedSecret) {
        if (sharedSecret == null) return true;
        String trimmed = sharedSecret.trim();
        return trimmed.isEmpty() || trimmed.toUpperCase(java.util.Locale.ROOT).startsWith("CHANGE-ME");
    }

    public ServerSecrets withProxySecret(String sharedSecret) {
        if (sharedSecret == null || sharedSecret.isBlank()) return this;
        if (isPlaceholderSecret(sharedSecret)) {
            throw new IllegalArgumentException("Refusing placeholder proxy shared-secret");
        }
        SecretKey base = new SecretKeySpec(
                sharedSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256");
        byte[] derived = IpHmac.hmacSha256(
                base, "justlogin:auth:v1".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return new ServerSecrets(hmacKey.getEncoded(), totpKey.getEncoded(), derived);
    }

    @Override
    public String toString() {
        return "ServerSecrets[redacted]";
    }
}

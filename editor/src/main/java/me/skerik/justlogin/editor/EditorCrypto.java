package me.skerik.justlogin.editor;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * End-to-end AES-256-GCM encryption for the web editor. The 256-bit key lives solely in the URL fragment
 * ({@code #key}) and in the plugin's memory until the session expires or is applied once.
 */
public final class EditorCrypto {

    private static final int KEY_BYTES = 32;
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RNG = new SecureRandom();

    private EditorCrypto() {
    }

    public record EncryptedEnvelope(int v, String alg, String iv, String ct) {
    }

    public static SecretKey generateKey() {
        byte[] raw = new byte[KEY_BYTES];
        RNG.nextBytes(raw);
        return new SecretKeySpec(raw, "AES");
    }

    public static String encodeKey(SecretKey key) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(key.getEncoded());
    }

    public static SecretKey decodeKey(String base64Url) {
        byte[] raw = Base64.getUrlDecoder().decode(base64Url.strip());
        if (raw.length != KEY_BYTES) throw new IllegalArgumentException("Editor key must be 256 bits");
        return new SecretKeySpec(raw, "AES");
    }

    public static EncryptedEnvelope encrypt(SecretKey key, String plaintextJson) {
        try {
            byte[] iv = new byte[IV_BYTES];
            RNG.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            byte[] ct = cipher.doFinal(plaintextJson.getBytes(StandardCharsets.UTF_8));
            Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
            return new EncryptedEnvelope(1, "AES-256-GCM", enc.encodeToString(iv), enc.encodeToString(ct));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Editor encryption failed", e);
        }
    }

    public static String decrypt(SecretKey key, EncryptedEnvelope env) {
        if (env == null || env.v() != 1 || !"AES-256-GCM".equals(env.alg())) {
            throw new IllegalArgumentException("Unsupported encrypted editor envelope");
        }
        try {
            Base64.Decoder dec = Base64.getUrlDecoder();
            byte[] iv = dec.decode(env.iv());
            byte[] ct = dec.decode(env.ct());
            if (iv.length != IV_BYTES) throw new IllegalArgumentException("Invalid GCM IV length");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            return new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Editor decryption failed (tampered or wrong key)", e);
        }
    }
}

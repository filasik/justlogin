package me.skerik.justlogin.core.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** AES-256-GCM encryption for storing TOTP secrets in the database with a key held outside the database. */
public final class AesGcmCrypto {

    private static final String PREFIX = "v1:";
    private static final String DEFAULT_KEY_ID = "k0:";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RNG = new SecureRandom();

    private AesGcmCrypto() {
    }

    public static String encrypt(SecretKey key, String plaintext) {
        try {
            byte[] iv = new byte[IV_BYTES];
            RNG.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
            return PREFIX + DEFAULT_KEY_ID + enc.encodeToString(iv) + ":" + enc.encodeToString(ct);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM encryption failed", e);
        }
    }

    public static String decrypt(SecretKey key, String encoded) {
        if (encoded == null || !encoded.startsWith(PREFIX)) {
            throw new IllegalArgumentException("Unsupported encrypted secret format");
        }
        String rest = encoded.substring(PREFIX.length());
        if (rest.startsWith("k") && rest.indexOf(':') > 1 && rest.indexOf(':') <= 8) {
            int firstSep = rest.indexOf(':');
            if (rest.indexOf(':', firstSep + 1) > firstSep + 1) {
                rest = rest.substring(firstSep + 1);
            }
        }
        int sep = rest.indexOf(':');
        if (sep <= 0) throw new IllegalArgumentException("Malformed encrypted secret");
        Base64.Decoder dec = Base64.getUrlDecoder();
        byte[] iv = dec.decode(rest.substring(0, sep));
        byte[] ct = dec.decode(rest.substring(sep + 1));
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            return new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM decryption failed (wrong key or tampered ciphertext)", e);
        }
    }
}

package me.skerik.justlogin.core.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.password4j.BcryptFunction;
import com.password4j.Password;
import com.password4j.types.Bcrypt;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import me.skerik.justlogin.core.model.HashAlgorithm;
import org.junit.jupiter.api.Test;

class PasswordHasherTest {

    @Test
    void argon2idHashesAndVerifiesWithoutRehash() {
        PasswordHasher hasher = new PasswordHasher(4096, 1, 1);
        PasswordHasher.HashedPassword hashed = hasher.hash("CorrectHorse99!".toCharArray());
        assertEquals(HashAlgorithm.ARGON2ID, hashed.algorithm());
        assertTrue(hashed.hash().startsWith("$argon2id$"));

        PasswordHasher.VerifyResult ok = hasher.verify("CorrectHorse99!".toCharArray(), hashed.hash(), hashed.algorithm());
        assertTrue(ok.valid());
        assertFalse(ok.needsRehash());

        PasswordHasher.VerifyResult bad = hasher.verify("WrongPassword!".toCharArray(), hashed.hash(), hashed.algorithm());
        assertFalse(bad.valid());
        assertFalse(bad.needsRehash());
    }

    @Test
    void upgradesWeakerArgon2ParametersOnLogin() {
        PasswordHasher weak = new PasswordHasher(4096, 1, 1);
        PasswordHasher.HashedPassword old = weak.hash("StrongPass!23".toCharArray());

        PasswordHasher stronger = new PasswordHasher(8192, 2, 1);
        PasswordHasher.VerifyResult res = stronger.verify("StrongPass!23".toCharArray(), old.hash(), HashAlgorithm.ARGON2ID);
        assertTrue(res.valid());
        assertTrue(res.needsRehash());
    }

    @Test
    void verifiesBcrypt2aAnd2yAndFlagsRehash() {
        PasswordHasher hasher = new PasswordHasher(4096, 1, 1);
        String bcrypt2y = Password.hash("MySecretPW1").with(BcryptFunction.getInstance(Bcrypt.Y, 6)).getResult();
        assertTrue(bcrypt2y.startsWith("$2y$"));

        PasswordHasher.VerifyResult res = hasher.verify("MySecretPW1".toCharArray(), bcrypt2y, HashAlgorithm.BCRYPT);
        assertTrue(res.valid());
        assertTrue(res.needsRehash());

        assertFalse(hasher.verify("WrongPW".toCharArray(), bcrypt2y, HashAlgorithm.BCRYPT).valid());
    }

    @Test
    void verifiesAuthMeSha256AndFlagsRehash() throws Exception {
        String salt = "a1b2c3d4e5f60718";
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String inner = HexFormat.of().formatHex(md.digest("Hunter2!Secret".getBytes(StandardCharsets.UTF_8)));
        String outer = HexFormat.of().formatHex(md.digest((inner + salt).getBytes(StandardCharsets.UTF_8)));
        String authMeHash = "$SHA$" + salt + "$" + outer;

        PasswordHasher hasher = new PasswordHasher(4096, 1, 1);
        assertEquals(HashAlgorithm.AUTHME_SHA256, PasswordHasher.detectAlgorithm(authMeHash, HashAlgorithm.NONE));

        PasswordHasher.VerifyResult ok = hasher.verify("Hunter2!Secret".toCharArray(), authMeHash, HashAlgorithm.AUTHME_SHA256);
        assertTrue(ok.valid());
        assertTrue(ok.needsRehash());

        assertFalse(hasher.verify("Wrong!".toCharArray(), authMeHash, HashAlgorithm.AUTHME_SHA256).valid());
        assertNotEquals(authMeHash, hasher.hash("Hunter2!Secret".toCharArray()).hash());
    }

    @Test
    void verifiesPbkdf2Sha256AndFlagsRehash() throws Exception {
        String salt = "somesalt123";
        PBEKeySpec spec = new PBEKeySpec("Pbkdf2Pass!9".toCharArray(), salt.getBytes(StandardCharsets.UTF_8), 1000, 256);
        byte[] raw = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        String encoded = "pbkdf2_sha256$1000$" + salt + "$" + Base64.getEncoder().encodeToString(raw);

        PasswordHasher hasher = new PasswordHasher(4096, 1, 1);
        PasswordHasher.VerifyResult ok = hasher.verify("Pbkdf2Pass!9".toCharArray(), encoded, HashAlgorithm.PBKDF2_SHA256);
        assertTrue(ok.valid());
        assertTrue(ok.needsRehash());
        assertFalse(hasher.verify("Nope".toCharArray(), encoded, HashAlgorithm.PBKDF2_SHA256).valid());
    }
}

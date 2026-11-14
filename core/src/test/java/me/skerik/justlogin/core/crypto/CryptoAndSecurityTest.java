package me.skerik.justlogin.core.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import me.skerik.justlogin.core.model.CoreSettings;
import me.skerik.justlogin.core.security.LoginRateLimiter;
import me.skerik.justlogin.core.security.PasswordPolicy;
import me.skerik.justlogin.core.security.UsernameValidator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CryptoAndSecurityTest {

    @TempDir Path dir;

    @Test
    void serverSecretsPersistAndEnforceRestrictivePermissions() throws Exception {
        Path keyFile = dir.resolve("secrets.key");
        ServerSecrets created = ServerSecrets.loadOrCreate(keyFile);
        ServerSecrets reloaded = ServerSecrets.loadOrCreate(keyFile);

        assertEquals(IpHmac.hashIp(created.hmacKey(), "1.2.3.4"), IpHmac.hashIp(reloaded.hmacKey(), "1.2.3.4"));
        assertEquals("[redacted]", created.toString().substring(created.toString().indexOf('[')));
        assertFalse(created.toString().contains("hmac"));

        try {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(keyFile);
            assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE), perms);
        } catch (UnsupportedOperationException ignored) {
            // non-POSIX FS
        }
    }

    @Test
    void ipHmacNormalizesAndDependsOnSecretKey() {
        ServerSecrets s1 = ServerSecrets.generateEphemeral();
        ServerSecrets s2 = ServerSecrets.generateEphemeral();

        String h1 = IpHmac.hashIp(s1.hmacKey(), "/192.168.1.10");
        String h1Same = IpHmac.hashIp(s1.hmacKey(), "192.168.1.10");
        String h2 = IpHmac.hashIp(s2.hmacKey(), "192.168.1.10");

        assertEquals(h1, h1Same);
        assertNotEquals(h1, h2);
        assertEquals("fe80::1", IpHmac.normalizeIp("[fe80::1%en0]"));
    }

    @Test
    void aesGcmRoundTripsAndRejectsTamperingOrWrongKey() {
        ServerSecrets s1 = ServerSecrets.generateEphemeral();
        ServerSecrets s2 = ServerSecrets.generateEphemeral();

        String ct1 = AesGcmCrypto.encrypt(s1.totpKey(), "JBSWY3DPEHPK3PXP");
        String ct2 = AesGcmCrypto.encrypt(s1.totpKey(), "JBSWY3DPEHPK3PXP");
        assertNotEquals(ct1, ct2);
        assertEquals("JBSWY3DPEHPK3PXP", AesGcmCrypto.decrypt(s1.totpKey(), ct1));

        assertThrows(IllegalStateException.class, () -> AesGcmCrypto.decrypt(s2.totpKey(), ct1));
        String tampered = ct1.substring(0, ct1.length() - 2) + "AA";
        assertThrows(RuntimeException.class, () -> AesGcmCrypto.decrypt(s1.totpKey(), tampered));
    }

    @Test
    void totpRejectsReplayWithinSameOrEarlierStep() {
        String secret = TotpService.generateSecret();
        byte[] raw = TotpService.decodeBase32(secret);
        long epochSec = 1_700_000_010L;
        long step = Math.floorDiv(epochSec, TotpService.PERIOD_SECONDS);
        String code = TotpService.generateCodeForStep(raw, step);

        TotpService.VerifyResult first = TotpService.verifyCode(secret, code, epochSec, -1L, 1);
        assertTrue(first.valid());
        assertEquals(step, first.matchedStep());

        // Threat #11: replaying the same code (or any code from step <= lastUsedStep) fails
        TotpService.VerifyResult replay = TotpService.verifyCode(secret, code, epochSec + 5, first.matchedStep(), 1);
        assertFalse(replay.valid());

        String nextCode = TotpService.generateCodeForStep(raw, step + 1);
        TotpService.VerifyResult next = TotpService.verifyCode(secret, nextCode, epochSec + 30, first.matchedStep(), 1);
        assertTrue(next.valid());
        assertEquals(step + 1, next.matchedStep());
    }

    @Test
    void backupCodesAreNormalizedAndHashedWithHmac() {
        ServerSecrets secrets = ServerSecrets.generateEphemeral();
        List<String> codes = TotpService.generateBackupCodes(4);
        assertEquals(4, codes.size());
        String first = codes.getFirst();
        String hash = TotpService.hashBackupCode(secrets.hmacKey(), first);
        assertTrue(TotpService.matchesBackupCode(secrets.hmacKey(), first.toLowerCase().replace("-", " "), hash));
        assertFalse(TotpService.matchesBackupCode(secrets.hmacKey(), "AAAA-BBBB", hash));
    }

    @Test
    void proxyTokenSignerRejectsTamperingExpiryAndReplay() {
        ServerSecrets secrets = ServerSecrets.generateEphemeral();
        ProxyTokenSigner signer = new ProxyTokenSigner(secrets.proxySecret());
        UUID uuid = UUID.randomUUID();
        long now = 1_700_000_000_000L;

        byte[] token = signer.sign(ProxyTokenSigner.MessageType.AUTH_OK, 42L, "filasik", uuid, now);
        ProxyTokenSigner.VerifiedMessage ok = signer.verify(token, now + 5000L);
        assertNotNull(ok);
        assertEquals(42L, ok.accountId());
        assertEquals("filasik", ok.nameLower());
        assertEquals(uuid, ok.gameUuid());

        // Threat #2: replay of exact same signed token (duplicate nonce) rejected
        assertNull(signer.verify(token, now + 6000L));

        // Expired token rejected
        byte[] old = signer.sign(ProxyTokenSigner.MessageType.AUTH_OK, 42L, "filasik", uuid, now);
        assertNull(signer.verify(old, now + 60_000L));

        // Tampered token rejected
        byte[] tampered = signer.sign(ProxyTokenSigner.MessageType.AUTH_OK, 42L, "filasik", uuid, now);
        tampered[tampered.length - 1] ^= 0x01;
        assertNull(signer.verify(tampered, now + 1000L));

        // Wrong secret rejected
        ProxyTokenSigner otherSigner = new ProxyTokenSigner(ServerSecrets.generateEphemeral().proxySecret());
        assertNull(otherSigner.verify(signer.sign(ProxyTokenSigner.MessageType.AUTH_OK, 42L, "filasik", uuid, now), now));
    }

    @Test
    void usernameAndPasswordPoliciesEnforceSecurityRules() {
        CoreSettings s = CoreSettings.defaults();
        assertTrue(UsernameValidator.isValid("Steve_123", s.usernamePattern()));
        assertFalse(UsernameValidator.isValid("ab", s.usernamePattern()));
        assertFalse(UsernameValidator.isValid("bad name", s.usernamePattern()));
        assertFalse(UsernameValidator.isValid("<script>", s.usernamePattern()));
        assertEquals("steve_123", UsernameValidator.normalizeLower("Steve_123"));

        assertEquals(PasswordPolicy.Violation.BLANK, PasswordPolicy.validate("   ".toCharArray(), "Steve", s));
        assertEquals(PasswordPolicy.Violation.TOO_SHORT, PasswordPolicy.validate("Abc12!".toCharArray(), "Steve", s));
        assertEquals(PasswordPolicy.Violation.SAME_AS_USERNAME, PasswordPolicy.validate("STEVE_123".toCharArray(), "steve_123", s));
        assertEquals(PasswordPolicy.Violation.COMMON_PASSWORD, PasswordPolicy.validate("password123".toCharArray(), "Steve", s));
        assertNull(PasswordPolicy.validate("T9!xK2#mZpQ".toCharArray(), "Steve", s));
    }

    @Test
    void rateLimiterIsolatesLockoutToUsernamePlusIp() {
        AtomicLong now = new AtomicLong(1_000_000L);
        LoginRateLimiter rl = new LoginRateLimiter(now::get);
        CoreSettings s = CoreSettings.defaults();

        for (int i = 0; i < s.maxLoginAttemptsPerAccountIp(); i++) {
            rl.recordFailure("victim", "attacker-ip", s);
        }
        // Attacker IP is locked out for victim
        assertFalse(rl.check("victim", "attacker-ip", s).allowed());
        // Threat #7: real owner on a different IP is NOT locked out
        assertTrue(rl.check("victim", "owner-ip", s).allowed());
        // Shared NAT IP isolation: another user on the same IP is not slowed after 3 typos by victim
        for (int i = 0; i < 4; i++) {
            rl.recordFailure("typo_user", "shared-nat-ip", s);
        }
        assertTrue(rl.check("innocent_user", "shared-nat-ip", s).allowed());

        // Threat #5: one IP spraying many accounts hits per-IP cap
        for (int i = 0; i < s.maxLoginAttemptsPerIp(); i++) {
            rl.recordFailure("user" + i, "spray-ip", s);
        }
        assertFalse(rl.check("otheruser", "spray-ip", s).allowed());

        // After lockout window expires, access returns
        now.addAndGet((s.lockoutSeconds() * 2000L) + 1000L);
        assertTrue(rl.check("victim", "attacker-ip", s).allowed());
    }

    @Test
    void hashingExecutorRejectsOverflowWithoutBlocking() throws Exception {
        try (HashingExecutor exec = new HashingExecutor(1, 1)) {
            CountDownLatch gate = new CountDownLatch(1);
            CountDownLatch running = new CountDownLatch(1);
            CompletableFuture<String> first = exec.submit(() -> {
                running.countDown();
                try {
                    gate.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                }
                return "done1";
            });
            assertTrue(running.await(2, TimeUnit.SECONDS));
            CompletableFuture<String> queued = exec.submit(() -> "done2");
            CompletableFuture<String> rejected = exec.submit(() -> "overflow");
            assertTrue(rejected.isCompletedExceptionally());
            gate.countDown();
            assertEquals("done1", first.join());
            assertEquals("done2", queued.join());
        }
    }
}

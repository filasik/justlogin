package me.skerik.justlogin.paper;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;
import me.skerik.justlogin.paper.auth.AuthSessionManager;
import org.junit.jupiter.api.Test;

final class TotpSetupLifecycleTest {
    @Test
    void cancellationReplacementAndDisconnectInvalidateSetupCallbacksAndSecrets() {
        AuthSessionManager sessions = new AuthSessionManager();
        UUID player = UUID.randomUUID();
        UUID first = sessions.beginTotpSetupRequest(player);
        sessions.putPendingTotpSetup(player, "secret-one", 100L);
        assertFalse(sessions.pendingTotpSetup(player).toString().contains("secret-one"));
        UUID second = sessions.beginTotpSetupRequest(player);
        assertFalse(sessions.isTotpSetupRequest(player, first));
        assertTrue(sessions.isTotpSetupRequest(player, second));
        assertNull(sessions.pendingTotpSetup(player));
        sessions.putPendingTotpSetup(player, "secret-two", 100L);
        sessions.cancelPendingTotpSetup(player);
        assertFalse(sessions.isTotpSetupRequest(player, second));
        assertNull(sessions.pendingTotpSetup(player));
        UUID third = sessions.beginTotpSetupRequest(player);
        sessions.putPendingTotpSetup(player, "secret-three", 100L);
        sessions.removePlayerSession(player);
        assertFalse(sessions.isTotpSetupRequest(player, third));
        assertNull(sessions.pendingTotpSetup(player));
    }

    @Test
    void confirmationConsumesOnceAndExpiredSecretsCannotBeConsumed() {
        AuthSessionManager sessions = new AuthSessionManager();
        UUID player = UUID.randomUUID();
        sessions.beginTotpSetupRequest(player);
        sessions.putPendingTotpSetup(player, "secret", 100L);
        assertNotNull(sessions.consumePendingTotpSetup(player, 99L));
        assertNull(sessions.consumePendingTotpSetup(player, 99L));
        sessions.putPendingTotpSetup(player, "secret", 100L);
        assertNull(sessions.consumePendingTotpSetup(player, 100L));
        assertNull(sessions.pendingTotpSetup(player));
        sessions.clearAll();
        assertNull(sessions.totpSetupRequest(player));
    }
    @Test
    void concurrentConfirmationsCannotConsumeTheSameSecretTwice() throws Exception {
        AuthSessionManager sessions = new AuthSessionManager();
        UUID player = UUID.randomUUID();
        sessions.beginTotpSetupRequest(player);
        sessions.putPendingTotpSetup(player, "secret", 100L);
        var start = new java.util.concurrent.CountDownLatch(1);
        try (var pool = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            var attempts = new java.util.ArrayList<java.util.concurrent.Future<Boolean>>();
            for (int i = 0; i < 16; i++) {
                attempts.add(pool.submit(() -> {
                    start.await();
                    return sessions.consumePendingTotpSetup(player, 99L) != null;
                }));
            }
            start.countDown();
            int consumed = 0;
            for (var result : attempts) if (result.get()) consumed++;
            assertEquals(1, consumed);
        }
    }
}

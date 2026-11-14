package me.skerik.justlogin.core.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.UUID;
import me.skerik.justlogin.core.model.HashAlgorithm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MigrationsTest {

    @TempDir Path dir;

    @Test
    void freshDatabaseReachesLatestAndMigratingAgainIsNoop() throws Exception {
        try (Database db = new Database(DbConfig.sqlite(dir.resolve("fresh.db"), 2))) {
            assertEquals(Migrations.latestVersion(), Migrations.migrate(db));
            assertEquals(Migrations.latestVersion(), Migrations.migrate(db));
        }
    }

    @Test
    void upgradesFromV2ToV3AndPersistsCustomSkinAcrossUpdatesAndMerge() throws Exception {
        try (Database db = new Database(DbConfig.sqlite(dir.resolve("upgrade.db"), 2))) {
            assertEquals(2, Migrations.migrate(db, 2));
            assertEquals(Migrations.latestVersion(), Migrations.migrate(db));

            AccountStore accounts = new AccountStore(db);
            var src = accounts.createAccount("source", "Source", UUID.randomUUID(), null, "$argon2id$a",
                    HashAlgorithm.ARGON2ID, null, false, 1000L, "ip1").join();
            var dst = accounts.createAccount("target", "Target", UUID.randomUUID(), null, "$argon2id$b",
                    HashAlgorithm.ARGON2ID, null, false, 1500L, "ip2").join();

            assertFalse(src.hasCustomSkin());
            accounts.updateCustomSkin(src.id(), "Notch", "SKIN_VAL", "SKIN_SIG", 2000L).join();
            var reloaded = accounts.findById(src.id()).join().orElseThrow();
            assertTrue(reloaded.hasCustomSkin());
            assertEquals("Notch", reloaded.skinOwner());
            assertEquals("SKIN_VAL", reloaded.skinValue());
            assertEquals("SKIN_SIG", reloaded.skinSignature());

            // Merge transfers saved custom skin when target has none
            var merged = accounts.mergeAccounts(src.id(), dst.id(), 3000L).join().orElseThrow();
            assertTrue(merged.hasCustomSkin());
            assertEquals("Notch", merged.skinOwner());

            accounts.clearCustomSkin(dst.id(), 4000L).join();
            var cleared = accounts.findById(dst.id()).join().orElseThrow();
            assertFalse(cleared.hasCustomSkin());
            assertNull(cleared.skinOwner());
        }
    }

    @Test
    void accountStorePreservesGameUuidAcrossPremiumConfirmAndCascadeDeletes() throws Exception {
        try (Database db = new Database(DbConfig.memory())) {
            Migrations.migrate(db);
            AccountStore accounts = new AccountStore(db);
            SessionStore sessions = new SessionStore(db);

            UUID gameUuid = UUID.randomUUID();
            UUID premUuid = UUID.randomUUID();
            var acc = accounts.createAccount("filasik", "Filasik", gameUuid, null, "$argon2id$x",
                    HashAlgorithm.ARGON2ID, null, true, 1000L, "iph").join();
            sessions.upsert(acc.id(), "iph", 999_999L).join();

            accounts.confirmPremium(acc.id(), premUuid, "filasiknew", "FilasikNew", 2000L).join();
            var reloaded = accounts.findByPremiumUuid(premUuid).join().orElseThrow();
            assertEquals(gameUuid, reloaded.gameUuid());
            assertEquals("FilasikNew", reloaded.lastName());
            assertTrue(reloaded.isPremiumConfirmed());

            assertTrue(accounts.deleteById(acc.id()).join());
            assertTrue(sessions.findValid(acc.id(), "iph", 2500L).join().isEmpty());
        }
    }
}

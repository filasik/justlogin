package me.skerik.justlogin.editor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import javax.crypto.SecretKey;
import me.skerik.justlogin.core.model.Account;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import org.jspecify.annotations.Nullable;

/**
 * Coordinates end-to-end encrypted web editor exports, short-lived in-memory sessions, diff previewing with
 * optimistic concurrency checks, and one-time confirmed application of bulk edits.
 */
public final class EditorService {

    public static final int DEFAULT_PAGE_SIZE = 500;
    public static final long DEFAULT_TTL_MILLIS = 30 * 60_000L;

    private static final Gson GSON = new GsonBuilder().serializeNulls().create();
    private static final SecureRandom RNG = new SecureRandom();

    public record ExportSessionResult(
            String sessionId,
            String blobKey,
            String editorUrl,
            int exportedCount,
            long totalAccounts,
            long expiresAt
    ) {
    }

    private record ActiveSession(
            String sessionId,
            SecretKey aesKey,
            Map<Long, SnapshotRow> snapshotById,
            long expiresAt
    ) {
    }

    private record SnapshotRow(String name, @Nullable Boolean premium, boolean forcePasswordChange, long updatedAt) {
    }

    private final AccountStore accounts;
    private final AuditStore audit;
    private final LongSupplier clock;
    private final Map<String, ActiveSession> sessions = new ConcurrentHashMap<>();
    private final Map<String, EditorModels.PendingEditPlan> pendingPlansByActor = new ConcurrentHashMap<>();

    public EditorService(AccountStore accounts, AuditStore audit, LongSupplier clock) {
        this.accounts = accounts;
        this.audit = audit;
        this.clock = clock;
    }

    public CompletableFuture<ExportSessionResult> createSession(
            int page, int pageSize, String webEditorUrl, BytebinClient relay, long ttlMillis) {
        int safePage = Math.max(1, page);
        int safeSize = Math.max(1, Math.min(2000, pageSize));
        int offset = (safePage - 1) * safeSize;

        return accounts.countAccounts()
                .thenCombine(accounts.listAccountsByLastLogin(offset, safeSize), (total, rows) -> {
                    long now = clock.getAsLong();
                    long expiresAt = now + Math.max(60_000L, ttlMillis);
                    String sessionId = generateSessionId();
                    SecretKey key = EditorCrypto.generateKey();

                    Map<Long, SnapshotRow> snapshot = new HashMap<>();
                    List<EditorModels.EditorAccount> exported = new ArrayList<>(rows.size());
                    for (Account a : rows) {
                        exported.add(EditorModels.EditorAccount.fromAccount(a));
                        snapshot.put(a.id(), new SnapshotRow(a.lastName(), a.premium(), a.forcePasswordChange(), a.updatedAt()));
                    }

                    EditorModels.EditorPayload payload = new EditorModels.EditorPayload(
                            1, sessionId, now, expiresAt, safePage, safeSize, total, exported);
                    String json = GSON.toJson(payload);
                    EditorCrypto.EncryptedEnvelope envelope = EditorCrypto.encrypt(key, json);
                    String envelopeJson = GSON.toJson(envelope);

                    return relay.upload(envelopeJson).thenApply(blobKey -> {
                        pruneExpired();
                        sessions.put(sessionId, new ActiveSession(sessionId, key, snapshot, expiresAt));

                        String base = !webEditorUrl.contains("?") && !webEditorUrl.endsWith("/")
                                ? webEditorUrl + "/"
                                : webEditorUrl;
                        String sep = base.contains("?") ? "&" : "?";
                        String fullUrl = base + sep + "session=" + sessionId + "&code=" + blobKey + "&relay=" + URLEncoder.encode(relay.relayUrl(), StandardCharsets.UTF_8) + "#" + EditorCrypto.encodeKey(key);
                        return new ExportSessionResult(sessionId, blobKey, fullUrl, exported.size(), total, expiresAt);
                    });
                })
                .thenCompose(f -> f);
    }

    /** Downloads and decrypts returned edits, verifies against current DB state, and stages a one-time diff plan. */
    public CompletableFuture<EditorModels.PendingEditPlan> prepareApply(
            String actorKey, String code, BytebinClient relay) {
        return relay.download(code).thenCompose(rawEnvelope -> {
            EditorCrypto.EncryptedEnvelope env = GSON.fromJson(rawEnvelope, EditorCrypto.EncryptedEnvelope.class);
            if (env == null) throw new IllegalArgumentException("Invalid encrypted payload");

            // Try matching an active session that can decrypt the returned blob
            long now = clock.getAsLong();
            pruneExpired();

            DecodedChanges decoded = findAndDecrypt(env, now);
            if (decoded == null) {
                throw new IllegalStateException("No active editor session matches this code (expired or already used)");
            }
            ActiveSession session = decoded.session();
            EditorModels.EditorChanges changes = decoded.changes();

            return buildPlan(session, code, changes).thenApply(plan -> {
                pendingPlansByActor.put(actorKey, plan);
                return plan;
            });
        });
    }

    public EditorModels.@Nullable PendingEditPlan getPendingPlan(String actorKey) {
        EditorModels.PendingEditPlan plan = pendingPlansByActor.get(actorKey);
        if (plan != null && plan.expiresAt() <= clock.getAsLong()) {
            pendingPlansByActor.remove(actorKey);
            return null;
        }
        return plan;
    }

    public CompletableFuture<EditorModels.ApplyReport> confirmAndApply(String actorKey, String actorName) {
        EditorModels.PendingEditPlan plan = pendingPlansByActor.remove(actorKey);
        if (plan == null || plan.expiresAt() <= clock.getAsLong()) {
            return CompletableFuture.failedFuture(new IllegalStateException("No pending editor changes to apply (or expired)"));
        }
        // Consume session immediately so codes cannot be reused (section 7)
        ActiveSession session = sessions.remove(plan.sessionId());
        if (session == null || session.expiresAt() <= clock.getAsLong()) {
            return CompletableFuture.failedFuture(new IllegalStateException("Editor session expired or already applied"));
        }

        return CompletableFuture.supplyAsync(() -> {
            int applied = 0;
            int conflicts = 0;
            int updatedCount = 0;
            int deletedCount = 0;
            List<Long> affectedIds = new ArrayList<>();
            List<String> affectedNames = new ArrayList<>();
            long now = clock.getAsLong();

            for (EditorModels.PlannedChange ch : plan.changes()) {
                boolean ok;
                if (ch.kind() == EditorModels.PlannedChange.ChangeKind.DELETE) {
                    ok = accounts.deleteIfUnchanged(ch.id(), ch.expectedUpdatedAt()).join();
                    if (ok) {
                        deletedCount++;
                        audit.record(now, actorName, "EDITOR_DELETE", ch.name(), "id=" + ch.id()).join();
                    }
                } else {
                    ok = accounts.applyEditorUpdateIfUnchanged(
                            ch.id(), ch.newPremium(), ch.newForcePasswordChange(), ch.expectedUpdatedAt(), now).join();
                    if (ok) {
                        updatedCount++;
                        audit.record(now, actorName, "EDITOR_UPDATE", ch.name(),
                                "premium=" + ch.newPremium() + ",forcePw=" + ch.newForcePasswordChange()).join();
                    }
                }
                if (ok) {
                    applied++;
                    affectedIds.add(ch.id());
                    affectedNames.add(ch.name());
                } else {
                    conflicts++;
                }
            }

            Map<String, Integer> breakdown = new LinkedHashMap<>();
            breakdown.put("updated", updatedCount);
            breakdown.put("deleted", deletedCount);
            return new EditorModels.ApplyReport(
                    applied, conflicts, breakdown, List.copyOf(affectedIds), List.copyOf(affectedNames));
        });
    }

    public void pruneExpired() {
        long now = clock.getAsLong();
        sessions.entrySet().removeIf(e -> e.getValue().expiresAt() <= now);
        pendingPlansByActor.entrySet().removeIf(e -> e.getValue().expiresAt() <= now);
    }

    private @Nullable DecodedChanges findAndDecrypt(EditorCrypto.EncryptedEnvelope env, long now) {
        for (ActiveSession s : sessions.values()) {
            if (s.expiresAt() <= now) continue;
            try {
                String json = EditorCrypto.decrypt(s.aesKey(), env);
                EditorModels.EditorChanges ch = GSON.fromJson(json, EditorModels.EditorChanges.class);
                if (ch != null && s.sessionId().equals(ch.sessionId())) {
                    return new DecodedChanges(s, ch);
                }
            } catch (RuntimeException ignored) {
                // Wrong session key for this blob
            }
        }
        return null;
    }

    private CompletableFuture<EditorModels.PendingEditPlan> buildPlan(
            ActiveSession session, String code, EditorModels.EditorChanges changes) {
        return CompletableFuture.supplyAsync(() -> {
            List<EditorModels.PlannedChange> planned = new ArrayList<>();
            List<EditorModels.ConflictEntry> conflicts = new ArrayList<>();

            List<Long> deletes = changes.deleteIds() == null ? List.of() : changes.deleteIds();
            for (Long id : deletes) {
                if (id == null) continue;
                SnapshotRow snap = session.snapshotById().get(id);
                if (snap == null) {
                    conflicts.add(new EditorModels.ConflictEntry(id, "#" + id, "not in exported snapshot"));
                    continue;
                }
                Optional<Account> currentOpt = accounts.findById(id).join();
                if (currentOpt.isEmpty()) {
                    conflicts.add(new EditorModels.ConflictEntry(id, snap.name(), "account already deleted"));
                    continue;
                }
                Account cur = currentOpt.get();
                if (cur.updatedAt() != snap.updatedAt()) {
                    conflicts.add(new EditorModels.ConflictEntry(id, cur.lastName(), "modified since export"));
                    continue;
                }
                planned.add(new EditorModels.PlannedChange(
                        id, cur.lastName(), EditorModels.PlannedChange.ChangeKind.DELETE,
                        cur.premium(), null, cur.forcePasswordChange(), false, snap.updatedAt()));
            }

            List<EditorModels.AccountUpdate> updates = changes.updates() == null ? List.of() : changes.updates();
            for (EditorModels.AccountUpdate u : updates) {
                if (deletes.contains(u.id())) continue;
                SnapshotRow snap = session.snapshotById().get(u.id());
                if (snap == null) {
                    conflicts.add(new EditorModels.ConflictEntry(u.id(), "#" + u.id(), "not in exported snapshot"));
                    continue;
                }
                Optional<Account> currentOpt = accounts.findById(u.id()).join();
                if (currentOpt.isEmpty()) {
                    conflicts.add(new EditorModels.ConflictEntry(u.id(), snap.name(), "account already deleted"));
                    continue;
                }
                Account cur = currentOpt.get();
                if (cur.updatedAt() != snap.updatedAt()) {
                    conflicts.add(new EditorModels.ConflictEntry(u.id(), cur.lastName(), "modified since export"));
                    continue;
                }
                if (Objects.equals(cur.premium(), u.premium()) && cur.forcePasswordChange() == u.forcePasswordChange()) {
                    continue; // no-op
                }
                boolean warningNoPassword = !cur.hasPassword()
                        && (Boolean.FALSE.equals(u.premium())
                                || (u.premium() == null && Boolean.TRUE.equals(cur.premium())));
                planned.add(new EditorModels.PlannedChange(
                        u.id(), cur.lastName(), EditorModels.PlannedChange.ChangeKind.UPDATE,
                        cur.premium(), u.premium(), cur.forcePasswordChange(), u.forcePasswordChange(),
                        snap.updatedAt(), warningNoPassword));
            }
            return new EditorModels.PendingEditPlan(session.sessionId(), code, planned, conflicts, session.expiresAt());
        });
    }

    private static String generateSessionId() {
        byte[] b = new byte[12];
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private record DecodedChanges(ActiveSession session, EditorModels.EditorChanges changes) {
    }
}

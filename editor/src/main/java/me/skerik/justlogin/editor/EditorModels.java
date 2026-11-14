package me.skerik.justlogin.editor;

import java.util.List;
import java.util.Map;
import me.skerik.justlogin.core.model.Account;
import org.jspecify.annotations.Nullable;

/** Data models serialized for the web editor. Never includes password hashes, TOTP secrets, or IP hashes. */
public final class EditorModels {

    private EditorModels() {
    }

    public record EditorAccount(
            long id,
            String name,
            String gameUuid,
            @Nullable Boolean premium,
            boolean hasPassword,
            boolean hasTotp,
            boolean forcePasswordChange,
            long registeredAt,
            long lastLoginAt,
            long updatedAt
    ) {
        public EditorAccount(
                long id,
                String name,
                String gameUuid,
                @Nullable Boolean premium,
                boolean hasTotp,
                boolean forcePasswordChange,
                long registeredAt,
                long lastLoginAt,
                long updatedAt
        ) {
            this(id, name, gameUuid, premium, true, hasTotp, forcePasswordChange, registeredAt, lastLoginAt, updatedAt);
        }

        public static EditorAccount fromAccount(Account a) {
            return new EditorAccount(
                    a.id(),
                    a.lastName(),
                    a.gameUuid().toString(),
                    a.premium(),
                    a.hasPassword(),
                    a.hasTotp(),
                    a.forcePasswordChange(),
                    a.registeredAt(),
                    a.lastLoginAt(),
                    a.updatedAt()
            );
        }
    }

    public record EditorPayload(
            int schemaVersion,
            String sessionId,
            long createdAt,
            long expiresAt,
            int page,
            int pageSize,
            long totalAccounts,
            List<EditorAccount> accounts
    ) {
    }

    /** Changes returned from the static web editor (encrypted under the session's AES-GCM key). */
    public record EditorChanges(
            String sessionId,
            List<AccountUpdate> updates,
            List<Long> deleteIds
    ) {
    }

    public record AccountUpdate(
            long id,
            @Nullable Boolean premium,
            boolean forcePasswordChange
    ) {
    }

    public record PlannedChange(
            long id,
            String name,
            ChangeKind kind,
            @Nullable Boolean oldPremium,
            @Nullable Boolean newPremium,
            boolean oldForcePasswordChange,
            boolean newForcePasswordChange,
            long expectedUpdatedAt,
            boolean warningNoPassword
    ) {
        public PlannedChange(
                long id,
                String name,
                ChangeKind kind,
                @Nullable Boolean oldPremium,
                @Nullable Boolean newPremium,
                boolean oldForcePasswordChange,
                boolean newForcePasswordChange,
                long expectedUpdatedAt
        ) {
            this(id, name, kind, oldPremium, newPremium, oldForcePasswordChange, newForcePasswordChange,
                    expectedUpdatedAt, false);
        }

        public boolean locksAccountWithoutPassword() {
            return warningNoPassword;
        }

        public enum ChangeKind {
            UPDATE,
            DELETE
        }
    }

    public record ConflictEntry(long id, String name, String reason) {
    }

    public record PendingEditPlan(
            String sessionId,
            String code,
            List<PlannedChange> changes,
            List<ConflictEntry> conflicts,
            long expiresAt
    ) {
        public boolean isEmpty() {
            return changes.isEmpty();
        }
    }

    public record ApplyReport(
            int applied,
            int skippedConflicts,
            Map<String, Integer> breakdown,
            List<Long> affectedIds,
            List<String> affectedNames
    ) {
        public ApplyReport(int applied, int skippedConflicts, Map<String, Integer> breakdown) {
            this(applied, skippedConflicts, breakdown, List.of(), List.of());
        }

        public ApplyReport(int applied, int skippedConflicts, Map<String, Integer> breakdown, List<String> affectedNames) {
            this(applied, skippedConflicts, breakdown, List.of(), affectedNames);
        }
    }
}

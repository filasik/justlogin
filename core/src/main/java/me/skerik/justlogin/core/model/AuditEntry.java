package me.skerik.justlogin.core.model;

import org.jspecify.annotations.Nullable;

/** Audit log entry for administrative and security-sensitive account events (never contains secrets). */
public record AuditEntry(
        long id,
        long timestamp,
        String actor,
        String action,
        String target,
        @Nullable String details
) {
}

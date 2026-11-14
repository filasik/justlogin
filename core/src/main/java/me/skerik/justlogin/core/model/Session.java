package me.skerik.justlogin.core.model;

/** Persisted IP-bound resume session. Disabled by default in settings (see threat model). */
public record Session(long accountId, String ipHash, long expiresAt) {

    public boolean isExpired(long nowMillis) {
        return nowMillis >= expiresAt;
    }
}

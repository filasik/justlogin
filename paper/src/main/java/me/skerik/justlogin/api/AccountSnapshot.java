package me.skerik.justlogin.api;

import java.util.UUID;
import me.skerik.justlogin.core.model.Account;
import org.jspecify.annotations.Nullable;

/** Immutable read-only account view exposed by {@link JustLoginAPI}. Never contains secrets or hashes. */
public record AccountSnapshot(
        long id,
        String username,
        UUID gameUuid,
        @Nullable UUID premiumUuid,
        boolean premiumConfirmed,
        boolean hasTotp,
        boolean forcePasswordChange,
        boolean hasEmail,
        long registeredAt,
        long lastLoginAt
) {
    public static AccountSnapshot fromAccount(Account acc) {
        return new AccountSnapshot(
                acc.id(),
                acc.lastName(),
                acc.gameUuid(),
                acc.premiumUuid(),
                acc.isPremiumConfirmed(),
                acc.hasTotp(),
                acc.forcePasswordChange(),
                acc.email() != null && !acc.email().isBlank(),
                acc.registeredAt(),
                acc.lastLoginAt()
        );
    }
}

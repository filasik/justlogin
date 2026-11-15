package me.skerik.justlogin.core.model;

import java.util.UUID;
import org.jspecify.annotations.Nullable;

/**
 * Immutable snapshot of an account row. {@link #gameUuid()} is assigned once on creation and never changes,
 * even when toggling {@code /premium}/{@code /unpremium} or when a Mojang account changes its username.
 */
public record Account(
        long id,
        String nameLower,
        String lastName,
        UUID gameUuid,
        @Nullable UUID premiumUuid,
        @Nullable String passwordHash,
        HashAlgorithm hashAlgo,
        @Nullable Boolean premium,
        boolean premiumPending,
        @Nullable String totpSecretEncrypted,
        long totpLastStep,
        boolean forcePasswordChange,
        long registeredAt,
        long lastLoginAt,
        @Nullable String lastIpHash,
        long updatedAt,
        @Nullable String email,
        @Nullable String recoveryCodeHash,
        long recoveryExpiresAt,
        @Nullable String skinOwner,
        @Nullable String skinValue,
        @Nullable String skinSignature,
        long skinUpdatedAt
) {

    /** Backwards-compatible constructor without email recovery or custom skin fields. */
    public Account(
            long id,
            String nameLower,
            String lastName,
            UUID gameUuid,
            @Nullable UUID premiumUuid,
            @Nullable String passwordHash,
            HashAlgorithm hashAlgo,
            @Nullable Boolean premium,
            boolean premiumPending,
            @Nullable String totpSecretEncrypted,
            long totpLastStep,
            boolean forcePasswordChange,
            long registeredAt,
            long lastLoginAt,
            @Nullable String lastIpHash,
            long updatedAt
    ) {
        this(id, nameLower, lastName, gameUuid, premiumUuid, passwordHash, hashAlgo, premium, premiumPending,
                totpSecretEncrypted, totpLastStep, forcePasswordChange, registeredAt, lastLoginAt, lastIpHash,
                updatedAt, null, null, 0L, null, null, null, 0L);
    }

    /** Backwards-compatible constructor without custom skin fields. */
    public Account(
            long id,
            String nameLower,
            String lastName,
            UUID gameUuid,
            @Nullable UUID premiumUuid,
            @Nullable String passwordHash,
            HashAlgorithm hashAlgo,
            @Nullable Boolean premium,
            boolean premiumPending,
            @Nullable String totpSecretEncrypted,
            long totpLastStep,
            boolean forcePasswordChange,
            long registeredAt,
            long lastLoginAt,
            @Nullable String lastIpHash,
            long updatedAt,
            @Nullable String email,
            @Nullable String recoveryCodeHash,
            long recoveryExpiresAt
    ) {
        this(id, nameLower, lastName, gameUuid, premiumUuid, passwordHash, hashAlgo, premium, premiumPending,
                totpSecretEncrypted, totpLastStep, forcePasswordChange, registeredAt, lastLoginAt, lastIpHash,
                updatedAt, email, recoveryCodeHash, recoveryExpiresAt, null, null, null, 0L);
    }

    public boolean isPremiumConfirmed() {
        return Boolean.TRUE.equals(premium);
    }

    public boolean hasTotp() {
        return totpSecretEncrypted != null && !totpSecretEncrypted.isBlank();
    }

    public boolean hasPassword() {
        return passwordHash != null && !passwordHash.isBlank() && hashAlgo != HashAlgorithm.NONE;
    }

    public boolean hasCustomSkin() {
        return skinValue != null && !skinValue.isBlank()
                && skinSignature != null && !skinSignature.isBlank();
    }
}

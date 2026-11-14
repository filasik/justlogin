package me.skerik.justlogin.core.model;

/** Supported password hash algorithms. Legacy algorithms verify on login and upgrade to {@link #ARGON2ID}. */
public enum HashAlgorithm {
    ARGON2ID,
    BCRYPT,
    AUTHME_SHA256,
    SHA512,
    PBKDF2_SHA256,
    NONE;

    public static HashAlgorithm fromDb(String raw) {
        if (raw == null || raw.isBlank()) return NONE;
        try {
            return HashAlgorithm.valueOf(raw.strip().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return NONE;
        }
    }
}

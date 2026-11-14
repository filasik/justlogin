package me.skerik.justlogin.core.security;

import java.util.Locale;
import java.util.Set;
import me.skerik.justlogin.core.model.CoreSettings;
import org.jspecify.annotations.Nullable;

/** Validates passwords against length bounds, username equality, and common leaked passwords (threat model #5). */
public final class PasswordPolicy {

    public enum Violation {
        BLANK,
        TOO_SHORT,
        TOO_LONG,
        SAME_AS_USERNAME,
        COMMON_PASSWORD
    }

    private static final Set<String> COMMON_PASSWORDS = Set.of(
            "password", "password1", "password123", "passw0rd", "123456", "1234567", "12345678",
            "123456789", "1234567890", "12345", "123123", "111111", "000000", "654321", "qwerty",
            "qwerty123", "qwertyuiop", "abc123", "admin", "admin123", "administrator", "minecraft",
            "minecraft1", "minecraft123", "creeper", "steve", "heslo", "heslo123", "tajneheslo",
            "letmein", "welcome", "monkey", "dragon", "baseball", "football", "iloveyou", "trustno1",
            "sunshine", "princess", "master", "shadow", "superman", "michael", "ashley", "bailey",
            "pass1234", "changeme", "default", "asdfgh", "asdfghjkl", "zxcvbnm", "qazwsx", "1q2w3e4r"
    );

    private PasswordPolicy() {
    }

    public static @Nullable Violation validate(char[] password, String username, CoreSettings settings) {
        if (password == null || password.length == 0) return Violation.BLANK;
        String raw = new String(password);
        if (raw.isBlank()) return Violation.BLANK;
        if (password.length < settings.minPasswordLength()) return Violation.TOO_SHORT;
        if (password.length > settings.maxPasswordLength()) return Violation.TOO_LONG;
        String lower = raw.toLowerCase(Locale.ROOT);
        if (settings.rejectUsernameAsPassword() && username != null && !username.isBlank()) {
            if (lower.equals(username.toLowerCase(Locale.ROOT))) {
                return Violation.SAME_AS_USERNAME;
            }
        }
        if (settings.rejectCommonPasswords() && COMMON_PASSWORDS.contains(lower)) {
            return Violation.COMMON_PASSWORD;
        }
        return null;
    }
}

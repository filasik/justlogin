package me.skerik.justlogin.core.security;

import java.util.Locale;
import java.util.regex.Pattern;

/** Validates usernames against the configured allowlist regex and normalizes case-insensitive keys. */
public final class UsernameValidator {

    private UsernameValidator() {
    }

    public static boolean isValid(String username, Pattern pattern) {
        return isValid(username, pattern, false);
    }

    /**
     * Validates a username against {@code pattern}. When {@code floodgateClient} is true (P1-6),
     * allows a single leading Floodgate prefix character ({@code .} or {@code *}) while validating
     * the underlying Xbox/Bedrock gamertag body (replacing spaces with underscores if needed).
     */
    public static boolean isValid(String username, Pattern pattern, boolean floodgateClient) {
        if (username == null || username.isEmpty() || username.length() > 32) return false;
        if (pattern.matcher(username).matches()) return true;
        if (floodgateClient && (username.startsWith(".") || username.startsWith("*")) && username.length() >= 4) {
            String stripped = username.substring(1).replace(' ', '_');
            return pattern.matcher(stripped).matches();
        }
        return false;
    }

    public static String normalizeLower(String username) {
        return username.toLowerCase(Locale.ROOT);
    }
}

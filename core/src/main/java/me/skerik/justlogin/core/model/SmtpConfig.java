package me.skerik.justlogin.core.model;

/** Outbound SMTP settings for optional email password recovery. */
public record SmtpConfig(
        boolean enabled,
        String host,
        int port,
        Security security,
        String username,
        String password,
        String fromAddress,
        String fromName,
        int connectTimeoutMs,
        int readTimeoutMs,
        int codeTtlSeconds,
        long cooldownSeconds,
        String serverDisplayName
) {
    public enum Security {
        STARTTLS,
        SSL,
        NONE;

        public static Security parse(String raw) {
            if (raw == null) return STARTTLS;
            return switch (raw.trim().toUpperCase()) {
                case "SSL", "TLS", "SMTPS" -> SSL;
                case "NONE", "PLAIN" -> NONE;
                default -> STARTTLS;
            };
        }
    }

    public static SmtpConfig disabled() {
        return new SmtpConfig(false, "smtp.example.com", 587, Security.STARTTLS,
                "", "", "noreply@example.com", "JustLogin",
                5000, 10_000, 600, 120L, "Minecraft Server");
    }
}

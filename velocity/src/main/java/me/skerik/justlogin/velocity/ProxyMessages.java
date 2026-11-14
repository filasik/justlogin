package me.skerik.justlogin.velocity;

import java.util.Locale;
import me.skerik.justlogin.core.service.ProxyAuthService;
import org.jspecify.annotations.Nullable;

/** Localized proxy messages (`en`, `cs`, `sk`) for Velocity pre-login, join profile resolution, and routing kicks. */
public final class ProxyMessages {

    public static final String EN_INVALID_USERNAME = "Your username does not match the server rules.";
    public static final String EN_MISSING_SECRET = "JustLogin proxy shared-secret is not configured! Rejecting connection.";
    public static final String EN_AUTH_REQUIRED_SERVER = "Please authenticate before switching servers.";
    public static final String EN_NOT_READY = "JustLogin proxy is not ready or is misconfigured.";
    public static final String EN_AUTH_SERVICE_ERROR = "Authentication service error. Please try again in a moment.";
    public static final String EN_AUTH_SERVER_UNAVAILABLE = "Authentication server is currently unavailable. Please try again shortly.";

    private ProxyMessages() {
    }

    public static String normalizeLocale(@Nullable String raw) {
        if (raw == null || raw.isBlank()) {
            return "en";
        }
        String norm = raw.trim().toLowerCase(Locale.ROOT);
        if (norm.startsWith("cs") || norm.equals("cz")) {
            return "cs";
        }
        if (norm.startsWith("sk")) {
            return "sk";
        }
        return "en";
    }

    public static String formatDeny(@Nullable String locale, ProxyAuthService.DenyReason reason) {
        String lang = normalizeLocale(locale);
        return switch (reason) {
            case PREMIUM_REQUIRED -> switch (lang) {
                case "cs" -> "Tento účet vyžaduje přihlášení přes originální účet Mojang.";
                case "sk" -> "Tento účet vyžaduje prihlásenie cez originálny účet Mojang.";
                default -> "This account requires Mojang online authentication.";
            };
            case MISSING_MOJANG_UUID -> switch (lang) {
                case "cs" -> "Chybí UUID originálního profilu Mojang.";
                case "sk" -> "Chýba UUID originálneho profilu Mojang.";
                default -> "Missing Mojang profile UUID.";
            };
            case MOJANG_ALREADY_LINKED -> switch (lang) {
                case "cs" -> "Tento účet Mojang je již propojen s jiným hráčem.";
                case "sk" -> "Tento účet Mojang je už prepojený s iným hráčom.";
                default -> "That Mojang account is already linked to another player.";
            };
            case REGISTERED_AS_OFFLINE -> switch (lang) {
                case "cs" -> "Jméno je zaregistrováno v offline režimu. Po přihlášení použij /premium.";
                case "sk" -> "Meno je zaregistrované v offline režime. Po prihlásení použi /premium.";
                default -> "Username is registered as offline-mode. Use /premium after logging in.";
            };
            case MOJANG_UUID_MISMATCH_RENAME_CONFLICT -> switch (lang) {
                case "cs" -> "Toto jméno patří dříve zaregistrovanému účtu Mojang, který se přejmenoval. Kontaktuj administrátora (/jl rename).";
                case "sk" -> "Toto meno patrí skôr zaregistrovanému účtu Mojang, ktorý sa premenoval. Kontaktuj administrátora (/jl rename).";
                default -> "This username is bound to a previously registered Mojang account that renamed. Contact an admin (/jl rename).";
            };
            case MOJANG_UNAVAILABLE -> switch (lang) {
                case "cs" -> "Ověřovací servery Mojangu jsou dočasně nedostupné. Zkus to prosím za chvíli.";
                case "sk" -> "Overovacie servery Mojangu sú dočasne nedostupné. Skús to prosím o chvíľu.";
                default -> "Mojang authentication servers are temporarily unavailable. Please try again in a moment.";
            };
            case INVALID_USERNAME -> invalidUsername(lang);
        };
    }

    public static String invalidUsername(@Nullable String locale) {
        return switch (normalizeLocale(locale)) {
            case "cs" -> "Tvoje herní jméno neodpovídá pravidlům serveru.";
            case "sk" -> "Tvoje herné meno nezodpovedá pravidlám servera.";
            default -> EN_INVALID_USERNAME;
        };
    }

    public static String missingSecret(@Nullable String locale) {
        return switch (normalizeLocale(locale)) {
            case "cs" -> "Sdílený klíč (shared-secret) JustLogin proxy není nastaven! Spojení odmítnuto.";
            case "sk" -> "Zdieľaný kľúč (shared-secret) JustLogin proxy nie je nastavený! Spojenie odmietnuté.";
            default -> EN_MISSING_SECRET;
        };
    }

    public static String authRequiredServer(@Nullable String locale) {
        return switch (normalizeLocale(locale)) {
            case "cs" -> "Před přepnutím serveru se prosím nejprve přihlas.";
            case "sk" -> "Pred prepnutím servera sa prosím najprv prihlás.";
            default -> EN_AUTH_REQUIRED_SERVER;
        };
    }

    public static String notReady(@Nullable String locale) {
        return switch (normalizeLocale(locale)) {
            case "cs" -> "Proxy plugin JustLogin není připraven nebo je špatně nakonfigurován.";
            case "sk" -> "Proxy plugin JustLogin nie je pripravený alebo je nesprávne nakonfigurovaný.";
            default -> EN_NOT_READY;
        };
    }

    public static String authServiceError(@Nullable String locale) {
        return switch (normalizeLocale(locale)) {
            case "cs" -> "Chyba ověřovací služby. Zkus to prosím za chvíli.";
            case "sk" -> "Chyba overovacej služby. Skús to prosím o chvíľu.";
            default -> EN_AUTH_SERVICE_ERROR;
        };
    }

    public static String authServerUnavailable(@Nullable String locale) {
        return switch (normalizeLocale(locale)) {
            case "cs" -> "Ověřovací server je momentálně nedostupný. Zkus to prosím za chvíli.";
            case "sk" -> "Overovací server je momentálne nedostupný. Skús to prosím o chvíľu.";
            default -> EN_AUTH_SERVER_UNAVAILABLE;
        };
    }

    public static String translateKickReason(@Nullable String locale, String reasonKey) {
        return switch (reasonKey) {
            case "not-ready" -> notReady(locale);
            case "auth-service-error" -> authServiceError(locale);
            case "auth-server-unavailable" -> authServerUnavailable(locale);
            case "invalid-username", "general.invalid-username" -> invalidUsername(locale);
            case "missing-secret" -> missingSecret(locale);
            case "auth-required-server" -> authRequiredServer(locale);
            case "proxy.deny-premium-required" -> formatDeny(locale, ProxyAuthService.DenyReason.PREMIUM_REQUIRED);
            case "proxy.deny-missing-uuid" -> formatDeny(locale, ProxyAuthService.DenyReason.MISSING_MOJANG_UUID);
            case "proxy.deny-mojang-already-linked" -> formatDeny(locale, ProxyAuthService.DenyReason.MOJANG_ALREADY_LINKED);
            case "proxy.deny-registered-offline" -> formatDeny(locale, ProxyAuthService.DenyReason.REGISTERED_AS_OFFLINE);
            case "proxy.deny-uuid-mismatch" -> formatDeny(locale, ProxyAuthService.DenyReason.MOJANG_UUID_MISMATCH_RENAME_CONFLICT);
            case "proxy.deny-mojang-unavailable" -> formatDeny(locale, ProxyAuthService.DenyReason.MOJANG_UNAVAILABLE);
            default -> authServiceError(locale);
        };
    }
}

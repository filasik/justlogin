package me.skerik.justlogin.paper.dialog;

import io.papermc.paper.dialog.DialogResponseView;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.kyori.adventure.key.Key;
import net.kyori.adventure.nbt.api.BinaryTagHolder;
import org.jspecify.annotations.Nullable;

/**
 * Pure parser for dialog click identifiers and SNBT payload tags carrying per-connection nonces.
 */
public record ClickData(Action action, String nonce) {

    public static final String FIELD_PASSWORD = "password";
    public static final String FIELD_CONFIRM = "confirm";
    public static final String FIELD_CODE = "code";

    private static final Pattern NONCE_SNBT = Pattern.compile("nonce\\s*:\\s*[\"']?([a-fA-F0-9]{8,64})[\"']?");

    public enum Action {
        LOGIN,
        REGISTER,
        TOTP,
        FORCE_PW,
        CANCEL
    }

    public static @Nullable ClickData parse(Key id, @Nullable BinaryTagHolder tag) {
        if (!Clicks.NAMESPACE.equals(id.namespace())) return null;
        Action action = switch (id.value()) {
            case "login" -> Action.LOGIN;
            case "register" -> Action.REGISTER;
            case "totp" -> Action.TOTP;
            case "force_pw" -> Action.FORCE_PW;
            case "cancel" -> Action.CANCEL;
            default -> null;
        };
        if (action == null) return null;
        String nonce = extractNonce(tag == null ? null : tag.string());
        if (nonce == null) return null;
        return new ClickData(action, nonce);
    }

    public static @Nullable String extractNonce(@Nullable String snbt) {
        if (snbt == null || snbt.isBlank()) return null;
        Matcher m = NONCE_SNBT.matcher(snbt);
        return m.find() ? m.group(1) : null;
    }

    public static String readText(@Nullable DialogResponseView view, String key) {
        if (view == null) return "";
        String value = view.getText(key);
        return value == null ? "" : value;
    }
}

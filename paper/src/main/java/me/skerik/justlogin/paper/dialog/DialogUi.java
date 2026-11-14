package me.skerik.justlogin.paper.dialog;

import net.kyori.adventure.audience.Audience;
import net.kyori.adventure.text.Component;
import org.jspecify.annotations.Nullable;

/**
 * Narrow UI abstraction isolating Paper's experimental Dialog API from authentication state handling.
 */
public interface DialogUi {

    void showRegisterDialog(Audience target, String playerName, int minPasswordLength, String nonce, @Nullable Component error);

    void showLoginDialog(Audience target, String playerName, String nonce, @Nullable Component error);

    void showTotpDialog(Audience target, String nonce, @Nullable Component error);

    void showForcePasswordChangeDialog(Audience target, int minPasswordLength, String nonce, @Nullable Component error);

    void close(Audience target);
}

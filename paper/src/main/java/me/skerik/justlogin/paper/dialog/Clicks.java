package me.skerik.justlogin.paper.dialog;

import net.kyori.adventure.key.Key;

/** Adventure resource keys used by JustLogin modal Dialog actions. */
public final class Clicks {

    public static final String NAMESPACE = "justlogin";

    public static final Key LOGIN = Key.key(NAMESPACE, "login");
    public static final Key REGISTER = Key.key(NAMESPACE, "register");
    public static final Key TOTP = Key.key(NAMESPACE, "totp");
    public static final Key FORCE_PW = Key.key(NAMESPACE, "force_pw");
    public static final Key CANCEL = Key.key(NAMESPACE, "cancel");

    private Clicks() {
    }
}

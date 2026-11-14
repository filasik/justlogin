package me.skerik.justlogin.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import me.skerik.justlogin.paper.dialog.ClickData;
import me.skerik.justlogin.paper.dialog.Clicks;
import net.kyori.adventure.key.Key;
import net.kyori.adventure.nbt.api.BinaryTagHolder;
import org.junit.jupiter.api.Test;

final class ClickDataTest {

    @Test
    void parsesValidSnbtPayloadsAndRejectsForgedNamespaces() {
        ClickData login = ClickData.parse(Clicks.LOGIN, BinaryTagHolder.binaryTagHolder("{nonce:\"0123456789abcdef\"}"));
        assertNotNull(login);
        assertEquals(ClickData.Action.LOGIN, login.action());
        assertEquals("0123456789abcdef", login.nonce());

        ClickData singleQuoted = ClickData.parse(Clicks.REGISTER, BinaryTagHolder.binaryTagHolder("{nonce:'fedcba9876543210'}"));
        assertNotNull(singleQuoted);
        assertEquals("fedcba9876543210", singleQuoted.nonce());

        assertNull(ClickData.parse(Key.key("otherplugin", "login"), BinaryTagHolder.binaryTagHolder("{nonce:\"0123456789abcdef\"}")));
        assertNull(ClickData.parse(Clicks.LOGIN, null));
        assertNull(ClickData.parse(Clicks.LOGIN, BinaryTagHolder.binaryTagHolder("{nonce:\"bad\"}")));
    }
}

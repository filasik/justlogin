package me.skerik.justlogin.paper;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import me.skerik.justlogin.paper.util.LogPasswordFilter;
import org.junit.jupiter.api.Test;

final class LogPasswordFilterTest {

    @Test
    void filtersSensitiveAuthCommandsButAllowsNormalLogs() {
        assertTrue(LogPasswordFilter.isSensitiveCommandLog("Alice issued server command: /login SuperSecret123"));
        assertTrue(LogPasswordFilter.isSensitiveCommandLog("Alice issued server command: /l SuperSecret123"));
        assertTrue(LogPasswordFilter.isSensitiveCommandLog("Alice issued server command: /register pass1234 pass1234"));
        assertTrue(LogPasswordFilter.isSensitiveCommandLog("Alice issued server command: /justlogin:reg pass1234 pass1234"));
        assertTrue(LogPasswordFilter.isSensitiveCommandLog("Alice issued server command: /changepassword old new"));
        assertTrue(LogPasswordFilter.isSensitiveCommandLog("Alice issued server command: /unregister secret"));
        assertTrue(LogPasswordFilter.isSensitiveCommandLog("Admin issued server command: /jl changepassword Bob newpass"));
        assertTrue(LogPasswordFilter.isSensitiveCommandLog("Admin issued server command: /jl import authme mysql localhost 3306 db user secret"));

        assertFalse(LogPasswordFilter.isSensitiveCommandLog("Alice issued server command: /spawn"));
        assertFalse(LogPasswordFilter.isSensitiveCommandLog("Admin issued server command: /jl status Alice"));
        assertFalse(LogPasswordFilter.isSensitiveCommandLog("Alice joined the game"));
    }
}

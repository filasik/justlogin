package me.skerik.justlogin.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import me.skerik.justlogin.paper.command.CommandDoc;
import me.skerik.justlogin.paper.command.CommandDoc.Entry;
import me.skerik.justlogin.paper.command.CommandDoc.Section;
import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.jupiter.api.Test;

final class HelpCommandCompletenessTest {

    private static final Pattern LITERAL_CALL = Pattern.compile("Commands\\.literal\\(\"([^\"]+)\"\\)");

    @Test
    void everyCommandDocEntryAndHelpKeyExistsInAllLocales() throws Exception {
        for (String locale : List.of("en", "cs", "sk")) {
            YamlConfiguration yaml = new YamlConfiguration();
            String res = "/messages_" + locale + ".yml";
            try (var in = getClass().getResourceAsStream(res)) {
                assertNotNull(in, "Missing resource " + res);
                yaml.load(new InputStreamReader(in, StandardCharsets.UTF_8));
            }
            for (String key : CommandDoc.requiredMessageKeys()) {
                String val = yaml.getString(key);
                assertNotNull(val, "Missing key '" + key + "' in " + res);
                assertFalse(val.isBlank(), "Blank key '" + key + "' in " + res);
            }
        }
    }

    @Test
    void everyBrigadierLiteralInSourceHasMatchingCommandDocEntry() throws Exception {
        Path cmdDir = Path.of("src/main/java/me/skerik/justlogin/paper/command");
        if (!Files.isDirectory(cmdDir)) {
            cmdDir = Path.of("paper/src/main/java/me/skerik/justlogin/paper/command");
        }
        assertTrue(Files.isDirectory(cmdDir), "Could not locate paper command directory");

        // 1. AuthCommands literals
        Set<String> authLiterals = extractLiterals(cmdDir.resolve("AuthCommands.java"));
        for (String lit : authLiterals) {
            if (Set.of("setup", "confirm", "disable", "verify").contains(lit)) {
                assertTrue(CommandDoc.findByQuery("2fa " + lit).isPresent(),
                        "Missing CommandDoc entry for /2fa " + lit);
            } else {
                assertTrue(CommandDoc.findByQuery(lit).isPresent(),
                        "Missing CommandDoc entry for AuthCommands literal: " + lit);
            }
        }

        // 2. EmailCommands literals
        Set<String> emailLiterals = extractLiterals(cmdDir.resolve("EmailCommands.java"));
        for (String lit : emailLiterals) {
            if (lit.equals("email")) {
                assertFalse(CommandDoc.findAllByQuery("email").isEmpty());
            } else {
                assertTrue(CommandDoc.findByQuery("email " + lit).isPresent(),
                        "Missing CommandDoc entry for /email " + lit);
            }
        }

        // 3. SkinCommands literals
        Set<String> skinLiterals = extractLiterals(cmdDir.resolve("SkinCommands.java"));
        for (String lit : skinLiterals) {
            if (Set.of("reset", "clear").contains(lit)) {
                continue;
            }
            assertTrue(CommandDoc.findByQuery(lit).isPresent(),
                    "Missing CommandDoc entry for SkinCommands literal: " + lit);
        }

        // 4. AdminCommands top-level subcommands
        Set<String> adminLiterals = extractLiterals(cmdDir.resolve("AdminCommands.java"));
        Set<String> nestedImportOrConfirmLiterals = Set.of(
                "justlogin", "debug-click", "confirm", "auto", "--dry-run", "sqlite", "mysql",
                "authme", "fastlogin", "librelogin", "loginsecurity", "nlogin",
                "openlogin", "limboauth", "authy"
        );
        for (String lit : adminLiterals) {
            if (nestedImportOrConfirmLiterals.contains(lit)) {
                continue;
            }
            assertTrue(CommandDoc.adminSubcommandLiterals().contains(lit)
                            || CommandDoc.findByQuery("jl " + lit).isPresent(),
                    "Missing CommandDoc entry for /jl " + lit);
        }
    }

    @Test
    void queryLookupResolvesCommandsAliasesAndSections() {
        assertEquals("register", CommandDoc.findByQuery("reg").orElseThrow().id());
        assertEquals("login", CommandDoc.findByQuery("/l").orElseThrow().id());
        assertEquals("changepassword", CommandDoc.findByQuery("cp").orElseThrow().id());
        assertEquals("skin", CommandDoc.findByQuery("skins").orElseThrow().id());
        assertEquals("jl_skin", CommandDoc.findByQuery("jl skin").orElseThrow().id());
        assertEquals("jl_changepass", CommandDoc.findByQuery("jl changepassword").orElseThrow().id());
        assertEquals("jl_forcepw", CommandDoc.findByQuery("/jl forcechangepassword").orElseThrow().id());
        assertEquals("jl_help", CommandDoc.findByQuery("?").orElseThrow().id());
        assertEquals(4, CommandDoc.findAllByQuery("2fa").size());
        assertEquals(4, CommandDoc.findAllByQuery("email").size());
        assertEquals(Section.ADMIN, CommandDoc.findSection("admin").orElseThrow());

        for (Entry e : CommandDoc.ALL) {
            if (e.hasSensitiveArgs()) {
                assertTrue(e.suggestCommand().endsWith(" "),
                        "Commands with sensitive args must only suggest_command with trailing space: " + e.id());
            }
        }
    }

    private static Set<String> extractLiterals(Path file) throws Exception {
        String src = Files.readString(file, StandardCharsets.UTF_8);
        Matcher m = LITERAL_CALL.matcher(src);
        Set<String> out = new HashSet<>();
        while (m.find()) {
            out.add(m.group(1));
        }
        return out;
    }
}

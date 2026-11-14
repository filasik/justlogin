package me.skerik.justlogin.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import me.skerik.justlogin.paper.config.Messages;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.jupiter.api.Test;

final class MessagesFilesTest {

    @Test
    void englishCzechAndSlovakHaveMatchingLeafKeys() throws Exception {
        YamlConfiguration en = load("/messages_en.yml");
        YamlConfiguration cs = load("/messages_cs.yml");
        YamlConfiguration sk = load("/messages_sk.yml");

        Set<String> enKeys = leafKeys(en);
        Set<String> csKeys = leafKeys(cs);
        Set<String> skKeys = leafKeys(sk);
        assertEquals(enKeys, csKeys, "messages_en.yml and messages_cs.yml must have identical key sets");
        assertEquals(enKeys, skKeys, "messages_en.yml and messages_sk.yml must have identical key sets");

        for (String key : enKeys) {
            for (YamlConfiguration cfg : new YamlConfiguration[] { en, cs, sk }) {
                String tpl = cfg.getString(key);
                assertNotNull(tpl);
                assertFalse(tpl.isEmpty(), "Empty message for key: " + key);
                Messages.renderTemplate(tpl, Map.of("player", "<click:run_command:/op>Evil", "url", "https://example.com/#k"));
            }
        }
    }

    @Test
    void placeholderRendersUntrustedPlayerNameWithoutTagInjection() {
        var rendered = Messages.renderTemplate("<green>Hi {player}</green>", Map.of("player", "<red>Injected</red>"));
        assertEquals("Hi <red>Injected</red>", PlainTextComponentSerializer.plainText().serialize(rendered));
    }

    private YamlConfiguration load(String resource) throws Exception {
        YamlConfiguration y = new YamlConfiguration();
        try (var in = getClass().getResourceAsStream(resource)) {
            assertNotNull(in, "Missing resource " + resource);
            y.load(new InputStreamReader(in, StandardCharsets.UTF_8));
        }
        return y;
    }

    private static Set<String> leafKeys(YamlConfiguration y) {
        Set<String> keys = new TreeSet<>();
        for (String k : y.getKeys(true)) {
            if (!y.isConfigurationSection(k)) keys.add(k);
        }
        return keys;
    }
}

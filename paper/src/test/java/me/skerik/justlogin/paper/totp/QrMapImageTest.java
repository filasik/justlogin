package me.skerik.justlogin.paper.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import me.skerik.justlogin.core.crypto.TotpService;
import org.junit.jupiter.api.Test;

final class QrMapImageTest {
    @Test
    void mapPaletteQrDecodesToExactProvisioningUriIncludingLongAndUnicodeLabels() throws Exception {
        for (String issuer : new String[] {"JustLogin", "Český Minecraft server – soukromý"}) {
            String uri = TotpService.provisioningUri(issuer, "Player_1234567890", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
            byte[] map = QrMapImage.encode(uri);
            assertEquals(128 * 128, map.length);
            int[] rgb = new int[map.length];
            for (int i = 0; i < map.length; i++) {
                assertTrue(map[i] == QrMapImage.BLACK || map[i] == QrMapImage.WHITE);
                rgb[i] = map[i] == QrMapImage.BLACK ? 0x0d0d0d : 0xffffff;
            }
            BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(new RGBLuminanceSource(128, 128, rgb)));
            assertEquals(uri, new QRCodeReader().decode(bitmap).getText());
        }
    }

    @Test
    void rejectsOversizedAndNonProvisioningInputWithoutEchoingSecret() {
        assertThrows(IllegalArgumentException.class, () -> QrMapImage.encode("https://example.org"));
        var ex = assertThrows(IllegalArgumentException.class,
                () -> QrMapImage.encode("otpauth://totp/" + "sensitive".repeat(300)));
        assertTrue(!ex.getMessage().contains("sensitive"));
    }
}

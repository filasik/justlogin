package me.skerik.justlogin.paper.totp;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import java.util.Map;

/** Local-only QR encoding. No Bukkit map, image file, URL fetch, or secret logging. */
public final class QrMapImage {
    public static final int SIZE = 128;
    public static final byte WHITE = 34;
    public static final byte BLACK = 119;

    private QrMapImage() { }

    public static byte[] encode(String uri) throws WriterException {
        if (uri == null || !uri.startsWith("otpauth://totp/") || uri.length() > 2048) {
            throw new IllegalArgumentException("Invalid TOTP provisioning URI");
        }
        BitMatrix qr = new QRCodeWriter().encode(uri, BarcodeFormat.QR_CODE, SIZE, SIZE,
                Map.of(EncodeHintType.MARGIN, 4, EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M));
        if (qr.getWidth() != SIZE || qr.getHeight() != SIZE) {
            throw new IllegalArgumentException("TOTP QR does not fit a map");
        }
        byte[] pixels = new byte[SIZE * SIZE];
        for (int y = 0; y < SIZE; y++) {
            for (int x = 0; x < SIZE; x++) pixels[y * SIZE + x] = qr.get(x, y) ? BLACK : WHITE;
        }
        return pixels;
    }
}

#!/usr/bin/env python3
"""Generate favicon / touch icons / social card for justlogin.net from docs/assets/icon.png.

    pip install pillow
    python3 scripts/make-site-icons.py

Outputs (all inside docs/, deployed with the site): favicon.ico, favicon-16x16.png, favicon-32x32.png,
apple-touch-icon.png, icon-192.png, icon-512.png, assets/og-image.png (1200x630).
The og-image is a brand card (icon + tagline), not a screenshot.
"""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
icon = Image.open(DOCS / "assets" / "icon.png").convert("RGBA")

def resized(size: int) -> Image.Image:
    return icon.resize((size, size), Image.LANCZOS)

resized(16).save(DOCS / "favicon-16x16.png")
resized(32).save(DOCS / "favicon-32x32.png")
resized(192).save(DOCS / "icon-192.png")
resized(512).save(DOCS / "icon-512.png")
icon.resize((256, 256), Image.LANCZOS).save(DOCS / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64)])

# Apple touch icon: iOS fills transparency with black, so use an opaque full-bleed background.
touch = Image.new("RGBA", (180, 180), (37, 99, 235, 255))
touch.alpha_composite(icon.resize((180, 180), Image.LANCZOS))
touch.convert("RGB").save(DOCS / "apple-touch-icon.png")

# Social card 1200x630.
W, H = 1200, 630
card = Image.new("RGB", (W, H), (15, 23, 42))
px = card.load()
for y in range(H):
    for x in range(W):
        t = (x / W * 0.6) + (y / H * 0.4)
        px[x, y] = (int(11 + 26 * t), int(18 + 60 * t), int(40 + 150 * t))
d = ImageDraw.Draw(card)
card.paste(icon.resize((200, 200), Image.LANCZOS), (90, 110), icon.resize((200, 200), Image.LANCZOS))

def font(size, bold=False):
    for path, idx in (("/System/Library/Fonts/HelveticaNeue.ttc", 1 if bold else 0),
                      ("/System/Library/Fonts/Helvetica.ttc", 1 if bold else 0),
                      ("/Library/Fonts/Arial.ttf", 0)):
        try:
            return ImageFont.truetype(path, size, index=idx)
        except OSError:
            continue
    return ImageFont.load_default()

d.text((330, 120), "JustLogin", font=font(96, True), fill=(255, 255, 255))
d.text((334, 235), "Authentication for Minecraft servers", font=font(40), fill=(219, 228, 245))
lines = ["Native login dialogs before the world loads", "Argon2id · 2FA · Mojang auto-login · immutable UUIDs"]
for i, line in enumerate(lines):
    d.text((90, 380 + i * 54), line, font=font(34), fill=(186, 204, 240))
d.text((90, 540), "Paper · Folia · Velocity · BungeeCord", font=font(30, True), fill=(255, 255, 255))
d.text((W - 90, 540), "justlogin.net", font=font(30, True), fill=(255, 255, 255), anchor="ra")
card.save(DOCS / "assets" / "og-image.png", optimize=True)
print("ok")

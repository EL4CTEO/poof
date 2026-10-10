"""Generates the brand assets: assets/app.ico, assets/logo.png, assets/social-preview.png.

Run from the repo root:  python tools/gen_assets.py   (needs Pillow)
"""
from PIL import Image, ImageDraw, ImageFont

S = 1024  # supersampled master size
TEAL, BLUE = (0, 178, 160), (44, 96, 224)
WHITE = (255, 255, 255, 255)
SHADE = (196, 220, 246, 255)


def gradient(w: int, h: int, a=TEAL, b=BLUE) -> Image.Image:
    img = Image.new("RGBA", (w, h))
    px = img.load()
    for y in range(h):
        for x in range(w):
            t = (x / w + y / h) / 2
            px[x, y] = tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3)) + (255,)
    return img


def sparkle(d: ImageDraw.ImageDraw, cx: float, cy: float, s: float) -> None:
    k = 0.22
    d.polygon(
        [(cx, cy - s), (cx + s * k, cy - s * k), (cx + s, cy), (cx + s * k, cy + s * k),
         (cx, cy + s), (cx - s * k, cy + s * k), (cx - s, cy), (cx - s * k, cy - s * k)],
        fill=WHITE,
    )


def cloud(d: ImageDraw.ImageDraw, dx: float, dy: float, color) -> None:
    for cx, cy, r in [(350, 610, 130), (500, 520, 175), (670, 570, 150), (790, 650, 105), (260, 680, 85)]:
        d.ellipse((cx - r + dx, cy - r + dy, cx + r + dx, cy + r + dy), fill=color)
    d.rounded_rectangle((260 + dx, 640 + dy, 790 + dx, 755 + dy), radius=57, fill=color)


def tile() -> Image.Image:
    """Rounded gradient tile with the puff-of-smoke cloud and sparkles."""
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle((40, 40, S - 40, S - 40), radius=230, fill=255)
    img.paste(gradient(S, S), (0, 0), mask)
    d = ImageDraw.Draw(img)
    ox, oy = -23, -30
    cloud(d, ox, oy + 22, SHADE)  # soft underside
    cloud(d, ox, oy, WHITE)
    sparkle(d, 790, 262, 96)
    sparkle(d, 250, 330, 52)
    d.ellipse((842, 392, 882, 432), fill=WHITE)
    d.ellipse((196, 438, 222, 464), fill=WHITE)
    return img


def social(logo: Image.Image) -> Image.Image:
    w, h = 1280, 640
    img = gradient(w, h, (14, 22, 46), (28, 58, 120))  # dark navy so the tile stands out
    d = ImageDraw.Draw(img)
    for cx, cy, s in [(1120, 120, 70), (1180, 470, 40), (610, 560, 34)]:
        sparkle(d, cx, cy, s)
    big = logo.resize((380, 380), Image.LANCZOS)
    img.alpha_composite(big, (110, 130))
    bold = ImageFont.truetype("C:/Windows/Fonts/segoeuib.ttf", 170)
    reg = ImageFont.truetype("C:/Windows/Fonts/segoeui.ttf", 44)
    d.text((540, 150), "Poof", font=bold, fill=WHITE)
    d.text((548, 360), "Fast, tiny Windows uninstaller", font=reg, fill=WHITE)
    d.text((548, 418), "that also clears the leftovers.", font=reg, fill=WHITE)
    return img


def main() -> None:
    master = tile()
    master.save("assets/app.ico", format="ICO", sizes=[(s, s) for s in (16, 20, 24, 32, 40, 48, 64, 128, 256)])
    logo = master.resize((512, 512), Image.LANCZOS)
    logo.save("assets/logo.png", optimize=True)
    social(master).convert("RGB").save("assets/social-preview.png", optimize=True)


main()

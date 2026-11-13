#!/usr/bin/env python3
"""Render the Anubis-365 chip: the package back, and the die floorplan.

Everything drawn here comes from numbers already measured in this repository
(SPEED.md, results/hbm3e-x8-2026-11-12.json):

  365 Argon2id engines x 3 contexts   68.1 M generic cells   70,122 h/s
  128 HashX lanes                     7.5 M cells            224 M h/s
  128 SHA-256 lanes                   1.1 M cells            1.94 G h/s
  8 x HBM3e stacks                    9.82 TB/s              8 x 1,228 B/cycle

So the die is ~89% Argon2id array, ~10% HashX and ~1.4% SHA-256 - which is the
point worth seeing: the memory machine dominates and the other two algorithms
are a sliver.

Draws at 4x and downsamples for antialiasing, then adds the lighting, grain and
vignette that make it read as a photograph of hardware rather than a diagram.

    python3 chip/tools/render_chip_art.py
"""
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

SS = 4                      # supersampling factor
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SANS_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

OUT = Path(__file__).resolve().parent.parent.parent / "docs" / "img"

# PCB / package palette
SUBSTRATE = (18, 26, 22)
SUBSTRATE_HI = (30, 44, 36)
GOLD = (198, 158, 74)
GOLD_HI = (244, 214, 138)
GOLD_LO = (120, 88, 38)


def font(path, size):
    return ImageFont.truetype(path, size)


def rgba(w, h, fill=(0, 0, 0, 0)):
    return Image.new("RGBA", (w, h), fill)


def linear_gradient(w, h, top, bottom):
    """Vertical gradient as an RGB array."""
    g = np.zeros((h, w, 3), dtype=np.float32)
    for i in range(3):
        g[:, :, i] = np.linspace(top[i], bottom[i], h)[:, None]
    return g


def radial_light(w, h, cx, cy, strength=1.0):
    """A soft single-source light, returns a 0..1 multiplier array."""
    yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
    d = np.sqrt(((xx - cx * w) / w) ** 2 + ((yy - cy * h) / h) ** 2)
    return np.clip(1.0 - d * 1.35 * strength, 0.45, 1.18)


def add_grain(arr, amount=3.0):
    n = np.random.normal(0.0, amount, arr.shape[:2])[:, :, None]
    return np.clip(arr + n, 0, 255)


def vignette(arr, strength=0.55):
    h, w = arr.shape[:2]
    yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
    d = np.sqrt(((xx - w / 2) / (w / 2)) ** 2 + ((yy - h / 2) / (h / 2)) ** 2)
    v = np.clip(1.0 - strength * np.clip(d - 0.55, 0, None) ** 1.4, 0.0, 1.0)
    return arr * v[:, :, None]


# ---------------------------------------------------------------- package back
def render_package_back(path, final=980, pads=46):
    S = final * SS
    margin = int(S * 0.10)
    pkg = S - 2 * margin

    img = rgba(S, S, (14, 14, 16, 255))
    d = ImageDraw.Draw(img)

    # substrate with a faint weave
    sub = linear_gradient(pkg, pkg, SUBSTRATE_HI, SUBSTRATE)
    yy, xx = np.mgrid[0:pkg, 0:pkg]
    weave = (np.sin(xx * 0.11) * np.sin(yy * 0.09) * 3.0)[:, :, None]
    sub = np.clip(sub + weave, 0, 255)
    sub_im = Image.fromarray(sub.astype(np.uint8)).convert("RGBA")
    mask = rgba(pkg, pkg, (255, 255, 255, 255))
    md = ImageDraw.Draw(mask)
    r = int(pkg * 0.035)
    md.rounded_rectangle([0, 0, pkg - 1, pkg - 1], radius=r, fill=(255, 255, 255, 255))
    # chamfered corner, top-right (LGA orientation mark)
    c = int(pkg * 0.10)
    md.polygon([(pkg - c, 0), (pkg, 0), (pkg, c)], fill=(0, 0, 0, 0))
    img.paste(sub_im, (margin, margin), mask)

    # drop shadow
    sh = rgba(S, S, (0, 0, 0, 0))
    ImageDraw.Draw(sh).rounded_rectangle(
        [margin + 10 * SS, margin + 16 * SS, margin + pkg, margin + pkg + 10 * SS],
        radius=r, fill=(0, 0, 0, 190))
    img = Image.alpha_composite(img, sh.filter(ImageFilter.GaussianBlur(18 * SS / 4)))

    # ---- pad field -------------------------------------------------------
    pad = rgba(S, S, (0, 0, 0, 0))
    pd = ImageDraw.Draw(pad)
    light = radial_light(S, S, 0.34, 0.28)
    inner = int(pkg * 0.075)          # keep the outer ring clear
    field = pkg - 2 * inner
    pitch = field / pads
    size = pitch * 0.58
    rr = max(2, int(pitch * 0.12))
    # the die cavity: a clear rectangle in the middle where the substrate shows
    cav = (0.33, 0.36, 0.67, 0.64)
    rng = np.random.default_rng(7)
    for iy in range(pads):
        for ix in range(pads):
            cx = margin + inner + (ix + 0.5) * pitch
            cy = margin + inner + (iy + 0.5) * pitch
            fx, fy = (ix + 0.5) / pads, (iy + 0.5) / pads
            if cav[0] < fx < cav[2] and cav[1] < fy < cav[3]:
                continue
            lum = light[int(cy), int(cx)] * (0.86 + 0.28 * rng.random())
            col = tuple(int(np.clip(a * lum, 0, 255)) for a in GOLD)
            x0, y0 = cx - size / 2, cy - size / 2
            pd.rounded_rectangle([x0, y0, x0 + size, y0 + size], radius=rr, fill=col)
            # specular sliver on the lit edge
            pd.line([(x0 + rr, y0 + 1), (x0 + size - rr, y0 + 1)],
                    fill=tuple(int(np.clip(a * lum * 1.35, 0, 255)) for a in GOLD_HI),
                    width=max(1, SS // 2))
            pd.line([(x0 + 1, y0 + rr), (x0 + 1, y0 + size - rr)],
                    fill=tuple(int(np.clip(a * lum * 1.15, 0, 255)) for a in GOLD_HI),
                    width=max(1, SS // 3))
            pd.line([(x0 + rr, y0 + size - 1), (x0 + size - rr, y0 + size - 1)],
                    fill=tuple(int(np.clip(a * lum * 0.55, 0, 255)) for a in GOLD_LO),
                    width=max(1, SS // 2))
    img = Image.alpha_composite(img, pad)

    # orientation triangle, top-right chamfer
    tri = rgba(S, S, (0, 0, 0, 0))
    td = ImageDraw.Draw(tri)
    tx, ty = margin + pkg - c * 0.55, margin + c * 0.62
    s2 = c * 0.22
    td.polygon([(tx, ty - s2), (tx - s2, ty + s2), (tx + s2, ty + s2)], fill=GOLD_HI)
    img = Image.alpha_composite(img, tri)

    # ---- etched markings in the cavity -----------------------------------
    etch = rgba(S, S, (0, 0, 0, 0))
    ed = ImageDraw.Draw(etch)
    cx = margin + pkg * 0.5
    top = margin + pkg * (cav[1] + 0.035)
    etch_col = (150, 178, 158, 255)
    faint = (108, 132, 116, 255)

    ed.text((cx, top), "ANUBIS-365", font=font(SANS_B, int(pkg * 0.062)),
            fill=etch_col, anchor="ma")
    y = top + pkg * 0.076
    lines = [
        ("8x HBM3e  9.82 TB/s", faint),
        ("A2I 365x3c x  HX 128  x  SHA 128", faint),
        ("QSPI/OSPI  UART  PCIe", faint),
    ]
    for txt, col in lines:
        ed.text((cx, y), txt, font=font(MONO, int(pkg * 0.026)), fill=col, anchor="ma")
        y += pkg * 0.036
    ed.text((cx, y + pkg * 0.012), "1 GHz  70,122 Argon2id h/s  224 M HashX/s  1.94 G SHA-256/s",
            font=font(MONO, int(pkg * 0.0205)), fill=faint, anchor="ma")
    ed.text((cx, margin + pkg - pkg * 0.045), "PWR 2026-11-13   ESR 1.96x   LOT A0B1-5C01",
            font=font(MONO, int(pkg * 0.019)), fill=faint, anchor="ma")
    img = Image.alpha_composite(img, etch)

    # bevel: bright top edge, dark bottom edge
    bev = rgba(S, S, (0, 0, 0, 0))
    bd = ImageDraw.Draw(bev)
    bd.rounded_rectangle([margin, margin, margin + pkg - 1, margin + pkg - 1],
                         radius=r, outline=(r // 3) and (120, 140, 124, 120),
                         width=max(1, SS))
    img = Image.alpha_composite(img, bev)

    # ---- photo finish ----------------------------------------------------
    arr = np.asarray(img.convert("RGB")).astype(np.float32)
    arr = add_grain(vignette(arr, 0.62), 3.2)
    out = Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8))
    out = out.resize((final, final), Image.LANCZOS)
    path.parent.mkdir(parents=True, exist_ok=True)
    out.save(path)
    print("wrote", path, out.size)


# ------------------------------------------------------------------ die floor
def render_die(path, W=1400, H=1000):
    S = SS
    w, h = W * S, H * S
    img = rgba(w, h, (10, 10, 14, 255))
    d = ImageDraw.Draw(img)

    m = int(w * 0.035)
    die = [m, m, w - m, h - m]
    # die base: metallic blue-violet, like a real die shot
    base = linear_gradient(w, h, (26, 30, 62), (16, 18, 40))
    yy, xx = np.mgrid[0:h, 0:w]
    sheen = (np.sin(xx * 0.010 + yy * 0.004) * 4.0)[:, :, None]
    base = np.clip(base + sheen, 0, 255)
    dim = Image.fromarray(base.astype(np.uint8)).convert("RGBA")
    mk = rgba(w, h, (0, 0, 0, 0))
    ImageDraw.Draw(mk).rounded_rectangle(die, radius=int(w * 0.012),
                                         fill=(255, 255, 255, 255))
    img.paste(dim, (0, 0), mk)

    # ---- Argon2id array: 365 engines, 25 x 15 grid ------------------------
    ax0, ay0 = die[0] + int(w * 0.022), die[1] + int(h * 0.045)
    ax1 = die[0] + int(w * 0.735)
    ay1 = die[3] - int(h * 0.215)
    cols, rows = 25, 15
    cw = (ax1 - ax0) / cols
    ch = (ay1 - ay0) / rows
    n = 0
    for r in range(rows):
        for c in range(cols):
            if n >= 365:
                break
            x0 = ax0 + c * cw
            y0 = ay0 + r * ch
            # engine tile: a die-block with a warm core and cooler logic ring
            d.rectangle([x0 + 1 * S, y0 + 1 * S, x0 + cw - 1 * S, y0 + ch - 1 * S],
                        fill=(38, 44, 86), outline=(70, 82, 132), width=S)
            d.rectangle([x0 + cw * 0.22, y0 + ch * 0.22,
                         x0 + cw * 0.78, y0 + ch * 0.78],
                        fill=(96, 74, 128), outline=(140, 108, 176), width=S)
            d.rectangle([x0 + cw * 0.36, y0 + ch * 0.36,
                         x0 + cw * 0.64, y0 + ch * 0.64],
                        fill=(168, 122, 196))
            n += 1

    # ---- HBM3e PHYs: 8 long strips along the right edge -------------------
    px0 = die[0] + int(w * 0.752)
    px1 = die[2] - int(w * 0.016)
    ph = (die[3] - die[1] - int(h * 0.10)) / 8
    for i in range(8):
        y0 = die[1] + int(h * 0.05) + i * ph
        d.rectangle([px0, y0 + ph * 0.12, px1, y0 + ph * 0.88],
                    fill=(120, 96, 42), outline=(196, 158, 74), width=2 * S)
        for k in range(1, 6):
            xx0 = px0 + (px1 - px0) * k / 6
            d.line([(xx0, y0 + ph * 0.12), (xx0, y0 + ph * 0.88)],
                   fill=(90, 72, 32), width=S)

    # ---- HashX pool: 128 lanes, 16 x 8 -----------------------------------
    hx0, hy0 = die[0] + int(w * 0.022), die[3] - int(h * 0.185)
    hx1 = die[0] + int(w * 0.50)
    hy1 = die[3] - int(h * 0.045)
    for r in range(8):
        for c in range(16):
            x0 = hx0 + c * (hx1 - hx0) / 16
            y0 = hy0 + r * (hy1 - hy0) / 8
            d.rectangle([x0 + 1 * S, y0 + 1 * S,
                         x0 + (hx1 - hx0) / 16 - 1 * S, y0 + (hy1 - hy0) / 8 - 1 * S],
                        fill=(30, 96, 92), outline=(72, 176, 160), width=S)

    # ---- SHA-256 pool: 128 lanes, 16 x 8 ---------------------------------
    sx0, sy0 = die[0] + int(w * 0.525), die[3] - int(h * 0.185)
    sx1 = die[0] + int(w * 0.735)
    sy1 = die[3] - int(h * 0.045)
    for r in range(8):
        for c in range(16):
            x0 = sx0 + c * (sx1 - sx0) / 16
            y0 = sy0 + r * (sy1 - sy0) / 8
            d.rectangle([x0 + 1 * S, y0 + 1 * S,
                         x0 + (sx1 - sx0) / 16 - 1 * S, y0 + (sy1 - sy0) / 8 - 1 * S],
                        fill=(120, 56, 30), outline=(206, 120, 62), width=S)

    # ---- IO: PCIe serdes, SPI/UART, doctor ------------------------------
    for i in range(8):
        x0 = die[0] + int(w * 0.022) + i * (w * 0.012)
        y0 = die[1] + int(h * 0.008)
        d.rectangle([x0, y0, x0 + w * 0.010, y0 + h * 0.028],
                    fill=(52, 52, 70), outline=(150, 150, 190), width=S)
    d.rectangle([die[0] + int(w * 0.752), die[3] - int(h * 0.185),
                 die[2] - int(w * 0.016), die[3] - int(h * 0.045)],
                fill=(46, 40, 66), outline=(150, 130, 200), width=2 * S)

    img = img.convert("RGB")

    # ---- labels -----------------------------------------------------------
    d = ImageDraw.Draw(img)
    lbl = font(SANS_B, int(h * 0.030))
    sub = font(MONO, int(h * 0.0205))
    small = font(MONO, int(h * 0.0175))

    d.text(((ax0 + ax1) / 2, ay0 - h * 0.030), "A2I - 365 Argon2id engines x 3 contexts",
           font=lbl, fill=(226, 214, 255), anchor="ms")
    d.text(((ax0 + ax1) / 2, ay0 - h * 0.008), "68.1 M cells (89%)   9,801 B/cycle   70,122 h/s @ 1 GHz",
           font=sub, fill=(168, 158, 206), anchor="ms")

    d.text(((px0 + px1) / 2, die[1] + h * 0.028), "8x HBM3e", font=lbl,
           fill=(238, 210, 150), anchor="ms")
    d.text(((px0 + px1) / 2, die[1] + h * 0.052), "9.82 TB/s", font=small,
           fill=(196, 168, 116), anchor="ms")

    d.text((hx0 + (hx1 - hx0) / 2, hy1 + h * 0.008), "HX - 128 lanes", font=sub,
           fill=(130, 224, 208), anchor="ms")
    d.text((hx0 + (hx1 - hx0) / 2, hy1 + h * 0.030), "7.5 M cells   224 M h/s", font=small,
           fill=(96, 176, 164), anchor="ms")

    d.text((sx0 + (sx1 - sx0) / 2, sy1 + h * 0.008), "SHA - 128 lanes", font=sub,
           fill=(240, 150, 100), anchor="ms")
    d.text((sx0 + (sx1 - sx0) / 2, sy1 + h * 0.030), "1.1 M cells   1.94 G h/s", font=small,
           fill=(186, 116, 80), anchor="ms")

    d.text((die[2] - int(w * 0.016) - 4 * S, die[3] - int(h * 0.215)),
           "QSPI/OSPI + UART + doctor", font=small, fill=(170, 158, 214), anchor="rs")
    d.text((die[0] + int(w * 0.022), die[1] + int(h * 0.043)),
           "PCIe x16 serdes", font=small, fill=(176, 176, 206), anchor="ls")

    arr = np.asarray(img).astype(np.float32)
    arr = add_grain(vignette(arr, 0.35), 2.0)
    out = Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8))
    out = out.resize((W, H), Image.LANCZOS)
    path.parent.mkdir(parents=True, exist_ok=True)
    out.save(path)
    print("wrote", path, out.size)




# --------------------------------------------------------------- photoreal die
def _noise(w, h, cells, seed, smooth=True):
    """Low-resolution noise upscaled: cheap, and it blurs like real texture."""
    rng = np.random.default_rng(seed)
    small = rng.random((cells, cells)).astype(np.float32)
    im = Image.fromarray((small * 255).astype(np.uint8)).resize(
        (w, h), Image.BICUBIC if smooth else Image.NEAREST)
    a = np.asarray(im).astype(np.float32) / 255.0
    return a


def _fractal(w, h, octaves=(10, 26, 70, 190, 470), seed=1):
    """Multi-octave noise: what makes die structure look organic, not tiled."""
    acc = np.zeros((h, w), dtype=np.float32)
    amp, tot = 1.0, 0.0
    for i, c in enumerate(octaves):
        acc += amp * _noise(w, h, c, seed + i, smooth=(c < 150))
        tot += amp
        amp *= 0.60
    return acc / tot


def _structure(w, h):
    """Luminance of the die: functional regions with silicon-scale texture.

    Real die shots are not boxes - they are a dense field of thousands of small
    blocks, each slightly different, with routing channels between them. That is
    what this generates, so the metal sheen has something to sit on.
    """
    yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
    x, y = xx / w, yy / h

    # base: fine grain + medium mottling, like polished silicon
    lum = 0.46 + 0.16 * (_noise(w, h, 420, 1) - 0.5) + 0.10 * (_noise(w, h, 90, 2) - 0.5)

    def rect(x0, x1, y0, y1):
        return (x >= x0) & (x <= x1) & (y >= y0) & (y <= y1)

    # ---- Argon2id array: 25 x 15 engines, each its own density -----------
    ax0, ax1, ay0, ay1 = 0.020, 0.760, 0.070, 0.760
    a = rect(ax0, ax1, ay0, ay1)
    cols, rows = 25.0, 15.0
    ti = np.floor((x - ax0) / ((ax1 - ax0) / cols)).astype(np.int32)
    tj = np.floor((y - ay0) / ((ay1 - ay0) / rows)).astype(np.int32)
    # per-engine brightness (broad) sits under the fractal detail
    tile = (((ti * 73856093) ^ (tj * 19349663)) & 255).astype(np.float32) / 255.0
    frac = _fractal(w, h, seed=31)
    engine = 0.30 + 0.20 * tile + 0.46 * frac
    # routing channels between engines
    ch = ((np.fmod((x - ax0), (ax1 - ax0) / cols) < 0.0022) |
          (np.fmod((y - ay0), (ay1 - ay0) / rows) < 0.0030))
    engine = np.where(ch, engine * 0.45, engine)
    lum = np.where(a, engine, lum)

    # ---- 8 HBM3e PHYs: long bundles of vertical wires ---------------------
    px0, px1 = 0.775, 0.985
    ph = rect(px0, px1, 0.05, 0.95)
    stripe = 0.5 + 0.5 * np.sin(yy * 3.1 + 0.7 * np.sin(xx * 0.9))
    phy = 0.52 + 0.30 * stripe
    gaps = (np.fmod(y - 0.05, (0.90) / 8.0) < 0.008)
    phy = np.where(gaps, phy * 0.4, phy)
    lum = np.where(ph, phy, lum)

    # ---- HashX and SHA pools: small, dense, regular lane arrays -----------
    hx = rect(0.020, 0.520, 0.800, 0.960)
    lane = 0.5 + 0.5 * np.sin(xx * 1.9) * np.sin(yy * 2.3)
    lum = np.where(hx, 0.44 + 0.26 * lane, lum)
    sh = rect(0.545, 0.760, 0.800, 0.960)
    lum = np.where(sh, 0.46 + 0.24 * (0.5 + 0.5 * np.sin(xx * 2.4 + yy * 1.7)), lum)

    # ---- IO ring ---------------------------------------------------------
    io_top = rect(0.020, 0.760, 0.010, 0.052)
    lum = np.where(io_top, 0.34 + 0.22 * (0.5 + 0.5 * np.sin(xx * 4.5)), lum)
    io_br = rect(0.775, 0.985, 0.800, 0.960)
    lum = np.where(io_br, 0.30 + 0.16 * (_noise(w, h, 260, 4)), lum)

    # region borders: dark scribe lines
    for x0 in (0.020, 0.520, 0.545, 0.760, 0.775):
        lum = np.where(np.abs(x - x0) < 0.0016, lum * 0.35, lum)
    for y0 in (0.070, 0.760, 0.800, 0.960):
        lum = np.where(np.abs(y - y0) < 0.0016, lum * 0.35, lum)

    # a few thousand tiny metal routing stubs, so nothing looks painted
    rng = np.random.default_rng(12)
    stubs = Image.new("L", (w, h), 0)
    sd = ImageDraw.Draw(stubs)
    for _ in range(2600):
        sx, sy = rng.integers(0, w), rng.integers(0, h)
        if rng.random() < 0.5:
            sd.line([(sx, sy), (sx + rng.integers(6, 40), sy)],
                    fill=int(rng.integers(40, 120)), width=1)
        else:
            sd.line([(sx, sy), (sx, sy + rng.integers(6, 40))],
                    fill=int(rng.integers(40, 120)), width=1)
    stub = np.asarray(stubs).astype(np.float32) / 255.0
    lum = np.clip(lum * (0.94 + 0.12 * stub), 0.05, 1.0)
    return np.clip(lum, 0.05, 1.0)


def render_die_photo(path, final=1000):
    """A delidded-die photograph: metallic, iridescent, functional blocks showing."""
    S = SS
    w = h = final * S
    lum = _structure(w, h)

    # iridescence: fine oil-slick field, plus a per-block hue so patches of the
    # die shimmer differently - that patchwork is most of what a die shot is
    yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
    x, y = xx / w, yy / h
    th = np.arctan2(y - 0.46, x - 0.44)
    rad = np.sqrt((x - 0.44) ** 2 + (y - 0.46) ** 2)
    fine = _noise(w, h, 900, 21)
    med = _noise(w, h, 120, 22)

    # per-engine hue offset
    ax0, ax1, ay0, ay1 = 0.020, 0.760, 0.070, 0.760
    ti = np.clip(np.floor((x - ax0) / ((ax1 - ax0) / 25.0)), 0, 24).astype(np.int32)
    tj = np.clip(np.floor((y - ay0) / ((ay1 - ay0) / 15.0)), 0, 14).astype(np.int32)
    in_a = (x >= ax0) & (x <= ax1) & (y >= ay0) & (y <= ay1)
    hue = (((ti * 73856093) ^ (tj * 19349663)) & 255).astype(np.float32) / 255.0
    hue = np.where(in_a, hue, 0.35)

    # keep the colour field LOW frequency: at high frequency the channels
    # decorrelate and a downsample averages them back to grey
    phase = 9.0 * rad + 2.5 * th + 2.2 * med + 9.0 * hue
    irid = np.stack([
        0.5 + 0.5 * np.sin(phase * 1.00),
        0.5 + 0.5 * np.sin(phase * 1.09 + 2.1),
        0.5 + 0.5 * np.sin(phase * 1.21 + 4.3),
    ], axis=2).astype(np.float32)

    # local contrast, then metal: brightness modulated with the hue kept alive
    lum = np.clip((lum - 0.46) * 1.75 + 0.50, 0.05, 1.0)
    silver = np.array([1.00, 1.01, 1.05], dtype=np.float32)
    rgb = lum[:, :, None] * (silver + 0.22 * (irid - 0.5)) * 255.0

    # directional key light from the upper left, plus a specular hotspot
    key = np.clip(1.32 - 0.62 * (x * 0.75 + y * 0.55), 0.55, 1.45)
    rgb = rgb * key[:, :, None]
    hot = np.exp(-(((x - 0.34) ** 2) / 0.045 + ((y - 0.28) ** 2) / 0.040))
    rgb = rgb + hot[:, :, None] * 40.0
    g = rgb.mean(axis=2, keepdims=True)
    rgb = 0.70 * rgb + 0.30 * g          # steel, with the fringe still visible

    # faint polish marks: thin, low contrast, both light and dark
    rng = np.random.default_rng(5)
    for _ in range(30):
        x0, y0 = int(rng.integers(0, w)), int(rng.integers(0, h))
        dx, dy = int(rng.integers(-w // 3, w // 3)), int(rng.integers(-h // 14, h // 14))
        sign = 1.0 if rng.random() < 0.5 else -1.0
        ov = Image.new("RGB", (w, h), (0, 0, 0))
        ImageDraw.Draw(ov).line([(x0, y0), (x0 + dx, y0 + dy)],
                                fill=tuple(int(120 * (0.35 + 0.5 * rng.random())) for _ in range(3)),
                                width=S)
        rgb = rgb + sign * np.asarray(ov).astype(np.float32) * 0.35

    rgb = np.clip(rgb, 0, 255)
    arr = add_grain(rgb, 2.2)

    # die outline: rounded, slightly irregular edge, dark scribe line
    mask = Image.new("L", (w, h), 0)
    md = ImageDraw.Draw(mask)
    m = int(w * 0.012)
    md.rounded_rectangle([m, m, w - m, h - m], radius=int(w * 0.020), fill=255)
    ma = np.asarray(mask).astype(np.float32) / 255.0
    rgb = rgb * (0.92 + 0.08 * ma)[:, :, None]

    arr = add_grain(np.clip(rgb, 0, 255), 2.6)   # rgb is already 0..255 here

    im = Image.fromarray(arr.astype(np.uint8))
    im = im.filter(ImageFilter.GaussianBlur(0.6 * S))

    # studio background + soft shadow, so it reads as a photo
    canvas = Image.new("RGB", (w, h), (44, 42, 40))
    bg = linear_gradient(w, h, (56, 54, 52), (30, 29, 28))
    yy2, xx2 = np.mgrid[0:h, 0:w].astype(np.float32)
    glow = np.exp(-(((xx2 - w * 0.5) / (w * 0.7)) ** 2 + ((yy2 - h * 0.42) / (h * 0.7)) ** 2))
    bg = bg + glow[:, :, None] * 16.0
    canvas = Image.fromarray(np.clip(bg, 0, 255).astype(np.uint8))

    sh = Image.new("L", (w, h), 0)
    ImageDraw.Draw(sh).rounded_rectangle([m + 8 * S, m + 14 * S, w - m + 6 * S, h - m + 12 * S],
                                         radius=int(w * 0.02), fill=150)
    sh = sh.filter(ImageFilter.GaussianBlur(16 * S / 4))
    canvas = Image.composite(Image.new("RGB", (w, h), (18, 17, 16)), canvas, sh.point(lambda v: v))

    canvas.paste(im, (0, 0), Image.fromarray((ma * 255).astype(np.uint8)))

    out = canvas.resize((final, final), Image.LANCZOS)
    path.parent.mkdir(parents=True, exist_ok=True)
    out.save(path)
    print("wrote", path, out.size)


# -------------------------------------------------------------------- sticker
def render_sticker(path, final=900):
    """The blue foil badge, to sit next to the die the way the Intel pair does."""
    S = SS
    w = final * S
    img = rgba(w, w, (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    m = int(w * 0.06)
    box = [m, m, w - m, w - m]
    r = int(w * 0.07)

    # foil: blue with a brushed metal gradient
    foil = linear_gradient(w, w, (26, 92, 196), (12, 40, 116))
    yy, xx = np.mgrid[0:w, 0:w].astype(np.float32)
    brush = (np.sin(xx * 0.06) * 5.0 + np.sin(yy * 0.9) * 2.5)[:, :, None]
    foil = np.clip(foil + brush, 0, 255)
    spec = np.clip(1.0 + 0.35 * np.sin((xx / w * 1.7 + yy / w * 0.9) * np.pi), 0.7, 1.45)
    foil = np.clip(foil * spec[:, :, None], 0, 255)
    foil_im = Image.fromarray(foil.astype(np.uint8)).convert("RGBA")

    mk = rgba(w, w, (0, 0, 0, 0))
    ImageDraw.Draw(mk).rounded_rectangle(box, radius=r, fill=(255, 255, 255, 255))
    img.paste(foil_im, (0, 0), mk)

    # inner white plate
    inset = int(w * 0.115)
    plate = [box[0] + inset, box[1] + inset, box[2] - inset, box[3] - inset]
    d.rounded_rectangle(plate, radius=int(w * 0.035), fill=(244, 246, 250, 255))
    d.rounded_rectangle(plate, radius=int(w * 0.035),
                        outline=(208, 216, 232, 255), width=max(1, 2 * S))

    cx = w / 2
    d.text((cx, plate[1] + w * 0.085), "ANUBIS", font=font(SANS_B, int(w * 0.145)),
           fill=(28, 44, 92, 255), anchor="ma")
    d.text((cx, plate[1] + w * 0.245), "365", font=font(SANS_B, int(w * 0.105)),
           fill=(52, 84, 156, 255), anchor="ma")
    d.text((cx, plate[1] + w * 0.365), "ARGON2ID - HASHX - SHA-256",
           font=font(MONO, int(w * 0.040)), fill=(70, 88, 128, 255), anchor="ma")

    # the same "powered by dsh" strip the mascot wears
    bw, bh = int(w * 0.48), int(w * 0.088)
    bx0, by0 = int(cx - bw / 2), int(plate[3] + w * 0.020)
    d.rounded_rectangle([bx0, by0, bx0 + bw, by0 + bh], radius=int(bh * 0.18),
                        fill=(58, 58, 62, 255))
    d.rectangle([bx0 + bw - int(bh * 1.55), by0, bx0 + bw, by0 + bh],
                fill=(46, 110, 232, 255))
    d.text((bx0 + int(bh * 0.26), by0 + bh / 2), "powered by",
           font=font(MONO, int(bh * 0.38)), fill=(232, 234, 240, 255), anchor="lm")
    d.text((bx0 + bw - int(bh * 0.78), by0 + bh / 2), "dsh",
           font=font(SANS_B, int(bh * 0.52)), fill=(255, 255, 255, 255), anchor="rm")

    arr = np.asarray(img.convert("RGB")).astype(np.float32)
    arr = add_grain(vignette(arr, 0.30), 2.0)
    out = Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8))
    out = out.resize((final, final), Image.LANCZOS)
    path.parent.mkdir(parents=True, exist_ok=True)
    out.save(path)
    print("wrote", path, out.size)


if __name__ == "__main__":
    np.random.seed(11)
    render_package_back(OUT / "anubis-365-package-back.png")
    render_die(OUT / "anubis-365-die.png")
    render_die_photo(OUT / "anubis-365-die-photo.png")
    render_sticker(OUT / "anubis-365-sticker.png")

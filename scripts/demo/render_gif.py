#!/usr/bin/env python3
"""Render scripts/demo/transcript.txt into docs/assets/demo.gif (+ demo.png).

Dev dependency: Pillow (see scripts/demo/README.md). Lines starting with "$ "
are typed character by character; other lines appear one at a time.
"""
import os
import re
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
TRANSCRIPT = ROOT / "scripts" / "demo" / "transcript.txt"
OUT_GIF = ROOT / "docs" / "assets" / "demo.gif"
OUT_PNG = ROOT / "docs" / "assets" / "demo.png"

W = 900
FONT_SIZE = 15
LINE_H = 21
PAD = 18
BAR_H = 32
BG = (22, 24, 29)
BAR = (38, 41, 49)
FG = (212, 216, 224)
DIM = (125, 133, 148)
PROMPT = (110, 200, 140)
RED = (240, 92, 92)
YELLOW = (235, 190, 70)
GREEN = (110, 200, 140)

FONT_CANDIDATES = [
    "C:/Windows/Fonts/consola.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
    "DejaVuSansMono.ttf",
]


def load_font():
    for p in FONT_CANDIDATES:
        try:
            return ImageFont.truetype(p, FONT_SIZE)
        except OSError:
            continue
    sys.exit("no monospace font found (install DejaVu Sans Mono)")


FONT = load_font()
CW = FONT.getlength("M")
TOKEN = re.compile(r"(\bHIGH\b|\bMEDIUM\b|\bLOW\b|\bAD-[A-Z]+-\d+\b|\b\d+ findings\b)")


def color_for(tok):
    if tok == "HIGH":
        return RED
    if tok == "MEDIUM":
        return YELLOW
    if tok == "LOW":
        return GREEN
    if tok.startswith("AD-"):
        return (130, 170, 255)
    return FG


def draw_line(d, x, y, text, cursor=False):
    if text.startswith("$ "):
        d.text((x, y), "$", font=FONT, fill=PROMPT)
        d.text((x + CW * 2, y), text[2:], font=FONT, fill=FG)
        end = x + CW * len(text)
    elif text == "...":
        d.text((x, y), text, font=FONT, fill=DIM)
        end = x + CW * len(text)
    else:
        cx = x
        for part in TOKEN.split(text):
            if not part:
                continue
            d.text((cx, y), part, font=FONT, fill=color_for(part))
            cx += CW * len(part)
        end = cx
    if cursor:
        d.rectangle([end + 2, y + 2, end + 2 + CW * 0.6, y + LINE_H - 3], fill=FG)


def frame(lines, height, cursor=True):
    im = Image.new("RGB", (W, height), BG)
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, W, BAR_H], fill=BAR)
    for i, c in enumerate([(240, 92, 92), (235, 190, 70), (110, 200, 140)]):
        d.ellipse([16 + i * 22, 10, 28 + i * 22, 22], fill=c)
    d.text((W // 2 - 60, 8), "authdiff demo", font=FONT, fill=DIM)
    # keep the last visible lines that fit
    cap = (height - BAR_H - PAD * 2) // LINE_H
    vis = lines[-cap:]
    y = BAR_H + PAD
    for i, ln in enumerate(vis):
        draw_line(d, PAD, y, ln, cursor and i == len(vis) - 1)
        y += LINE_H
    return im


def main():
    src = TRANSCRIPT.read_text(encoding="utf-8").rstrip("\n").split("\n")
    n = len(src)
    height = BAR_H + PAD * 2 + LINE_H * 24  # fixed window; older lines scroll off
    frames, durs = [], []

    def add(lines, ms, cursor=True):
        frames.append(frame(lines, height, cursor))
        durs.append(ms)

    shown = []
    add([""], 600)
    for ln in src:
        if ln.startswith("$ "):
            shown.append("")
            step = 3
            for k in range(2, len(ln) + step, step):
                shown[-1] = ln[: min(k, len(ln))]
                add(shown, 55)
            add(shown, 450)
        else:
            shown.append(ln)
            add(shown, 90 if ln.strip() else 160)
    add(shown, 4000, cursor=False)

    palette_frames = [f.quantize(colors=32, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE) for f in frames]
    OUT_GIF.parent.mkdir(parents=True, exist_ok=True)
    palette_frames[0].save(
        OUT_GIF, save_all=True, append_images=palette_frames[1:],
        duration=durs, loop=0, optimize=True, disposal=1,
    )
    frames[-1].save(OUT_PNG, optimize=True)
    print(f"{OUT_GIF} {OUT_GIF.stat().st_size/1024:.0f} KiB, {len(frames)} frames; {n} transcript lines")


if __name__ == "__main__":
    main()

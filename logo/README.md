# RCEKit logo

The mark is the tool's own mechanism. An open circuit — the probe leaves. A
wedge driving back in through the opening — the value returns. A dot at the
centre — the verdict it earned. The wedge's back sits on the ring's own curve,
so the arrow is part of the circuit rather than something floating beside it,
and the open ring reads as the `C` of RCE.

Geometrically the whole mark fits a 44.5-unit square centred in a 64-unit box,
so it centres by its bounding box in any frame without optical correction.

## Files

| File | Size | Use |
|---|---|---|
| `rcekit-social-1280x640.*` | 1280 × 640 | GitHub **Social preview** (Settings → General → Social preview) |
| `rcekit-banner.*` | 1280 × 320 | Wide banner at the top of `README.md` |
| `rcekit-avatar.*` | 460 × 460 | GitHub organisation / user avatar |
| `rcekit-logo-dark.*` | 354 × 140 | Horizontal lockup, baked dark ground |
| `rcekit-logo-light.*` | 354 × 140 | Horizontal lockup for light grounds, transparent |
| `rcekit-logo-mono-white.*` | 354 × 140 | One-colour white, for photos and dark UI |
| `rcekit-logo-stacked.*` | 260 × 142 | Stacked lockup for narrow or square space |
| `rcekit-mark.*` / `-ink` | 64 × 64 | Mark alone, mint and single-colour ink |
| `rcekit-favicon.*` | 64 × 64 | Heavier redraw that survives 16–24 px |

Every `.svg` has a matching `.png` rendered at 2–16× (the social card is exact
at 1280 × 640). Use the SVG wherever the renderer allows it; GitHub strips
external font references from SVGs shown as images, so the **PNG is the safe
choice inside `README.md`**.

## Colour

| Token | Hex | Role |
|---|---|---|
| Ink | `#0B0E11` | Ground |
| Paper | `#F2F1ED` | Wordmark on dark |
| Mint | `#3DDC97` | Mark and `executed` on dark — 12.9:1 on Ink |
| Mint deep | `#0F9C68` | Mark on light grounds — 3.1:1 on Paper |
| Slate | `#8A95A1` | Supporting copy on dark |
| Steel | `#5A646E` | Meta copy |

Mint carries one meaning: *confirmed*. Weaker tiers stay outlined and grey, the
way the tool refuses to promote a signal into `executed`.

## Type

**JetBrains Mono ExtraBold** for the wordmark, tracked −0.03 em; **Inter
Regular** for the tagline. Both are SIL OFL. The SVGs name a monospace fallback
stack, so a machine without JetBrains Mono renders a near but not identical
wordmark — another reason to ship the PNG where exactness matters.

## Clear space and minimum size

Keep clear space equal to the diameter of the centre dot on every side of the
lockup. Minimum: 24 px tall for the horizontal lockup, 16 px for the mark. Below
32 px use `rcekit-favicon`, which carries a heavier stroke and a wider opening
so the dot does not fill in.

Do not recolour the mark outside the two approved greens, rotate it, mirror it,
add a gradient or an outer glow, or set the wordmark in another typeface.

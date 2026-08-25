"""Design tokens: one accent, one font family, an 8 px spacing scale, two themes.

Every colour in the UI comes from here. CustomTkinter accepts a ``(light, dark)``
tuple for most colour options and picks the right one for the current appearance
mode, so tokens are defined as pairs and widgets never branch on the theme
themselves.
"""

from __future__ import annotations

import tkinter.font as tkfont
from typing import Literal

import customtkinter as ctk

# --- spacing: multiples of 8, with a 4 for tight pairings --------------------------------

SPACE_XS = 4
SPACE_SM = 8
SPACE_MD = 16
SPACE_LG = 24
SPACE_XL = 32

RADIUS_SM = 6
RADIUS_MD = 10
RADIUS_LG = 14

# --- colour tokens: (light, dark) --------------------------------------------------------

ACCENT = ("#2563eb", "#5b8cff")
ACCENT_HOVER = ("#1d4ed8", "#7aa2ff")
ACCENT_MUTED = ("#dbeafe", "#1e2a4a")

BG_APP = ("#f4f5f7", "#16181d")
BG_PANEL = ("#ffffff", "#1e2127")
BG_ELEVATED = ("#f9fafb", "#252932")
BG_INPUT = ("#ffffff", "#252932")
BG_OWN_MESSAGE = ("#eff4ff", "#1c2333")
BG_HOVER = ("#eef0f4", "#2a2f3a")

TEXT_PRIMARY = ("#111827", "#e8eaed")
TEXT_SECONDARY = ("#4b5563", "#a8adb7")
TEXT_MUTED = ("#6b7280", "#7d838f")
TEXT_ON_ACCENT = ("#ffffff", "#0d1117")

BORDER = ("#e2e5ea", "#2c313a")

STATUS_OK = ("#16a34a", "#3ddc84")
STATUS_WARN = ("#d97706", "#f5b544")
STATUS_ERROR = ("#dc2626", "#ff6b6b")

# Roster and message-author avatar palette, indexed by a hash of the user id.
# Chosen to stay legible against both panel backgrounds.
AVATAR_COLORS: tuple[tuple[str, str], ...] = (
    ("#2563eb", "#5b8cff"),
    ("#0891b2", "#22d3ee"),
    ("#059669", "#34d399"),
    ("#65a30d", "#a3e635"),
    ("#ca8a04", "#facc15"),
    ("#ea580c", "#fb923c"),
    ("#dc2626", "#f87171"),
    ("#db2777", "#f472b6"),
    ("#9333ea", "#c084fc"),
    ("#4f46e5", "#818cf8"),
)

# --- fonts --------------------------------------------------------------------------------

_PREFERRED_FAMILIES = (
    "Inter",
    "Segoe UI",
    "SF Pro Text",
    "Helvetica Neue",
    "Ubuntu",
    "Cantarell",
    "DejaVu Sans",
)
_PREFERRED_MONO = ("JetBrains Mono", "SF Mono", "Cascadia Mono", "Ubuntu Mono", "DejaVu Sans Mono")

SIZE_SM = 11
SIZE_MD = 13
SIZE_LG = 15
SIZE_XL = 19

_family_cache: dict[str, str] = {}


def _pick_family(candidates: tuple[str, ...], fallback: str) -> str:
    """First candidate the system actually has, so we never fall back to Tk's default."""
    cache_key = candidates[0]
    if cache_key in _family_cache:
        return _family_cache[cache_key]
    try:
        available = {name.lower() for name in tkfont.families()}
    except RuntimeError:
        return fallback  # no Tk root yet
    chosen = next((c for c in candidates if c.lower() in available), fallback)
    _family_cache[cache_key] = chosen
    return chosen


def font(
    size: int = SIZE_MD,
    weight: Literal["normal", "bold"] = "normal",
    *,
    mono: bool = False,
    slant: Literal["roman", "italic"] = "roman",
) -> ctk.CTkFont:
    family = (
        _pick_family(_PREFERRED_MONO, "TkFixedFont")
        if mono
        else _pick_family(_PREFERRED_FAMILIES, "TkDefaultFont")
    )
    return ctk.CTkFont(family=family, size=size, weight=weight, slant=slant)


# --- appearance ----------------------------------------------------------------------------


def apply(mode: str = "dark") -> None:
    """Set the global appearance mode. ``dark``, ``light`` or ``system``."""
    ctk.set_appearance_mode(mode)
    ctk.set_default_color_theme("blue")


def current_mode() -> str:
    return ctk.get_appearance_mode().lower()


def pick(pair: tuple[str, str]) -> str:
    """Resolve a (light, dark) token to a single colour for raw Tk widgets.

    CustomTkinter widgets take the tuple directly; a bare Canvas does not.
    """
    return pair[1] if current_mode() == "dark" else pair[0]


def avatar_color(user_id: str) -> tuple[str, str]:
    """A stable colour for a user, so they look the same in the roster and the log."""
    digest = sum(byte * (i + 1) for i, byte in enumerate(user_id.encode("utf-8")))
    return AVATAR_COLORS[digest % len(AVATAR_COLORS)]


def initial(name: str) -> str:
    """The character to draw inside an avatar."""
    stripped = name.strip()
    return stripped[0].upper() if stripped else "?"

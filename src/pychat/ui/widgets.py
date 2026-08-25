"""Reusable pieces of the chat window: avatars, roster rows, message rows, status pill.

Each widget owns its own layout and exposes a small ``refresh_theme`` so the window can
switch between light and dark without rebuilding anything.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from tkinter import font as tkfont
from typing import ClassVar

import customtkinter as ctk

from . import theme


class Avatar(ctk.CTkCanvas):
    """A circular initial badge, coloured deterministically from the user id."""

    def __init__(self, master, user_id: str, name: str, size: int = 28, **kwargs):
        super().__init__(
            master,
            width=size,
            height=size,
            highlightthickness=0,
            borderwidth=0,
            **kwargs,
        )
        self._size = size
        self._user_id = user_id
        self._name = name
        self.refresh_theme()

    def set_user(self, user_id: str, name: str) -> None:
        self._user_id, self._name = user_id, name
        self.refresh_theme()

    def refresh_theme(self, background: tuple[str, str] = theme.BG_PANEL) -> None:
        self.delete("all")
        self.configure(background=theme.pick(background))
        fill = theme.pick(theme.avatar_color(self._user_id))
        pad = 1
        self.create_oval(pad, pad, self._size - pad, self._size - pad, fill=fill, outline="")
        self.create_text(
            self._size / 2,
            self._size / 2 + 1,
            text=theme.initial(self._name),
            fill="#ffffff",
            font=(
                theme._pick_family(theme._PREFERRED_FAMILIES, "TkDefaultFont"),
                max(9, int(self._size * 0.42)),
                "bold",
            ),
        )


class RosterRow(ctk.CTkFrame):
    """One person in the online list."""

    def __init__(self, master, user_id: str, name: str, *, is_self: bool = False, **kwargs):
        super().__init__(master, fg_color="transparent", corner_radius=theme.RADIUS_SM, **kwargs)
        self.user_id = user_id

        self.avatar = Avatar(self, user_id, name, size=26)
        self.avatar.grid(
            row=0, column=0, padx=(theme.SPACE_SM, theme.SPACE_SM), pady=theme.SPACE_XS
        )

        label = f"{name} (You)" if is_self else name
        self.label = ctk.CTkLabel(
            self,
            text=label,
            anchor="w",
            font=theme.font(theme.SIZE_MD, "bold" if is_self else "normal"),
            text_color=theme.ACCENT if is_self else theme.TEXT_PRIMARY,
        )
        self.label.grid(row=0, column=1, sticky="ew", padx=(0, theme.SPACE_SM))
        self.grid_columnconfigure(1, weight=1)

    def refresh_theme(self) -> None:
        self.avatar.refresh_theme()


class MessageRow(ctk.CTkFrame):
    """One chat message.

    ``grouped`` suppresses the author header for a run of consecutive messages from the
    same person, which keeps a busy log readable.
    """

    def __init__(
        self,
        master,
        *,
        user_id: str,
        name: str,
        text: str,
        ts: float,
        is_own: bool,
        grouped: bool = False,
        **kwargs,
    ):
        super().__init__(
            master,
            fg_color=theme.BG_OWN_MESSAGE if is_own else "transparent",
            corner_radius=theme.RADIUS_MD,
            **kwargs,
        )
        self.grid_columnconfigure(1, weight=1)
        self._is_own = is_own
        self._avatar: Avatar | None = None

        body_row = 0
        if not grouped:
            self._avatar = Avatar(self, user_id, name, size=28)
            self._avatar.grid(
                row=0,
                column=0,
                sticky="n",
                padx=(theme.SPACE_SM, theme.SPACE_SM),
                pady=(theme.SPACE_SM, 0),
            )

            header = ctk.CTkFrame(self, fg_color="transparent")
            header.grid(
                row=0, column=1, sticky="ew", pady=(theme.SPACE_SM, 0), padx=(0, theme.SPACE_SM)
            )
            ctk.CTkLabel(
                header,
                text=name,
                font=theme.font(theme.SIZE_MD, "bold"),
                text_color=theme.ACCENT if is_own else theme.TEXT_PRIMARY,
            ).pack(side="left")
            ctk.CTkLabel(
                header,
                text=datetime.fromtimestamp(ts).strftime("%H:%M"),
                font=theme.font(theme.SIZE_SM),
                text_color=theme.TEXT_MUTED,
            ).pack(side="left", padx=(theme.SPACE_SM, 0))
            body_row = 1

        body = SelectableText(
            self,
            text=text,
            font=theme.font(theme.SIZE_MD),
            text_color=theme.TEXT_PRIMARY,
        )
        body.grid(
            row=body_row,
            column=1,
            sticky="ew",
            padx=(0, theme.SPACE_SM),
            pady=(theme.SPACE_XS if not grouped else 0, theme.SPACE_SM),
        )
        # Reserve the avatar gutter so grouped messages line up under their header.
        self.grid_columnconfigure(0, minsize=28 + theme.SPACE_SM * 2)
        self._body = body

    def refresh_theme(self) -> None:
        if self._avatar is not None:
            self._avatar.refresh_theme(theme.BG_OWN_MESSAGE if self._is_own else theme.BG_PANEL)


class SelectableText(ctk.CTkTextbox):
    """A read-only text block that still supports selection and copying.

    A CTkLabel cannot be selected and a plain Textbox does not size itself to its
    content, so this recomputes its own height from the number of *display* lines
    whenever its width changes. Getting this wrong clips the last line of a wrapped
    message when the window is narrow, which is exactly what a minimum-size check
    is meant to catch.
    """

    def __init__(self, master, *, text: str, **kwargs):
        super().__init__(
            master,
            fg_color="transparent",
            border_width=0,
            activate_scrollbars=False,
            wrap="word",
            height=22,
            **kwargs,
        )
        self.insert("1.0", text)
        self.configure(state="disabled")
        self._last_width = -1
        self._pending_measure: str | None = None
        self.bind("<Configure>", self._resize)

    def _line_height(self) -> int:
        """Height of one rendered display line, in real pixels."""
        try:
            info = self._textbox.dlineinfo("1.0")
            if info and info[3]:
                return int(info[3])
        except Exception:
            pass
        try:
            return tkfont.Font(font=self._textbox.cget("font")).metrics("linespace")
        except Exception:
            return 18

    def _chrome_height(self) -> int:
        """Vertical space the CTkTextbox spends on its own border and padding.

        The height passed to configure() covers the whole widget, but only the inner
        Text widget renders the message, so this has to be added on top of the content
        height or the last line falls outside the visible area.
        """
        try:
            pad = self.winfo_height() - self._textbox.winfo_height()
        except Exception:
            return 12
        return pad if 0 <= pad <= 40 else 12

    def _content_height(self) -> int:
        """Pixels needed to show the whole wrapped message.

        Tk's ``count`` reports the *distance between* two indices, so a single display
        line measures zero and a three-line message measures two lines' worth. One line
        height therefore has to be added back — getting this wrong silently clips the
        last line of every wrapped message once the window is narrow.
        """
        line_height = self._line_height()
        try:
            measured = self._textbox.count("1.0", "end-1c", "ypixels")
            span = int(measured[0]) if measured else 0
        except Exception:
            span = 0
        return span + line_height

    def _resize(self, _event=None) -> None:
        """React to a width change by remeasuring on the next idle pass.

        The measurement is deferred because <Configure> fires on this frame before
        CustomTkinter has re-laid-out the Text widget inside it. Measuring immediately
        wraps the text at the *previous* width, which is how the last line of a message
        ends up clipped after the window is narrowed.
        """
        width = self.winfo_width()
        if abs(width - self._last_width) < 2:
            return
        self._last_width = width
        if self._pending_measure is None:
            self._pending_measure = self.after_idle(self._apply_height)

    def _apply_height(self) -> None:
        self._pending_measure = None
        try:
            self.update_idletasks()
            needed = self._content_height() + self._chrome_height()
            # configure() takes unscaled units while the measurements are real pixels.
            scaling = self._get_widget_scaling() or 1.0
            self.configure(height=max(22, int(needed / scaling) + 2))
        except Exception:
            return


class SystemRow(ctk.CTkFrame):
    """A centred, muted notice: joins, leaves, reconnect attempts."""

    def __init__(self, master, text: str, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            self,
            text=f"—  {text}  —",
            font=theme.font(theme.SIZE_SM, slant="italic"),
            text_color=theme.TEXT_MUTED,
            wraplength=520,
        ).grid(row=0, column=0, pady=theme.SPACE_SM)

    def refresh_theme(self) -> None:
        pass


class ErrorRow(ctk.CTkFrame):
    """A server-sent error: rate limits, over-length messages."""

    def __init__(self, master, text: str, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            self,
            text=f"⚠  {text}",
            font=theme.font(theme.SIZE_SM),
            text_color=theme.STATUS_ERROR,
            wraplength=520,
            anchor="w",
            justify="left",
        ).grid(row=0, column=0, sticky="ew", padx=theme.SPACE_MD, pady=theme.SPACE_XS)

    def refresh_theme(self) -> None:
        pass


class StatusPill(ctk.CTkFrame):
    """The connection indicator: a coloured dot plus a word, reason on hover."""

    STATES: ClassVar[dict[str, tuple[tuple[str, str], str]]] = {
        "connected": (theme.STATUS_OK, "Connected"),
        "connecting": (theme.STATUS_WARN, "Connecting…"),
        "reconnecting": (theme.STATUS_WARN, "Reconnecting…"),
        "disconnected": (theme.STATUS_ERROR, "Disconnected"),
    }

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._state = "connecting"
        self._reason = ""

        self.dot = ctk.CTkCanvas(self, width=10, height=10, highlightthickness=0, borderwidth=0)
        self.dot.pack(side="left", padx=(0, theme.SPACE_SM))
        self.label = ctk.CTkLabel(self, text="", font=theme.font(theme.SIZE_SM))
        self.label.pack(side="left")

        self._tip = Tooltip(self)
        for widget in (self, self.dot, self.label):
            widget.bind("<Enter>", self._show_tip)
            widget.bind("<Leave>", self._hide_tip)
        self.set_state("connecting")

    def set_state(self, state: str, reason: str = "") -> None:
        self._state = state
        self._reason = reason
        colour, text = self.STATES.get(state, self.STATES["disconnected"])
        self.label.configure(text=text, text_color=colour)
        self.refresh_theme()

    def refresh_theme(self) -> None:
        colour, _ = self.STATES.get(self._state, self.STATES["disconnected"])
        self.dot.configure(background=theme.pick(theme.BG_PANEL))
        self.dot.delete("all")
        self.dot.create_oval(1, 1, 9, 9, fill=theme.pick(colour), outline="")

    def _show_tip(self, _event=None) -> None:
        if self._reason:
            self._tip.show(self._reason)

    def _hide_tip(self, _event=None) -> None:
        self._tip.hide()


class Tooltip:
    """A minimal hover tooltip. CustomTkinter does not ship one."""

    def __init__(self, widget: ctk.CTkBaseClass) -> None:
        self._widget = widget
        self._window: ctk.CTkToplevel | None = None

    def show(self, text: str) -> None:
        if self._window is not None or not text:
            return
        x = self._widget.winfo_rootx()
        y = self._widget.winfo_rooty() + self._widget.winfo_height() + theme.SPACE_XS
        window = ctk.CTkToplevel(self._widget)
        window.wm_overrideredirect(True)
        window.wm_geometry(f"+{x}+{y}")
        window.attributes("-topmost", True)
        frame = ctk.CTkFrame(
            window,
            fg_color=theme.BG_ELEVATED,
            corner_radius=theme.RADIUS_SM,
            border_width=1,
            border_color=theme.BORDER,
        )
        frame.pack()
        ctk.CTkLabel(
            frame,
            text=text,
            font=theme.font(theme.SIZE_SM),
            text_color=theme.TEXT_SECONDARY,
            wraplength=320,
            justify="left",
        ).pack(padx=theme.SPACE_SM, pady=theme.SPACE_XS)
        self._window = window

    def hide(self) -> None:
        if self._window is not None:
            self._window.destroy()
            self._window = None


class IconButton(ctk.CTkButton):
    """A small square button used for the theme toggle and the settings affordance."""

    def __init__(self, master, text: str, command: Callable[[], None], **kwargs):
        super().__init__(
            master,
            text=text,
            command=command,
            width=32,
            height=32,
            corner_radius=theme.RADIUS_SM,
            fg_color="transparent",
            hover_color=theme.BG_HOVER,
            text_color=theme.TEXT_SECONDARY,
            font=theme.font(theme.SIZE_LG),
            **kwargs,
        )


def autohide_scrollbar(frame: ctk.CTkScrollableFrame) -> Callable[[], None]:
    """Hide a scrollable frame's scrollbar while its content fits.

    A permanently visible scrollbar track over an empty roster is the sort of detail
    that makes an interface look unfinished. Returns a callable to re-check after
    content changes.
    """
    canvas = frame._parent_canvas
    scrollbar = frame._scrollbar

    def check(_event=None) -> None:
        try:
            first, last = canvas.yview()
        except Exception:
            return
        if first <= 0.0 and last >= 1.0:
            scrollbar.grid_remove()
        else:
            scrollbar.grid()

    canvas.bind("<Configure>", check, add="+")
    return check

"""The launch dialog: where to connect, as whom, and with which room password."""

from __future__ import annotations

from collections.abc import Callable

import customtkinter as ctk

from .. import net
from .. import protocol as p
from . import theme


class Field(ctk.CTkFrame):
    """A labelled entry with an inline error slot underneath it."""

    def __init__(self, master, label: str, *, show: str | None = None, width: int = 320, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self,
            text=label,
            font=theme.font(theme.SIZE_SM, "bold"),
            text_color=theme.TEXT_SECONDARY,
            anchor="w",
        ).grid(row=0, column=0, sticky="ew", pady=(0, theme.SPACE_XS))

        self.entry = ctk.CTkEntry(
            self,
            width=width,
            height=36,
            show=show,
            corner_radius=theme.RADIUS_SM,
            border_color=theme.BORDER,
            fg_color=theme.BG_INPUT,
            text_color=theme.TEXT_PRIMARY,
            font=theme.font(theme.SIZE_MD),
        )
        self.entry.grid(row=1, column=0, sticky="ew")

        self._error = ctk.CTkLabel(
            self,
            text="",
            font=theme.font(theme.SIZE_SM),
            text_color=theme.STATUS_ERROR,
            anchor="w",
            wraplength=width,
            justify="left",
        )
        self._error.grid(row=2, column=0, sticky="ew", pady=(theme.SPACE_XS, 0))
        self._error.grid_remove()

    @property
    def value(self) -> str:
        return self.entry.get().strip()

    def set(self, value: str) -> None:
        self.entry.delete(0, "end")
        self.entry.insert(0, value)

    def show_error(self, message: str) -> None:
        self._error.configure(text=message)
        self._error.grid()
        self.entry.configure(border_color=theme.STATUS_ERROR)

    def clear_error(self) -> None:
        self._error.grid_remove()
        self.entry.configure(border_color=theme.BORDER)

    def set_enabled(self, enabled: bool) -> None:
        self.entry.configure(state="normal" if enabled else "disabled")


class ConnectDialog(ctk.CTkToplevel):
    """Collects connection details, then hands them back through ``on_connect``.

    The dialog stays open and responsive while the connection is attempted, so a
    failure can put the user back in front of the values they typed.
    """

    def __init__(
        self,
        master,
        *,
        on_connect: Callable[[net.Settings, bool], None],
        on_cancel: Callable[[], None],
    ):
        super().__init__(master)
        self.title("Connect to pychat")
        self.resizable(False, False)
        self.configure(fg_color=theme.BG_APP)
        self._on_connect = on_connect
        self._on_cancel = on_cancel
        self._connecting = False

        prefs = net.load_prefs()
        self._build(prefs)
        self._center()

        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.bind("<Escape>", lambda _e: self._cancel())
        self.bind("<Return>", lambda _e: self._submit())
        self.after(120, self._grab)

    # --- construction -------------------------------------------------------------------

    def _build(self, prefs: dict) -> None:
        outer = ctk.CTkFrame(self, fg_color="transparent")
        outer.pack(padx=theme.SPACE_XL, pady=theme.SPACE_XL, fill="both", expand=True)

        ctk.CTkLabel(
            outer,
            text="pychat",
            font=theme.font(theme.SIZE_XL + 6, "bold"),
            text_color=theme.TEXT_PRIMARY,
        ).pack(anchor="w")
        ctk.CTkLabel(
            outer,
            text="Encrypted group chat. Everything below stays on this machine.",
            font=theme.font(theme.SIZE_SM),
            text_color=theme.TEXT_MUTED,
        ).pack(anchor="w", pady=(theme.SPACE_XS, theme.SPACE_LG))

        row = ctk.CTkFrame(outer, fg_color="transparent")
        row.pack(fill="x")
        self.host = Field(row, "Server", width=228)
        self.host.pack(side="left")
        self.port = Field(row, "Port", width=80)
        self.port.pack(side="left", padx=(theme.SPACE_SM, 0))

        self.name = Field(outer, "Display name", width=320)
        self.name.pack(fill="x", pady=(theme.SPACE_MD, 0))

        self.password = Field(outer, "Room password", show="•", width=320)
        self.password.pack(fill="x", pady=(theme.SPACE_MD, 0))
        self._reveal = ctk.CTkCheckBox(
            outer,
            text="Show password",
            font=theme.font(theme.SIZE_SM),
            text_color=theme.TEXT_SECONDARY,
            checkbox_width=16,
            checkbox_height=16,
            corner_radius=theme.RADIUS_SM,
            fg_color=theme.ACCENT,
            hover_color=theme.ACCENT_HOVER,
            border_color=theme.BORDER,
            command=self._toggle_reveal,
        )
        self._reveal.pack(anchor="w", pady=(theme.SPACE_SM, 0))

        self._remember = ctk.CTkCheckBox(
            outer,
            text="Remember server and name (never the password)",
            font=theme.font(theme.SIZE_SM),
            text_color=theme.TEXT_SECONDARY,
            checkbox_width=16,
            checkbox_height=16,
            corner_radius=theme.RADIUS_SM,
            fg_color=theme.ACCENT,
            hover_color=theme.ACCENT_HOVER,
            border_color=theme.BORDER,
        )
        self._remember.pack(anchor="w", pady=(theme.SPACE_SM, 0))

        self.status = ctk.CTkLabel(
            outer,
            text="",
            font=theme.font(theme.SIZE_SM),
            text_color=theme.TEXT_MUTED,
            wraplength=320,
            justify="left",
            anchor="w",
        )
        self.status.pack(fill="x", pady=(theme.SPACE_MD, 0))

        self.progress = ctk.CTkProgressBar(
            outer, height=3, corner_radius=2, progress_color=theme.ACCENT
        )
        self.progress.pack(fill="x", pady=(theme.SPACE_SM, 0))
        self.progress.pack_forget()

        buttons = ctk.CTkFrame(outer, fg_color="transparent")
        buttons.pack(fill="x", pady=(theme.SPACE_LG, 0))
        self.cancel_button = ctk.CTkButton(
            buttons,
            text="Quit",
            width=88,
            height=38,
            corner_radius=theme.RADIUS_SM,
            fg_color="transparent",
            border_width=1,
            border_color=theme.BORDER,
            text_color=theme.TEXT_SECONDARY,
            hover_color=theme.BG_HOVER,
            font=theme.font(theme.SIZE_MD),
            command=self._cancel,
        )
        self.cancel_button.pack(side="left")
        self.connect_button = ctk.CTkButton(
            buttons,
            text="Connect",
            width=140,
            height=38,
            corner_radius=theme.RADIUS_SM,
            fg_color=theme.ACCENT,
            hover_color=theme.ACCENT_HOVER,
            text_color=theme.TEXT_ON_ACCENT,
            font=theme.font(theme.SIZE_MD, "bold"),
            command=self._submit,
        )
        self.connect_button.pack(side="right")

        self.host.set(str(prefs.get("host") or "localhost"))
        self.port.set(str(prefs.get("port") or 8765))
        self.name.set(str(prefs.get("name") or ""))
        if prefs.get("host") or prefs.get("name"):
            self._remember.select()

        first_empty = self.name if not self.name.value else self.password
        first_empty.entry.focus_set()

    def _center(self) -> None:
        self.update_idletasks()
        width, height = self.winfo_reqwidth(), self.winfo_reqheight()
        x = (self.winfo_screenwidth() - width) // 2
        y = (self.winfo_screenheight() - height) // 3
        self.geometry(f"{width}x{height}+{max(0, x)}+{max(0, y)}")

    def _grab(self) -> None:
        try:
            self.lift()
            self.grab_set()
            self.focus_force()
        except Exception:  # a window manager may refuse; not fatal
            pass

    # --- interaction --------------------------------------------------------------------

    def _toggle_reveal(self) -> None:
        self.password.entry.configure(show="" if self._reveal.get() else "•")

    def _validate(self) -> net.Settings | None:
        for field in (self.host, self.port, self.name, self.password):
            field.clear_error()

        ok = True
        host = self.host.value
        if not host:
            self.host.show_error("Enter a server address.")
            ok = False

        port = 0
        try:
            port = int(self.port.value)
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            self.port.show_error("1–65535.")  # noqa: RUF001 - en dash is deliberate here
            ok = False

        name = ""
        try:
            name = p.normalize_name(self.name.value)
        except p.ProtocolError as exc:
            self.name.show_error(str(exc).capitalize() + ".")
            ok = False

        password = self.password.entry.get()
        if not password:
            self.password.show_error("Enter the room password.")
            ok = False

        if not ok:
            return None
        return net.Settings(host=host, port=port, name=name, password=password)

    def _submit(self) -> None:
        if self._connecting:
            return
        settings = self._validate()
        if settings is None:
            return
        self.set_busy(True, f"Connecting to {settings.host}:{settings.port}…")
        self._on_connect(settings, bool(self._remember.get()))

    def _cancel(self) -> None:
        if self._connecting:
            # Cancel the attempt and return to the form rather than quitting.
            self.set_busy(False)
            self._on_cancel_attempt()
            return
        self._on_cancel()

    def _on_cancel_attempt(self) -> None:
        self.status.configure(text="Connection cancelled.", text_color=theme.TEXT_MUTED)
        if hasattr(self, "_cancel_attempt_hook"):
            self._cancel_attempt_hook()

    # --- state driven by the app --------------------------------------------------------

    def set_busy(self, busy: bool, message: str = "") -> None:
        self._connecting = busy
        for field in (self.host, self.port, self.name, self.password):
            field.set_enabled(not busy)
        self._reveal.configure(state="disabled" if busy else "normal")
        self._remember.configure(state="disabled" if busy else "normal")
        self.connect_button.configure(
            state="disabled" if busy else "normal",
            text="Connecting…" if busy else "Connect",
        )
        self.cancel_button.configure(text="Cancel" if busy else "Quit")
        if busy:
            self.progress.pack(fill="x", pady=(theme.SPACE_SM, 0))
            self.progress.configure(mode="indeterminate")
            self.progress.start()
            self.status.configure(text=message, text_color=theme.TEXT_MUTED)
        else:
            self.progress.stop()
            self.progress.pack_forget()

    def show_failure(self, message: str) -> None:
        self.set_busy(False)
        self.status.configure(text=message, text_color=theme.STATUS_ERROR)
        self.password.entry.focus_set()

    def show_notice(self, message: str) -> None:
        self.status.configure(text=message, text_color=theme.TEXT_MUTED)

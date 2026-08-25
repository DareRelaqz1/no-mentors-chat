"""The main pychat window.

Threading contract, restated because it is the thing most easily broken here: the
network layer lives on its own thread and never touches a widget. Everything below
runs on the Tk main thread, and the only bridge is :meth:`ChatApp._drain_events`,
which polls the network queue from a ``root.after`` callback.
"""

from __future__ import annotations

import logging
import queue
import time
import tkinter as tk
from typing import Any

import customtkinter as ctk

from .. import net
from .. import protocol as p
from . import theme
from .connect_dialog import ConnectDialog
from .widgets import (
    ErrorRow,
    IconButton,
    MessageRow,
    RosterRow,
    StatusPill,
    SystemRow,
    autohide_scrollbar,
)

log = logging.getLogger("pychat.ui")

DRAIN_INTERVAL_MS = 50
GROUPING_WINDOW_SECONDS = 60
MIN_WIDTH, MIN_HEIGHT = 720, 480
DEFAULT_GEOMETRY = "1000x640"


class ChatApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        theme.apply("dark")

        self.title("pychat")
        self.geometry(DEFAULT_GEOMETRY)
        self.minsize(MIN_WIDTH, MIN_HEIGHT)
        self.configure(fg_color=theme.BG_APP)

        self.client: net.NetworkClient | None = None
        self.own_id: str | None = None
        self.own_name: str = ""
        self.host_label: str = ""
        self.remember: bool = False

        self._roster_rows: dict[str, RosterRow] = {}
        self._log_rows: list[Any] = []
        self._last_author: str | None = None
        self._last_ts: float = 0.0
        self._pending_new_messages = False
        self._connected = False

        self._build()
        self._bind_shortcuts()

        self.protocol("WM_DELETE_WINDOW", self.quit_app)
        self.withdraw()  # hidden until the connect dialog succeeds
        self.dialog: ConnectDialog | None = None
        self.after(100, self._open_connect_dialog)
        self.after(DRAIN_INTERVAL_MS, self._drain_events)

    # --- layout ---------------------------------------------------------------------------

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=theme.SPACE_MD, pady=(0, theme.SPACE_MD))
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, minsize=220, weight=0)
        body.grid_columnconfigure(1, weight=1)

        self._build_roster(body)
        self._build_chat(body)

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent", height=56)
        header.grid(
            row=0, column=0, sticky="ew", padx=theme.SPACE_MD, pady=(theme.SPACE_MD, theme.SPACE_MD)
        )
        header.grid_columnconfigure(1, weight=1)

        self.title_label = ctk.CTkLabel(
            header,
            text="pychat",
            font=theme.font(theme.SIZE_XL, "bold"),
            text_color=theme.TEXT_PRIMARY,
        )
        self.title_label.grid(row=0, column=0, sticky="w")

        self.subtitle_label = ctk.CTkLabel(
            header,
            text="",
            font=theme.font(theme.SIZE_SM),
            text_color=theme.TEXT_MUTED,
        )
        self.subtitle_label.grid(row=0, column=1, sticky="w", padx=(theme.SPACE_SM, 0))

        right = ctk.CTkFrame(header, fg_color="transparent")
        right.grid(row=0, column=2, sticky="e")
        self.status_pill = StatusPill(right)
        self.status_pill.pack(side="left", padx=(0, theme.SPACE_MD))
        self.theme_button = IconButton(right, "◐", self.toggle_theme)
        self.theme_button.pack(side="left")

    def _build_roster(self, parent: ctk.CTkFrame) -> None:
        panel = ctk.CTkFrame(
            parent,
            fg_color=theme.BG_PANEL,
            corner_radius=theme.RADIUS_LG,
            border_width=1,
            border_color=theme.BORDER,
        )
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, theme.SPACE_MD))
        panel.grid_rowconfigure(1, weight=1)
        panel.grid_columnconfigure(0, weight=1)
        self.roster_panel = panel

        self.roster_header = ctk.CTkLabel(
            panel,
            text="ONLINE — 0",
            font=theme.font(theme.SIZE_SM, "bold"),
            text_color=theme.TEXT_MUTED,
            anchor="w",
        )
        self.roster_header.grid(
            row=0,
            column=0,
            sticky="ew",
            padx=theme.SPACE_MD,
            pady=(theme.SPACE_MD, theme.SPACE_SM),
        )

        self.roster_list = ctk.CTkScrollableFrame(panel, fg_color="transparent")
        self.roster_list.grid(
            row=1, column=0, sticky="nsew", padx=theme.SPACE_SM, pady=(0, theme.SPACE_MD)
        )
        self.roster_list.grid_columnconfigure(0, weight=1)
        self._recheck_roster_scrollbar = autohide_scrollbar(self.roster_list)

    def _build_chat(self, parent: ctk.CTkFrame) -> None:
        panel = ctk.CTkFrame(
            parent,
            fg_color=theme.BG_PANEL,
            corner_radius=theme.RADIUS_LG,
            border_width=1,
            border_color=theme.BORDER,
        )
        panel.grid(row=0, column=1, sticky="nsew")
        panel.grid_rowconfigure(0, weight=1)
        panel.grid_columnconfigure(0, weight=1)
        self.chat_panel = panel

        self.log = ctk.CTkScrollableFrame(panel, fg_color="transparent")
        self.log.grid(row=0, column=0, sticky="nsew", padx=theme.SPACE_SM, pady=(theme.SPACE_SM, 0))
        self.log.grid_columnconfigure(0, weight=1)
        self.log._parent_canvas.bind("<Configure>", self._on_log_configure, add="+")
        self.log._scrollbar.configure(command=self._on_scrollbar)
        self._recheck_log_scrollbar = autohide_scrollbar(self.log)

        # The "new messages" pill floats over the log rather than taking layout space.
        self.jump_button = ctk.CTkButton(
            panel,
            text="↓  New messages",
            width=150,
            height=30,
            corner_radius=theme.RADIUS_LG,
            fg_color=theme.ACCENT,
            hover_color=theme.ACCENT_HOVER,
            text_color=theme.TEXT_ON_ACCENT,
            font=theme.font(theme.SIZE_SM, "bold"),
            command=self._jump_to_bottom,
        )

        self._build_composer(panel)

    def _build_composer(self, parent: ctk.CTkFrame) -> None:
        composer = ctk.CTkFrame(parent, fg_color="transparent")
        composer.grid(row=1, column=0, sticky="ew", padx=theme.SPACE_SM, pady=theme.SPACE_SM)
        composer.grid_columnconfigure(0, weight=1)

        divider = ctk.CTkFrame(parent, height=1, fg_color=theme.BORDER)
        divider.grid(row=1, column=0, sticky="new", padx=theme.SPACE_SM)

        self.input = ctk.CTkTextbox(
            composer,
            height=42,
            wrap="word",
            corner_radius=theme.RADIUS_SM,
            border_width=1,
            border_color=theme.BORDER,
            fg_color=theme.BG_INPUT,
            text_color=theme.TEXT_PRIMARY,
            font=theme.font(theme.SIZE_MD),
        )
        self.input.grid(row=0, column=0, sticky="ew", pady=(theme.SPACE_SM, 0))
        self.input.bind("<Return>", self._on_return)
        self.input.bind("<Shift-Return>", self._on_shift_return)
        self.input.bind("<KeyRelease>", self._on_input_changed)

        self.send_button = ctk.CTkButton(
            composer,
            text="Send",
            width=88,
            height=42,
            corner_radius=theme.RADIUS_SM,
            fg_color=theme.ACCENT,
            hover_color=theme.ACCENT_HOVER,
            text_color=theme.TEXT_ON_ACCENT,
            font=theme.font(theme.SIZE_MD, "bold"),
            command=self.send_current,
        )
        self.send_button.grid(
            row=0, column=1, sticky="e", padx=(theme.SPACE_SM, 0), pady=(theme.SPACE_SM, 0)
        )

        self.counter = ctk.CTkLabel(
            composer,
            text="",
            font=theme.font(theme.SIZE_SM),
            text_color=theme.TEXT_MUTED,
            anchor="e",
        )
        self.counter.grid(row=1, column=0, columnspan=2, sticky="e", pady=(theme.SPACE_XS, 0))

    def _bind_shortcuts(self) -> None:
        self.bind("<Control-q>", lambda _e: self.quit_app())
        self.bind("<Control-l>", lambda _e: self.clear_log())

    # --- connect dialog -------------------------------------------------------------------

    def _open_connect_dialog(self) -> None:
        self.dialog = ConnectDialog(
            self, on_connect=self._start_connection, on_cancel=self.quit_app
        )
        self.dialog._cancel_attempt_hook = self._cancel_connection

    def _start_connection(self, settings: net.Settings, remember: bool) -> None:
        self.remember = remember
        self.own_name = settings.name
        self.host_label = settings.key
        self.client = net.NetworkClient(settings)
        self.client.start()

    def _cancel_connection(self) -> None:
        if self.client is not None:
            self.client.stop(timeout=2)
            self.client = None

    def _enter_chat(self, event: net.Connected) -> None:
        self.own_id = event.user_id
        self.own_name = event.name
        self.host_label = event.host

        if self.remember and self.client is not None:
            settings = self.client.settings
            net.save_prefs({"host": settings.host, "port": settings.port, "name": event.name})

        if self.dialog is not None:
            self.dialog.grab_release()
            self.dialog.destroy()
            self.dialog = None

        self.deiconify()
        self.lift()
        self.subtitle_label.configure(text=f"connected to {event.host}")
        self.update_roster(event.roster)
        self.add_system(f"You joined as {event.name}.")
        self.input.focus_set()

    # --- event pump -----------------------------------------------------------------------

    def _drain_events(self) -> None:
        """The one bridge from the network thread. Runs on the Tk thread only."""
        try:
            client = self.client
            if client is not None:
                for _ in range(200):  # bounded so a burst cannot freeze the UI
                    try:
                        event = client.events.get_nowait()
                    except queue.Empty:
                        break
                    try:
                        self._handle_event(event)
                    except Exception:
                        log.exception("failed to handle %s", type(event).__name__)
        finally:
            self.after(DRAIN_INTERVAL_MS, self._drain_events)

    def _handle_event(self, event: net.Event) -> None:
        match event:
            case net.Connecting(attempt=attempt):
                self._set_status("connecting", f"Attempt {attempt}")

            case net.CertificateUnknown():
                self._ask_about_certificate(event)

            case net.CertificateMismatch():
                pass  # the fatal ConnectionFailed that follows carries the message

            case net.Connected():
                self._connected = True
                self._set_status("connected", f"Connected to {event.host}")
                if event.reconnected:
                    self.own_id = event.user_id
                    self.own_name = event.name
                    self.update_roster(event.roster)
                    self.add_system("Reconnected.")
                    self.title(f"pychat — {event.host}")
                else:
                    self._enter_chat(event)
                    self.title(f"pychat — {event.host}")

            case net.AuthFailed():
                self._connected = False
                self._fail(event.message)

            case net.ConnectionFailed(message=message):
                self._connected = False
                self._fail(message)

            case net.Disconnected(reason=reason):
                self._connected = False
                self._set_status("reconnecting", reason)
                self.title("pychat — reconnecting")
                self.add_system(reason)

            case net.Reconnecting(attempt=attempt, delay=delay, max_attempts=cap):
                self._set_status("reconnecting", f"Attempt {attempt} of {cap}")
                self.add_system(f"Reconnecting in {delay:.0f}s (attempt {attempt} of {cap})…")

            case net.GaveUp(attempts=attempts):
                self._set_status("disconnected", f"Gave up after {attempts} attempts")
                self.title("pychat — disconnected")
                self.add_system(f"Could not reconnect after {attempts} attempts.")
                self._show_reconnect_button()

            case net.Frame(inner=inner):
                self._handle_frame(inner)

            case net.Stopped():
                pass

    def _handle_frame(self, inner: dict) -> None:
        match inner.get("t"):
            case "msg":
                self.add_message(
                    user_id=inner["user_id"],
                    name=inner["name"],
                    text=inner["text"],
                    ts=float(inner.get("ts") or time.time()),
                )
            case "system":
                self.add_system(inner["text"])
            case "roster":
                self.update_roster(inner["users"])
            case "error":
                self.add_error(inner["text"])
            case _:
                pass

    def _fail(self, message: str) -> None:
        """A connection could not be established or was refused for good."""
        self._set_status("disconnected", message)
        self.title("pychat — disconnected")
        if self.dialog is not None:
            self.dialog.show_failure(message)
        else:
            self.add_error(message)
            self._show_reconnect_button()
        if self.client is not None:
            self.client.stop(timeout=1)
            self.client = None

    def _ask_about_certificate(self, event: net.CertificateUnknown) -> None:
        dialog = CertificateDialog(self, event)
        self.wait_window(dialog)
        if self.client is not None:
            self.client.answer_certificate(dialog.accepted)
        if self.dialog is not None and not dialog.accepted:
            self.dialog.show_notice("Certificate not accepted.")

    # --- roster -------------------------------------------------------------------------

    def update_roster(self, users: list[dict[str, str]]) -> None:
        for row in self._roster_rows.values():
            row.destroy()
        self._roster_rows.clear()

        ordered = sorted(users, key=lambda u: u["name"].casefold())
        for index, user in enumerate(ordered):
            row = RosterRow(
                self.roster_list,
                user_id=user["user_id"],
                name=user["name"],
                is_self=user["user_id"] == self.own_id,
            )
            row.grid(row=index, column=0, sticky="ew", pady=1)
            self._roster_rows[user["user_id"]] = row

        self.roster_header.configure(text=f"ONLINE — {len(ordered)}")
        self.after_idle(self._recheck_roster_scrollbar)

    # --- chat log -----------------------------------------------------------------------

    def _at_bottom(self) -> bool:
        try:
            return self.log._parent_canvas.yview()[1] >= 0.999
        except Exception:
            return True

    def _append(self, widget, *, stick: bool) -> None:
        widget.grid(row=len(self._log_rows), column=0, sticky="ew", pady=1)
        self._log_rows.append(widget)
        self.after_idle(self._recheck_log_scrollbar)
        if stick:
            self.after_idle(self._jump_to_bottom)
        else:
            self._pending_new_messages = True
            self._show_jump_pill()

    def add_message(self, *, user_id: str, name: str, text: str, ts: float) -> None:
        stick = self._at_bottom()
        grouped = self._last_author == user_id and (ts - self._last_ts) <= GROUPING_WINDOW_SECONDS
        row = MessageRow(
            self.log,
            user_id=user_id,
            name=name,
            text=text,
            ts=ts,
            is_own=user_id == self.own_id,
            grouped=grouped,
        )
        self._last_author, self._last_ts = user_id, ts
        self._append(row, stick=stick)

    def add_system(self, text: str) -> None:
        stick = self._at_bottom()
        self._last_author = None
        self._append(SystemRow(self.log, text), stick=stick)

    def add_error(self, text: str) -> None:
        stick = self._at_bottom()
        self._last_author = None
        self._append(ErrorRow(self.log, text), stick=stick)

    def clear_log(self) -> None:
        for row in self._log_rows:
            row.destroy()
        self._log_rows.clear()
        self._last_author = None
        self.add_system("Local view cleared. Messages already sent are unaffected.")

    def _jump_to_bottom(self) -> None:
        self.log._parent_canvas.yview_moveto(1.0)
        self._pending_new_messages = False
        self.jump_button.place_forget()

    def _show_jump_pill(self) -> None:
        # Anchored to the log's viewport, not the log frame: the frame grows with the
        # content, so anchoring to it would put the pill somewhere off in the scrollback.
        if self._pending_new_messages:
            self.jump_button.place(
                in_=self.log._parent_canvas, relx=0.5, rely=1.0, anchor="s", y=-10
            )

    def _on_scrollbar(self, *args) -> None:
        self.log._parent_canvas.yview(*args)
        if self._at_bottom():
            self._pending_new_messages = False
            self.jump_button.place_forget()

    def _on_log_configure(self, event=None) -> None:
        # Keep message wrapping in step with the panel width.
        for row in self._log_rows:
            if isinstance(row, SystemRow | ErrorRow):
                for child in row.winfo_children():
                    if isinstance(child, ctk.CTkLabel):
                        child.configure(wraplength=max(240, self.log.winfo_width() - 80))

    # --- composing ----------------------------------------------------------------------

    def _current_text(self) -> str:
        return self.input.get("1.0", "end-1c")

    def _on_return(self, _event=None) -> str:
        self.send_current()
        return "break"  # stop Tk inserting the newline

    def _on_shift_return(self, _event=None) -> None:
        return None  # let the newline through

    def _on_input_changed(self, _event=None) -> None:
        text = self._current_text()
        count = len(text)
        limit = p.MAX_MESSAGE_CHARS
        if count > limit * 0.8:
            self.counter.configure(
                text=f"{count} / {limit}",
                text_color=theme.STATUS_ERROR if count > limit else theme.TEXT_MUTED,
            )
        else:
            self.counter.configure(text="")
        self.send_button.configure(state="disabled" if count > limit else "normal")

    def send_current(self) -> None:
        text = self._current_text().strip()
        if not text:
            return
        if len(text) > p.MAX_MESSAGE_CHARS:
            self.add_error(f"Message too long (limit {p.MAX_MESSAGE_CHARS} characters).")
            return
        if self.client is None or not self._connected:
            self.add_error("Not connected — your message was not sent.")
            return
        self.client.send_message(text)
        self.input.delete("1.0", "end")
        self._on_input_changed()
        self.input.focus_set()

    # --- status, theme, lifecycle -------------------------------------------------------

    def _set_status(self, state: str, reason: str = "") -> None:
        self.status_pill.set_state(state, reason)

    def _show_reconnect_button(self) -> None:
        if getattr(self, "_reconnect_button", None) is not None:
            return
        self._reconnect_button = ctk.CTkButton(
            self.chat_panel,
            text="Reconnect",
            width=130,
            height=32,
            corner_radius=theme.RADIUS_LG,
            fg_color=theme.ACCENT,
            hover_color=theme.ACCENT_HOVER,
            text_color=theme.TEXT_ON_ACCENT,
            font=theme.font(theme.SIZE_SM, "bold"),
            command=self._manual_reconnect,
        )
        self._reconnect_button.place(
            in_=self.log._parent_canvas, relx=0.5, rely=1.0, anchor="s", y=-10
        )

    def _manual_reconnect(self) -> None:
        button = getattr(self, "_reconnect_button", None)
        if button is not None:
            button.destroy()
            self._reconnect_button = None
        if self.client is not None:
            self.client.stop(timeout=2)
        if self.client is None:
            self.add_error("Reconnecting needs the room password again — restart the client.")
            return
        settings = self.client.settings
        self.client = net.NetworkClient(settings)
        self.client.start()
        self.add_system("Reconnecting…")

    def toggle_theme(self) -> None:
        theme.apply("light" if theme.current_mode() == "dark" else "dark")
        for widget in (*self._roster_rows.values(), *self._log_rows, self.status_pill):
            if hasattr(widget, "refresh_theme"):
                widget.refresh_theme()

    def quit_app(self) -> None:
        if self.client is not None:
            self.client.stop(timeout=3)
            self.client = None
        try:
            self.quit()
            self.destroy()
        except tk.TclError:
            pass


class CertificateDialog(ctk.CTkToplevel):
    """Trust-on-first-use prompt. Deliberately shows the whole fingerprint."""

    def __init__(self, master, event: net.CertificateUnknown):
        super().__init__(master)
        self.title("Unknown server")
        self.resizable(False, False)
        self.configure(fg_color=theme.BG_APP)
        self.accepted = False

        outer = ctk.CTkFrame(self, fg_color="transparent")
        outer.pack(padx=theme.SPACE_LG, pady=theme.SPACE_LG)

        ctk.CTkLabel(
            outer,
            text="First connection to this server",
            font=theme.font(theme.SIZE_LG, "bold"),
            text_color=theme.TEXT_PRIMARY,
        ).pack(anchor="w")
        ctk.CTkLabel(
            outer,
            text=(
                f"pychat has not seen {event.host_key} before. Check the fingerprint below "
                "against the one the server printed at startup. If they match, it is safe "
                "to trust it — pychat will remember it and warn you if it ever changes."
            ),
            font=theme.font(theme.SIZE_SM),
            text_color=theme.TEXT_SECONDARY,
            wraplength=420,
            justify="left",
        ).pack(anchor="w", pady=(theme.SPACE_SM, theme.SPACE_MD))

        box = ctk.CTkFrame(outer, fg_color=theme.BG_ELEVATED, corner_radius=theme.RADIUS_SM)
        box.pack(fill="x")
        ctk.CTkLabel(
            box,
            text=event.readable,
            font=theme.font(theme.SIZE_SM, mono=True),
            text_color=theme.TEXT_PRIMARY,
            wraplength=400,
            justify="left",
        ).pack(padx=theme.SPACE_MD, pady=theme.SPACE_MD)

        buttons = ctk.CTkFrame(outer, fg_color="transparent")
        buttons.pack(fill="x", pady=(theme.SPACE_LG, 0))
        ctk.CTkButton(
            buttons,
            text="Cancel",
            width=100,
            height=36,
            corner_radius=theme.RADIUS_SM,
            fg_color="transparent",
            border_width=1,
            border_color=theme.BORDER,
            text_color=theme.TEXT_SECONDARY,
            hover_color=theme.BG_HOVER,
            font=theme.font(theme.SIZE_MD),
            command=self._decline,
        ).pack(side="left")
        ctk.CTkButton(
            buttons,
            text="Trust and connect",
            width=170,
            height=36,
            corner_radius=theme.RADIUS_SM,
            fg_color=theme.ACCENT,
            hover_color=theme.ACCENT_HOVER,
            text_color=theme.TEXT_ON_ACCENT,
            font=theme.font(theme.SIZE_MD, "bold"),
            command=self._accept,
        ).pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self._decline)
        self.bind("<Escape>", lambda _e: self._decline())
        self.after(100, self._grab)

    def _grab(self) -> None:
        try:
            self.lift()
            self.grab_set()
            self.focus_force()
        except Exception:
            pass

    def _accept(self) -> None:
        self.accepted = True
        self.destroy()

    def _decline(self) -> None:
        self.accepted = False
        self.destroy()


def launch() -> int:
    app = ChatApp()
    app.mainloop()
    return 0

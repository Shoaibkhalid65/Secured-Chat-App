# server.py
# Offline Secured Chat Application — SERVER SIDE
# Run this on the machine that will RECEIVE the first connection.
# Project : Offline Secured Chat Application
# Author  : Muhammad Shoaib Khalid

import os
import socket
import sys
import threading
from pathlib import Path


def _configure_tk_library() -> None:
    """Point Tk at the bundled Tcl/Tk libraries when Python does not."""
    python_roots = []
    for raw_root in (
        Path(sys.executable).resolve().parent,
        Path(sys.base_prefix).resolve(),
        Path(getattr(sys, "_base_executable", sys.executable)).resolve().parent,
    ):
        if raw_root not in python_roots:
            python_roots.append(raw_root)

    tcl_candidates = [
        root / "tcl" / "tcl8.6" for root in python_roots
    ] + [
        root / "Lib" / "tcl8.6" for root in python_roots
    ]
    tk_candidates = [
        root / "tcl" / "tk8.6" for root in python_roots
    ] + [
        root / "Lib" / "tk8.6" for root in python_roots
    ]

    tcl_library = next((path for path in tcl_candidates if (path / "init.tcl").exists()), None)
    tk_library = next((path for path in tk_candidates if (path / "tk.tcl").exists()), None)

    if tcl_library is not None:
        os.environ.setdefault("TCL_LIBRARY", str(tcl_library))
    if tk_library is not None:
        os.environ.setdefault("TK_LIBRARY", str(tk_library))


_configure_tk_library()

import tkinter as tk
from tkinter import scrolledtext, messagebox
from datetime import datetime

from blowfish import BlowfishCipher
from secure_protocol import (
    build_secure_packet, derive_keys,
    parse_secure_packet, recv_packet, send_packet,
)

HOST       = "0.0.0.0"       # Listen on ALL interfaces (LAN + localhost)
PORT       = 9999
SECRET_KEY = b"SecureKey123" # ← Must match client exactly


def get_local_ip() -> str:
    """Return the machine's LAN IP address for display."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


class ServerChatApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("🔐 Secure Chat — Server (User B)")
        self.root.geometry("600x650")
        self.root.configure(bg="#1e1e2e")
        self.root.resizable(False, False)

        enc_key, self.mac_key = derive_keys(SECRET_KEY)
        self.cipher    = BlowfishCipher(enc_key)
        self.conn      = None
        self.srv_sock  = None
        self.running   = False
        self.send_seq  = 0
        self.recv_seq  = -1

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._start_server()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self.root, bg="#181825", pady=10)
        hdr.pack(fill=tk.X)

        tk.Label(
            hdr, text="🔐 Offline Secure Chat  —  Server (User B)",
            font=("Helvetica", 14, "bold"), bg="#181825", fg="#cdd6f4",
        ).pack()

        local_ip = get_local_ip()
        tk.Label(
            hdr,
            text=f"Your IP: {local_ip}  |  Port: {PORT}  ←  Share this with User A",
            font=("Helvetica", 9), bg="#181825", fg="#a6e3a1",
        ).pack(pady=2)

        tk.Label(
            hdr,
            text="Algorithm: Blowfish-CBC  |  Integrity: HMAC-SHA256  |  Anti-replay: ✔",
            font=("Helvetica", 9), bg="#181825", fg="#6c7086",
        ).pack()

        # Status bar
        self.status_var = tk.StringVar(value="⏳  Waiting for client to connect…")
        tk.Label(
            self.root, textvariable=self.status_var,
            font=("Helvetica", 10), bg="#1e1e2e", fg="#f38ba8",
        ).pack(pady=6)

        # Chat display
        self.chat = scrolledtext.ScrolledText(
            self.root, width=68, height=24,
            bg="#181825", fg="#cdd6f4",
            font=("Consolas", 10),
            state=tk.DISABLED, wrap=tk.WORD,
            bd=0, relief="flat",
        )
        self.chat.pack(padx=12, pady=4)
        self.chat.tag_config("you",    foreground="#a6e3a1")
        self.chat.tag_config("other",  foreground="#89b4fa")
        self.chat.tag_config("system", foreground="#f9e2af", font=("Consolas", 9, "italic"))
        self.chat.tag_config("error",  foreground="#f38ba8")

        # Input row
        row = tk.Frame(self.root, bg="#1e1e2e")
        row.pack(padx=12, pady=8, fill=tk.X)

        self.entry = tk.Entry(
            row, font=("Consolas", 11),
            bg="#313244", fg="#cdd6f4", insertbackground="#cdd6f4",
            relief="flat", bd=8,
        )
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.entry.bind("<Return>", self._send)

        tk.Button(
            row, text="Send 🔒",
            font=("Helvetica", 10, "bold"),
            bg="#89b4fa", fg="#1e1e2e",
            activebackground="#74c7ec",
            relief="flat", bd=0, padx=14,
            command=self._send,
        ).pack(side=tk.LEFT, padx=(8, 0))

    # ── Thread-safe UI helpers ────────────────────────────────────────────────

    def _log(self, sender: str, msg: str, tag: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.chat.config(state=tk.NORMAL)
        self.chat.insert(tk.END, f"[{ts}] [{sender}]: {msg}\n", tag)
        self.chat.see(tk.END)
        self.chat.config(state=tk.DISABLED)

    def _log_safe(self, sender, msg, tag):
        self.root.after(0, self._log, sender, msg, tag)

    def _set_status(self, text: str, fg: str = "#f38ba8"):
        self.root.after(0, lambda: self.status_var.set(text))

    # ── Networking ────────────────────────────────────────────────────────────

    def _start_server(self):
        self.srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv_sock.bind((HOST, PORT))
        self.srv_sock.listen(1)
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        try:
            self.conn, addr = self.srv_sock.accept()
            self.running  = True
            self.send_seq = 0
            self.recv_seq = -1
            self._set_status(f"✅  Connected to {addr[0]}:{addr[1]}", "#a6e3a1")
            self._log_safe("System", f"Client connected from {addr[0]}", "system")
            threading.Thread(target=self._receive_loop, daemon=True).start()
        except Exception as e:
            self._log_safe("System", f"Accept error: {e}", "error")

    def _receive_loop(self):
        while self.running:
            try:
                packet = recv_packet(self.conn)
                text, seq = parse_secure_packet(self.cipher, self.mac_key, packet, self.recv_seq)
                self.recv_seq = seq
                self._log_safe("User A (Client)", text, "other")
            except ValueError as e:
                self._log_safe("Security", str(e), "error")
                break
            except Exception:
                break
        self._log_safe("System", "Client disconnected.", "system")
        self._set_status("🔌  Client disconnected. Waiting for new connection…")
        self.running = False
        # Automatically listen for next connection
        threading.Thread(target=self._accept, daemon=True).start()

    def _send(self, event=None):
        if not self.conn or not self.running:
            messagebox.showwarning("Not Connected", "No client is connected yet.")
            return
        msg = self.entry.get().strip()
        if not msg:
            return
        try:
            packet = build_secure_packet(self.cipher, self.mac_key, msg, self.send_seq)
            send_packet(self.conn, packet)
            self.send_seq += 1
            self._log("You (User B)", msg, "you")
            self.entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", str(e))

    # ── Clean shutdown ────────────────────────────────────────────────────────

    def _on_close(self):
        self.running = False
        for s in (self.conn, self.srv_sock):
            if s:
                try: s.shutdown(socket.SHUT_RDWR)
                except: pass
                try: s.close()
                except: pass
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    ServerChatApp(root)
    root.mainloop()
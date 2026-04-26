# client.py
# Offline Secured Chat Application — CLIENT SIDE
# Run this on the machine that CONNECTS to the server.
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

    tcl_candidates = [root / "tcl" / "tcl8.6" for root in python_roots] + [root / "Lib" / "tcl8.6" for root in python_roots]
    tk_candidates = [root / "tcl" / "tk8.6" for root in python_roots] + [root / "Lib" / "tk8.6" for root in python_roots]

    tcl_library = next((path for path in tcl_candidates if (path / "init.tcl").exists()), None)
    tk_library = next((path for path in tk_candidates if (path / "tk.tcl").exists()), None)

    if tcl_library is not None:
        os.environ.setdefault("TCL_LIBRARY", str(tcl_library))
    if tk_library is not None:
        os.environ.setdefault("TK_LIBRARY", str(tk_library))


_configure_tk_library()

import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
from datetime import datetime

from blowfish import BlowfishCipher
from secure_protocol import (
    build_secure_packet, derive_keys,
    parse_secure_packet, recv_packet, send_packet,
)

PORT       = 9999
SECRET_KEY = b"SecureKey123"  # ← Must match server exactly


class ClientChatApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("🔐 Secure Chat — Client (User A)")
        self.root.geometry("600x650")
        self.root.configure(bg="#1e1e2e")
        self.root.resizable(False, False)

        enc_key, self.mac_key = derive_keys(SECRET_KEY)
        self.cipher   = BlowfishCipher(enc_key)
        self.sock     = None
        self.running  = False
        self.send_seq = 0
        self.recv_seq = -1

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._ask_ip()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self.root, bg="#181825", pady=10)
        hdr.pack(fill=tk.X)

        tk.Label(
            hdr, text="🔐 Offline Secure Chat  —  Client (User A)",
            font=("Helvetica", 14, "bold"), bg="#181825", fg="#cdd6f4",
        ).pack()

        tk.Label(
            hdr,
            text=f"Port: {PORT}  |  Enter server IP when prompted",
            font=("Helvetica", 9), bg="#181825", fg="#a6e3a1",
        ).pack(pady=2)

        tk.Label(
            hdr,
            text="Algorithm: Blowfish-CBC  |  Integrity: HMAC-SHA256  |  Anti-replay: ✔",
            font=("Helvetica", 9), bg="#181825", fg="#6c7086",
        ).pack()

        # Status bar
        self.status_var = tk.StringVar(value="🔌  Not connected…")
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

    # ── Connection ────────────────────────────────────────────────────────────

    def _ask_ip(self):
        ip = simpledialog.askstring(
            "Connect to Server",
            "Enter Server IP address:\n\n"
            "• Same machine  →  127.0.0.1\n"
            "• WiFi/LAN      →  e.g. 192.168.1.5\n"
            "  (Server shows its IP in the header)",
            initialvalue="127.0.0.1",
        )
        if ip:
            threading.Thread(target=self._connect, args=(ip.strip(),), daemon=True).start()
        else:
            self.root.destroy()

    def _connect(self, host: str):
        try:
            self._set_status(f"⏳  Connecting to {host}:{PORT}…")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((host, PORT))
            self.sock.settimeout(None)
            self.running  = True
            self.send_seq = 0
            self.recv_seq = -1
            self._set_status(f"✅  Connected to {host}:{PORT}", "#a6e3a1")
            self._log_safe("System", f"Secure channel established with {host}", "system")
            threading.Thread(target=self._receive_loop, daemon=True).start()
        except socket.timeout:
            self.root.after(0, messagebox.showerror, "Timeout",
                            f"Could not reach {host}:{PORT}\n"
                            "Make sure server is running and both devices are on the same WiFi.")
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Connection Failed", str(e))

    def _receive_loop(self):
        while self.running:
            try:
                packet = recv_packet(self.sock)
                text, seq = parse_secure_packet(self.cipher, self.mac_key, packet, self.recv_seq)
                self.recv_seq = seq
                self._log_safe("User B (Server)", text, "other")
            except ValueError as e:
                self._log_safe("Security", str(e), "error")
                break
            except Exception:
                break
        self._log_safe("System", "Disconnected from server.", "system")
        self._set_status("🔌  Disconnected.")
        self.running = False

    def _send(self, event=None):
        if not self.sock or not self.running:
            messagebox.showwarning("Not Connected", "Not connected to any server.")
            return
        msg = self.entry.get().strip()
        if not msg:
            return
        try:
            packet = build_secure_packet(self.cipher, self.mac_key, msg, self.send_seq)
            send_packet(self.sock, packet)
            self.send_seq += 1
            self._log("You (User A)", msg, "you")
            self.entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", str(e))

    # ── Clean shutdown ────────────────────────────────────────────────────────

    def _on_close(self):
        self.running = False
        if self.sock:
            try: self.sock.shutdown(socket.SHUT_RDWR)
            except: pass
            try: self.sock.close()
            except: pass
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    ClientChatApp(root)
    root.mainloop()
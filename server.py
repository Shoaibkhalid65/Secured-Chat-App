# server.py
# Offline Secured Chat Application — SERVER SIDE
# User B runs this file to listen for incoming connections.

import socket
import threading
import os
from pathlib import Path


def _configure_tcl_tk_env():
    if os.environ.get("TCL_LIBRARY") and os.environ.get("TK_LIBRARY"):
        return

    candidate_roots = [Path(__file__).resolve().parent, Path(os.__file__).resolve().parents[1]]
    for root in candidate_roots:
        tcl_lib = root / "tcl" / "tcl8.6"
        tk_lib = root / "tcl" / "tk8.6"
        if tcl_lib.exists() and tk_lib.exists():
            os.environ.setdefault("TCL_LIBRARY", str(tcl_lib))
            os.environ.setdefault("TK_LIBRARY", str(tk_lib))
            return


_configure_tcl_tk_env()

import tkinter as tk
from tkinter import scrolledtext, messagebox
from blowfish import BlowfishCipher
from secure_protocol import build_secure_packet, derive_keys, parse_secure_packet, recv_packet, send_packet

HOST = "0.0.0.0"   # Listen on all network interfaces
PORT = 9999        # Port number (must match client)
SECRET_KEY = b"SecureKey123"   # Pre-shared secret key (must match client)


class ServerChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Chat — Server (User B)")
        self.root.geometry("550x600")
        self.root.configure(bg="#1e1e2e")
        self.root.resizable(False, False)

        enc_key, self.mac_key = derive_keys(SECRET_KEY)
        self.cipher = BlowfishCipher(enc_key)
        self.conn = None
        self.server_socket = None
        self.running = False
        self.send_seq = 0
        self.recv_seq = -1

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._start_server()

    def _build_ui(self):
        # Title
        title = tk.Label(
            self.root, text="🔐 Offline Secure Chat — Server",
            font=("Helvetica", 14, "bold"), bg="#1e1e2e", fg="#cdd6f4"
        )
        title.pack(pady=10)

        # Status label
        self.status_label = tk.Label(
            self.root, text="⏳ Waiting for client to connect...",
            font=("Helvetica", 10), bg="#1e1e2e", fg="#f38ba8"
        )
        self.status_label.pack(pady=4)

        # Algorithm info label
        algo_label = tk.Label(
            self.root, text="Algorithm: Blowfish-CBC + HMAC-SHA256 | Key: Pre-shared",
            font=("Helvetica", 9), bg="#1e1e2e", fg="#6c7086"
        )
        algo_label.pack(pady=2)

        # Chat display
        self.chat_display = scrolledtext.ScrolledText(
            self.root, width=60, height=22,
            bg="#181825", fg="#cdd6f4",
            font=("Consolas", 10),
            state=tk.DISABLED, wrap=tk.WORD,
            borderwidth=0, relief="flat"
        )
        self.chat_display.pack(padx=15, pady=10)

        # Tag colors
        self.chat_display.tag_config("you", foreground="#a6e3a1")
        self.chat_display.tag_config("other", foreground="#89b4fa")
        self.chat_display.tag_config("system", foreground="#f9e2af")

        # Input area
        input_frame = tk.Frame(self.root, bg="#1e1e2e")
        input_frame.pack(padx=15, pady=5, fill=tk.X)

        self.msg_entry = tk.Entry(
            input_frame, font=("Consolas", 11),
            bg="#313244", fg="#cdd6f4", insertbackground="#cdd6f4",
            relief="flat", bd=8
        )
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.msg_entry.bind("<Return>", self._send_message)

        send_btn = tk.Button(
            input_frame, text="Send 🔒",
            font=("Helvetica", 10, "bold"),
            bg="#89b4fa", fg="#1e1e2e",
            activebackground="#74c7ec",
            relief="flat", bd=0, padx=12,
            command=self._send_message
        )
        send_btn.pack(side=tk.LEFT, padx=(8, 0))

    def _append_message(self, sender, message, tag):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, f"[{sender}]: {message}\n", tag)
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)

    def _append_message_safe(self, sender, message, tag):
        self.root.after(0, self._append_message, sender, message, tag)

    def _set_status_safe(self, text, fg):
        self.root.after(0, lambda: self.status_label.config(text=text, fg=fg))

    def _show_error_safe(self, title, message):
        self.root.after(0, messagebox.showerror, title, message)

    def _show_warning_safe(self, title, message):
        self.root.after(0, messagebox.showwarning, title, message)

    def _start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((HOST, PORT))
        self.server_socket.listen(1)
        threading.Thread(target=self._accept_connection, daemon=True).start()

    def _accept_connection(self):
        self.conn, addr = self.server_socket.accept()
        self.running = True
        self.send_seq = 0
        self.recv_seq = -1
        self._set_status_safe(
            text=f"✅ Connected to {addr[0]}:{addr[1]}",
            fg="#a6e3a1"
        )
        self._append_message_safe("System", f"Client connected from {addr[0]}", "system")
        threading.Thread(target=self._receive_messages, daemon=True).start()

    def _receive_messages(self):
        while self.running:
            try:
                packet = recv_packet(self.conn)
                plain_text, recv_seq = parse_secure_packet(self.cipher, self.mac_key, packet, self.recv_seq)
                self.recv_seq = recv_seq
                self._append_message_safe("Client (User A)", plain_text, "other")
            except ValueError as e:
                self._append_message_safe("System", f"Security error: {e}", "system")
                break
            except Exception:
                break
        self._append_message_safe("System", "Client disconnected.", "system")
        self.running = False

    def _send_message(self, event=None):
        if not self.conn or not self.running:
            self._show_warning_safe("Not Connected", "No client connected yet!")
            return
        msg = self.msg_entry.get().strip()
        if not msg:
            return
        try:
            packet = build_secure_packet(self.cipher, self.mac_key, msg, self.send_seq)
            send_packet(self.conn, packet)
            self.send_seq += 1
            self._append_message("You (User B)", msg, "you")
            self.msg_entry.delete(0, tk.END)
        except Exception as e:
            self._show_error_safe("Error", str(e))

    def _on_close(self):
        self.running = False
        if self.conn:
            try:
                self.conn.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.conn.close()
            except Exception:
                pass
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = ServerChatApp(root)
    root.mainloop()
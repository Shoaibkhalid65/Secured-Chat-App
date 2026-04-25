# client.py
# Offline Secured Chat Application — CLIENT SIDE
# User A runs this file to connect to the server.

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
from tkinter import scrolledtext, messagebox, simpledialog
from blowfish import BlowfishCipher
from secure_protocol import build_secure_packet, derive_keys, parse_secure_packet, recv_packet, send_packet

PORT = 9999
SECRET_KEY = b"SecureKey123"   # Must match server


class ClientChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Chat — Client (User A)")
        self.root.geometry("550x600")
        self.root.configure(bg="#1e1e2e")
        self.root.resizable(False, False)

        enc_key, self.mac_key = derive_keys(SECRET_KEY)
        self.cipher = BlowfishCipher(enc_key)
        self.sock = None
        self.running = False
        self.send_seq = 0
        self.recv_seq = -1

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._ask_server_ip()

    def _build_ui(self):
        # Title
        title = tk.Label(
            self.root, text="🔐 Offline Secure Chat — Client",
            font=("Helvetica", 14, "bold"), bg="#1e1e2e", fg="#cdd6f4"
        )
        title.pack(pady=10)

        # Status label
        self.status_label = tk.Label(
            self.root, text="🔌 Not connected...",
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

    def _ask_server_ip(self):
        ip = simpledialog.askstring(
            "Server IP",
            "Enter the Server IP address:\n(Use 127.0.0.1 if testing on same machine)",
            initialvalue="127.0.0.1"
        )
        if ip:
            threading.Thread(target=self._connect, args=(ip,), daemon=True).start()
        else:
            self.root.destroy()

    def _connect(self, host):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, PORT))
            self.running = True
            self.send_seq = 0
            self.recv_seq = -1
            self._set_status_safe(
                text=f"✅ Connected to server {host}:{PORT}",
                fg="#a6e3a1"
            )
            self._append_message_safe("System", f"Connected to server at {host}", "system")
            threading.Thread(target=self._receive_messages, daemon=True).start()
        except Exception as e:
            self._show_error_safe("Connection Failed", f"Could not connect:\n{e}")

    def _receive_messages(self):
        while self.running:
            try:
                packet = recv_packet(self.sock)
                plain_text, recv_seq = parse_secure_packet(self.cipher, self.mac_key, packet, self.recv_seq)
                self.recv_seq = recv_seq
                self._append_message_safe("Server (User B)", plain_text, "other")
            except ValueError as e:
                self._append_message_safe("System", f"Security error: {e}", "system")
                break
            except Exception:
                break
        self._append_message_safe("System", "Disconnected from server.", "system")
        self.running = False

    def _send_message(self, event=None):
        if not self.sock or not self.running:
            self._show_warning_safe("Not Connected", "Not connected to server!")
            return
        msg = self.msg_entry.get().strip()
        if not msg:
            return
        try:
            packet = build_secure_packet(self.cipher, self.mac_key, msg, self.send_seq)
            send_packet(self.sock, packet)
            self.send_seq += 1
            self._append_message("You (User A)", msg, "you")
            self.msg_entry.delete(0, tk.END)
        except Exception as e:
            self._show_error_safe("Error", str(e))

    def _on_close(self):
        self.running = False
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = ClientChatApp(root)
    root.mainloop()
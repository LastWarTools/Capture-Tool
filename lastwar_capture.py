#!/usr/bin/env python3
"""
Last War Credential Capture Tool

Simple GUI tool to capture game login credentials for API access.
Requires Npcap to be installed on Windows.
"""

import threading
import time
import requests
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
import os

# Try to import scapy
try:
    from scapy.all import sniff, TCP, Raw, conf, get_if_list, get_if_addr, IP
    conf.use_pcap = True
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# API Configuration
API_BASE_URL = "https://api.lastwar.tools"


def get_active_interfaces():
    """Get list of network interfaces with IP addresses."""
    interfaces = []
    try:
        try:
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                name = iface.get('name', '')
                desc = iface.get('description', '')
                ips = iface.get('ips', [])
                ipv4 = None
                for ip in ips:
                    if '.' in ip and not ip.startswith('169.254'):
                        ipv4 = ip
                        break
                if ipv4:
                    friendly = desc if desc else name
                    interfaces.append((name, ipv4, friendly))
        except ImportError:
            for iface in get_if_list():
                try:
                    addr = get_if_addr(iface)
                    if addr and addr != '0.0.0.0' and addr != '127.0.0.1' and not addr.startswith('169.254'):
                        interfaces.append((iface, addr, iface))
                except:
                    pass
    except Exception as e:
        print(f"Error getting interfaces: {e}")
    return interfaces


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/local (capture proxy, not real game server)."""
    if not ip:
        return True
    parts = ip.split('.')
    if len(parts) != 4:
        return True
    try:
        first, second = int(parts[0]), int(parts[1])
    except ValueError:
        return True
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    if first == 127:
        return True
    return False


# Expected blob size ranges based on known-good captures
# Handshake: ~400-2000 bytes (e405 ~460B, e406 ~1862B)
# Auth:      ~200-2000 bytes (~1.3-1.4 KiB typical)
# Login:     ~400-2000 bytes (~1.4 KiB typical)
MIN_HANDSHAKE_SIZE = 300
MAX_HANDSHAKE_SIZE = 5000
MIN_AUTH_SIZE = 200
MAX_AUTH_SIZE = 5000
MIN_LOGIN_SIZE = 300
MAX_LOGIN_SIZE = 5000


class CaptureApp:
    E405_HEADER = b'\xe4\x05'
    E406_HEADER = b'\xe4\x06'
    # c4xx headers are also protocol packets (possibly responses/acks)
    C405_HEADER = b'\xc4\x05'
    C406_HEADER = b'\xc4\x06'

    def __init__(self, root):
        self.root = root
        self.root.title("Last War Credential Capture")
        self.root.geometry("480x550")
        self.root.resizable(True, True)
        self.root.minsize(400, 500)

        # State
        self.capturing = False
        self.capture_thread = None
        self.handshake_data = None  # First e405 packet
        self.auth_data = None       # Non-e405 packet (PC flow)
        self.login_data = None      # Second e405 packet (PC) or e177 (mobile)
        self.protocol = None
        self.packets_seen = 0
        self.selected_interface = None
        self.log_messages = []
        self.game_server_ip = None
        self.game_server_port = None

        # Get available interfaces
        self.interfaces = get_active_interfaces() if SCAPY_AVAILABLE else []

        self.setup_ui()
        self.check_dependencies()

    def setup_ui(self):
        # Configure style
        style = ttk.Style()
        style.configure('Title.TLabel', font=('Segoe UI', 18, 'bold'))
        style.configure('Subtitle.TLabel', font=('Segoe UI', 9), foreground='#666')
        style.configure('Success.TLabel', foreground='#2e7d32')
        style.configure('Waiting.TLabel', foreground='#666')
        style.configure('Big.TButton', font=('Segoe UI', 10), padding=10)

        # Main frame
        main = ttk.Frame(self.root, padding=20)
        main.pack(fill=tk.BOTH, expand=True)

        # Title
        ttk.Label(main, text="Last War Capture", style='Title.TLabel').pack(anchor=tk.W)
        ttk.Label(main, text="Capture your game credentials for API access",
                  style='Subtitle.TLabel').pack(anchor=tk.W, pady=(0, 15))

        # Network interface
        ttk.Label(main, text="Network Interface:", font=('Segoe UI', 9, 'bold')).pack(anchor=tk.W)
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(main, textvariable=self.iface_var, state='readonly')
        if self.interfaces:
            iface_values = [f"{friendly} ({addr})" for name, addr, friendly in self.interfaces]
            self.iface_combo['values'] = iface_values
            selected_idx = 0
            for i, (name, addr, friendly) in enumerate(self.interfaces):
                if addr.startswith('192.168.') or addr.startswith('10.'):
                    if 'virtual' not in friendly.lower() and 'hyper' not in friendly.lower():
                        selected_idx = i
                        break
            self.iface_combo.current(selected_idx)
            self.selected_interface = self.interfaces[selected_idx][0]
        else:
            self.iface_combo['values'] = ["No interfaces found - install Npcap"]
        self.iface_combo.pack(fill=tk.X, pady=(5, 15))
        self.iface_combo.bind('<<ComboboxSelected>>', self.on_interface_changed)

        # Capture button
        self.capture_btn = ttk.Button(main, text="▶  Start Capture", style='Big.TButton',
                                      command=self.toggle_capture)
        self.capture_btn.pack(fill=tk.X, pady=(0, 15))

        # Status section
        status_frame = ttk.LabelFrame(main, text="Status", padding=15)
        status_frame.pack(fill=tk.X, pady=(0, 15))

        self.status_label = ttk.Label(status_frame, text="Ready to capture",
                                      font=('Segoe UI', 10))
        self.status_label.pack(anchor=tk.W)

        self.packets_label = ttk.Label(status_frame, text="",
                                       font=('Segoe UI', 9), foreground='#666')
        self.packets_label.pack(anchor=tk.W, pady=(5, 10))

        # Captured data indicators
        self.handshake_label = ttk.Label(status_frame, text="○  Handshake: waiting...",
                                         style='Waiting.TLabel', font=('Segoe UI', 10))
        self.handshake_label.pack(anchor=tk.W, pady=2)

        self.login_label = ttk.Label(status_frame, text="○  Login: waiting...",
                                     style='Waiting.TLabel', font=('Segoe UI', 10))
        self.login_label.pack(anchor=tk.W, pady=2)

        # Actions section
        actions_frame = ttk.LabelFrame(main, text="Actions", padding=15)
        actions_frame.pack(fill=tk.X, pady=(0, 10))

        # API Key entry
        key_frame = ttk.Frame(actions_frame)
        key_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(key_frame, text="API Key:", font=('Segoe UI', 9)).pack(side=tk.LEFT)
        self.apikey_entry = ttk.Entry(key_frame, width=40, show="•")
        self.apikey_entry.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)

        # Buttons row
        btn_frame = ttk.Frame(actions_frame)
        btn_frame.pack(fill=tk.X)

        self.upload_btn = ttk.Button(btn_frame, text="Upload to API",
                                     command=self.upload_credentials, state=tk.DISABLED)
        self.upload_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        self.save_btn = ttk.Button(btn_frame, text="Save Files",
                                   command=self.save_locally, state=tk.DISABLED)
        self.save_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))

        # Debug log button (small, at bottom)
        bottom_frame = ttk.Frame(main)
        bottom_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self.debug_btn = ttk.Button(bottom_frame, text="Save Debug Log",
                                    command=self.save_debug_log)
        self.debug_btn.pack(side=tk.RIGHT)

        ttk.Label(bottom_frame, text=f"API: {API_BASE_URL}",
                  font=('Segoe UI', 8), foreground='#999').pack(side=tk.LEFT)

    def log(self, message):
        """Add message to internal log."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_messages.append(f"[{timestamp}] {message}")

    def save_debug_log(self):
        """Save debug log to file."""
        if not self.log_messages:
            messagebox.showinfo("Debug Log", "No log messages to save.")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile=f"capture_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if filepath:
            with open(filepath, 'w') as f:
                f.write("Last War Capture Tool - Debug Log\n")
                f.write(f"Generated: {datetime.now()}\n")
                f.write("=" * 50 + "\n\n")
                f.write("\n".join(self.log_messages))
            messagebox.showinfo("Saved", f"Debug log saved to:\n{filepath}")

    def on_interface_changed(self, event=None):
        """Handle interface selection change."""
        idx = self.iface_combo.current()
        if idx >= 0 and idx < len(self.interfaces):
            name, addr, friendly = self.interfaces[idx]
            self.selected_interface = name
            self.log(f"Selected: {friendly} ({addr})")

    def check_dependencies(self):
        """Check if scapy/npcap is available."""
        if not SCAPY_AVAILABLE:
            self.status_label.config(text="⚠ Error: Npcap not installed", foreground='red')
            self.capture_btn.config(state=tk.DISABLED)
            self.log("ERROR: Scapy/Npcap not found")
            messagebox.showerror("Missing Dependencies",
                "Npcap is required for packet capture.\n\n"
                "Download from: https://npcap.com/")

    def toggle_capture(self):
        if self.capturing:
            self.stop_capture()
        else:
            self.start_capture()

    def start_capture(self):
        if not self.selected_interface:
            messagebox.showwarning("No Interface", "Please select a network interface.")
            return

        self.capturing = True
        self.capture_btn.config(text="■  Stop Capture")
        self.status_label.config(text="● Capturing... Open game and log in", foreground='#1565c0')
        self.packets_label.config(text="Packets: 0")
        self.log(f"Started capture on {self.selected_interface}")

        # Reset state
        self.handshake_data = None
        self.auth_data = None
        self.login_data = None
        self.game_server_ip = None
        self.game_server_port = None
        self.packets_seen = 0
        self._stream_buf = {}  # TCP stream reassembly buffer
        self._capture_dst_ip = None   # Actual packet destination (may be proxy)
        self._capture_dst_port = None
        self.handshake_label.config(text="○  Handshake: waiting...", style='Waiting.TLabel')
        self.login_label.config(text="○  Login: waiting...", style='Waiting.TLabel')
        self.upload_btn.config(state=tk.DISABLED)
        self.save_btn.config(state=tk.DISABLED)

        self.capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
        self.capture_thread.start()

    def stop_capture(self):
        self.capturing = False
        self.capture_btn.config(text="▶  Start Capture")

        if not self.handshake_data:
            self.status_label.config(text="Stopped - no handshake captured", foreground='#666')
        elif not self.auth_data:
            self.status_label.config(text="Stopped - no auth packet captured", foreground='#c62828')
        elif not self.login_data:
            self.status_label.config(text="Stopped - no login packet captured", foreground='#c62828')
        self.log("Capture stopped")

    def capture_packets(self):
        """Packet capture thread."""
        all_tcp_count = 0

        def packet_handler(pkt):
            nonlocal all_tcp_count
            if not self.capturing:
                return

            if TCP in pkt:
                all_tcp_count += 1
                if all_tcp_count % 200 == 0:
                    self.root.after(0, lambda c=all_tcp_count: self.packets_label.config(
                        text=f"Packets scanned: {c}"))

            if TCP in pkt and Raw in pkt and IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                data = bytes(pkt[Raw].load)

                # Check for game protocol header (client->server packets)
                header = data[:2] if len(data) >= 2 else b''
                is_protocol_packet = header in (
                    self.E405_HEADER, self.E406_HEADER,
                    self.C405_HEADER, self.C406_HEADER
                )
                is_game_packet = header in (self.E405_HEADER, self.E406_HEADER)

                # Step 1: Capture first e405/e406 packet (handshake)
                if (is_game_packet and self.handshake_data is None and
                        MIN_HANDSHAKE_SIZE <= len(data) <= MAX_HANDSHAKE_SIZE):
                    self.packets_seen += 1

                    self.protocol = "e406" if header == self.E406_HEADER else "e405"
                    self.handshake_data = data

                    # Record game server IP/port — if destination is a private
                    # IP (local proxy/VPN), use the known public game server
                    # and keep the port (it's usually correct even through proxies)
                    if is_private_ip(dst_ip):
                        self.game_server_ip = "172.65.210.24"
                        self.game_server_port = dport
                        self.log(f"[1] Handshake via proxy {dst_ip}:{dport}: {len(data)} bytes "
                                 f"(using public IP {self.game_server_ip})")
                    else:
                        self.game_server_ip = dst_ip
                        self.game_server_port = dport
                        self.log(f"[1] Handshake to {dst_ip}:{dport}: {len(data)} bytes")

                    # For steps 2+3, match on the actual dst (could be proxy)
                    self._capture_dst_ip = dst_ip
                    self._capture_dst_port = dport
                    self.root.after(0, self.on_handshake_captured)

                # Steps 2+3: Buffer post-handshake data to same destination and
                # reassemble fragmented TCP segments. The auth packet (non-protocol,
                # high entropy) and login packet (second e405/e406) may arrive
                # split across multiple TCP segments.
                # Match on actual destination (may be a local proxy), not the
                # corrected public IP we store for the API.
                elif (self.handshake_data is not None and self.login_data is None and
                      self._capture_dst_ip and dst_ip == self._capture_dst_ip and
                      self._capture_dst_port and dport == self._capture_dst_port):

                    key = (src_ip, dst_ip, sport, dport)
                    if key not in self._stream_buf:
                        self._stream_buf[key] = bytearray()
                    self._stream_buf[key].extend(data)
                    buf = self._stream_buf[key]

                    # Try direct capture first (non-fragmented case)
                    if self.auth_data is None and not is_protocol_packet:
                        if MIN_AUTH_SIZE <= len(data) <= MAX_AUTH_SIZE:
                            sample = data[:100] if len(data) >= 100 else data
                            if len(set(sample)) > 50:
                                self.packets_seen += 1
                                self.log(f"[2] Auth packet: {len(data)} bytes, header={header.hex()}")
                                self.auth_data = data
                                self._stream_buf[key] = bytearray()
                                self.root.after(0, self.on_auth_captured)
                                return

                    if self.auth_data is not None and is_game_packet:
                        if MIN_LOGIN_SIZE <= len(data) <= MAX_LOGIN_SIZE:
                            self.packets_seen += 1
                            self.log(f"[3] Login trigger: {len(data)} bytes to {dst_ip}:{dport}")
                            self.login_data = data
                            self.root.after(0, self.on_login_captured)
                            return

                    # Reassembly: scan buffer for e405/e406 boundary that splits
                    # auth data (before) from login packet (after)
                    for i in range(1, len(buf) - 1):
                        if buf[i] == 0xE4 and buf[i + 1] in (0x05, 0x06):
                            auth_candidate = bytes(buf[:i])
                            login_candidate = bytes(buf[i:])

                            if (self.auth_data is None and
                                    MIN_AUTH_SIZE <= len(auth_candidate) <= MAX_AUTH_SIZE):
                                sample = auth_candidate[:100]
                                if len(set(sample)) > 50:
                                    self.packets_seen += 1
                                    self.log(f"[2] Auth packet: {len(auth_candidate)} bytes (reassembled)")
                                    self.auth_data = auth_candidate
                                    self.root.after(0, self.on_auth_captured)

                            if (self.auth_data is not None and self.login_data is None and
                                    login_candidate[:2] in (self.E405_HEADER, self.E406_HEADER) and
                                    MIN_LOGIN_SIZE <= len(login_candidate) <= MAX_LOGIN_SIZE):
                                self.packets_seen += 1
                                self.log(f"[3] Login trigger: {len(login_candidate)} bytes (reassembled)")
                                self.login_data = login_candidate
                                self.root.after(0, self.on_login_captured)

                            buf.clear()
                            break

        self.log(f"Listening on {self.selected_interface}")

        try:
            sniff(iface=self.selected_interface,
                  filter="tcp",
                  prn=packet_handler,
                  store=False,
                  stop_filter=lambda x: not self.capturing)
        except PermissionError:
            self.root.after(0, lambda: self.status_label.config(
                text="⚠ Error: Run as Administrator", foreground='red'))
            self.log("ERROR: Permission denied - run as Administrator")
        except Exception as e:
            self.root.after(0, lambda: self.status_label.config(
                text=f"⚠ Error: {str(e)[:30]}", foreground='red'))
            self.log(f"ERROR: {e}")

    def on_handshake_captured(self):
        size = len(self.handshake_data)
        self.handshake_label.config(text=f"✓  Handshake: {size} bytes ({self.protocol})",
                                   style='Success.TLabel')
        self.login_label.config(text=f"○  Waiting for auth packet...",
                               style='Waiting.TLabel')
        self.log(f"Captured handshake: {size} bytes, server={self.game_server_ip}")

    def on_auth_captured(self):
        size = len(self.auth_data)
        self.login_label.config(text=f"✓  Auth: {size} bytes, waiting for login...",
                               style='Waiting.TLabel')
        self.log(f"Captured auth: {size} bytes")

    def on_login_captured(self):
        size = len(self.login_data)
        header = self.login_data[:2].hex() if len(self.login_data) >= 2 else "??"
        self.login_label.config(text=f"✓  Login: {size} bytes (header: {header})", style='Success.TLabel')
        self.log(f"Captured login packet: {size} bytes, header={header}")
        self.on_capture_complete()

    def on_capture_complete(self):
        self.stop_capture()
        self.status_label.config(text="✓ Capture complete!", foreground='#2e7d32')
        self.upload_btn.config(state=tk.NORMAL)
        self.save_btn.config(state=tk.NORMAL)
        self.log(f"Capture complete: server={self.game_server_ip}:{self.game_server_port}")
        self.log(f"  handshake={len(self.handshake_data)}B, "
                 f"auth={len(self.auth_data)}B, "
                 f"login={len(self.login_data)}B")
        self.root.bell()

    def upload_credentials(self):
        api_key = self.apikey_entry.get().strip()

        if not api_key:
            messagebox.showwarning("Missing API Key", "Please enter your API key.")
            return

        if not self.handshake_data:
            messagebox.showwarning("No Data", "No credentials captured yet.")
            return

        self.upload_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Uploading...", foreground='#1565c0')

        def do_upload():
            try:
                files = {
                    'handshake': ('handshake.bin', self.handshake_data, 'application/octet-stream')
                }
                if self.auth_data:
                    files['auth_packet'] = ('auth.bin', self.auth_data, 'application/octet-stream')
                if self.login_data:
                    files['login'] = ('login.bin', self.login_data, 'application/octet-stream')

                headers = {'X-API-Key': api_key}

                # Include server IP/port as query params (skip private IPs)
                params = {}
                if self.game_server_ip and not is_private_ip(self.game_server_ip):
                    params['server_ip'] = self.game_server_ip
                    if self.game_server_port:
                        params['server_port'] = self.game_server_port

                self.log(f"Upload params: {params}")
                self.log(f"game_server_ip={self.game_server_ip}, game_server_port={self.game_server_port}")

                response = requests.post(
                    f"{API_BASE_URL}/auth/credentials/upload",
                    headers=headers,
                    files=files,
                    params=params,
                    timeout=30
                )

                if response.ok:
                    result = response.json()
                    self.log(f"Upload success: {result}")
                    self.root.after(0, lambda: self.status_label.config(
                        text="✓ Uploaded successfully!", foreground='#2e7d32'))
                    self.root.after(0, lambda: messagebox.showinfo("Success",
                        "Credentials uploaded!\n\nYour API access is now active."))
                else:
                    error = response.json().get('detail', response.text)
                    self.log(f"Upload failed: {error}")
                    self.root.after(0, lambda: self.status_label.config(
                        text="⚠ Upload failed", foreground='red'))
                    self.root.after(0, lambda e=error: messagebox.showerror("Upload Failed", str(e)))
            except Exception as e:
                self.log(f"Upload error: {e}")
                self.root.after(0, lambda: self.status_label.config(
                    text="⚠ Upload error", foreground='red'))
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.root.after(0, lambda: self.upload_btn.config(state=tk.NORMAL))

        threading.Thread(target=do_upload, daemon=True).start()

    def save_locally(self):
        folder = filedialog.askdirectory(title="Select folder to save credentials")
        if not folder:
            return

        try:
            handshake_path = os.path.join(folder, "handshake.bin")
            with open(handshake_path, 'wb') as f:
                f.write(self.handshake_data)
            self.log(f"Saved: {handshake_path}")

            if self.auth_data:
                auth_path = os.path.join(folder, "auth.bin")
                with open(auth_path, 'wb') as f:
                    f.write(self.auth_data)
                self.log(f"Saved: {auth_path}")

            if self.login_data:
                login_path = os.path.join(folder, "login.bin")
                with open(login_path, 'wb') as f:
                    f.write(self.login_data)
                self.log(f"Saved: {login_path}")

            # Save server metadata
            meta_path = os.path.join(folder, "server_info.txt")
            with open(meta_path, 'w') as f:
                f.write(f"server_ip={self.game_server_ip}\n")
                f.write(f"server_port={self.game_server_port}\n")
                f.write(f"protocol={self.protocol}\n")
            self.log(f"Saved: {meta_path}")

            messagebox.showinfo("Saved", f"Credentials saved to:\n{folder}")
        except Exception as e:
            self.log(f"Save error: {e}")
            messagebox.showerror("Error", str(e))


def main():
    root = tk.Tk()

    # Set icon if available
    try:
        root.iconbitmap('icon.ico')
    except:
        pass

    app = CaptureApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

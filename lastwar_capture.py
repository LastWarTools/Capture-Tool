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
    E407_HEADER = b'\xe4\x07'
    E408_HEADER = b'\xe4\x08'

    # c4xx headers are also protocol packets (possibly responses/acks)
    C405_HEADER = b'\xc4\x05'
    C406_HEADER = b'\xc4\x06'
    C407_HEADER = b'\xc4\x07'
    C408_HEADER = b'\xc4\x08'

    def __init__(self, root):
        self.root = root
        self.root.title("Last War Credential Capture")
        self.root.geometry("480x650")
        self.root.resizable(True, True)
        self.root.minsize(400, 600)

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
        self.attempt_count = 0
        self._failed_handshakes = set()
        self._credential_queue = []  # queued (handshake, auth, login, server_ip, port, protocol) tuples
        self._uploading = False

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

        # --- Step 1: API Key ---
        apikey_frame = ttk.LabelFrame(main, text="Step 1: Enter API Key", padding=15)
        apikey_frame.pack(fill=tk.X, pady=(0, 10))

        key_frame = ttk.Frame(apikey_frame)
        key_frame.pack(fill=tk.X)
        ttk.Label(key_frame, text="API Key:", font=('Segoe UI', 9)).pack(side=tk.LEFT)
        self.apikey_entry = ttk.Entry(key_frame, width=40, show="•")
        self.apikey_entry.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)
        self.apikey_entry.bind('<KeyRelease>', self._on_apikey_changed)

        # --- Step 2: Network Interface + Capture ---
        capture_frame = ttk.LabelFrame(main, text="Step 2: Capture Credentials", padding=15)
        capture_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(capture_frame, text="Network Interface:", font=('Segoe UI', 9, 'bold')).pack(anchor=tk.W)
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(capture_frame, textvariable=self.iface_var, state='readonly')
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
        self.iface_combo.pack(fill=tk.X, pady=(5, 10))
        self.iface_combo.bind('<<ComboboxSelected>>', self.on_interface_changed)

        self.capture_btn = ttk.Button(capture_frame, text="▶  Start Capture", style='Big.TButton',
                                      command=self.toggle_capture, state=tk.DISABLED)
        self.capture_btn.pack(fill=tk.X, pady=(0, 5))

        self.capture_hint = ttk.Label(capture_frame, text="Enter and validate your API key first",
                                      font=('Segoe UI', 9), foreground='#999')
        self.capture_hint.pack(anchor=tk.W)

        # Status section
        status_frame = ttk.LabelFrame(main, text="Status", padding=15)
        status_frame.pack(fill=tk.X, pady=(0, 10))

        self.status_label = ttk.Label(status_frame, text="Ready",
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

        self.validate_label = ttk.Label(status_frame, text="",
                                        font=('Segoe UI', 10))
        self.validate_label.pack(anchor=tk.W, pady=2)

        # Post-capture actions
        self.save_btn = ttk.Button(main, text="Save Files Locally",
                                   command=self.save_locally, state=tk.DISABLED)
        self.save_btn.pack(fill=tk.X, pady=(0, 10))

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

    def _on_apikey_changed(self, event=None):
        """Validate the API key when user finishes typing."""
        api_key = self.apikey_entry.get().strip()
        if not api_key:
            self.capture_btn.config(state=tk.DISABLED)
            self.capture_hint.config(text="Enter your API key first")
            return

        # Debounce: schedule validation after a short delay
        if hasattr(self, '_apikey_after_id') and self._apikey_after_id:
            self.root.after_cancel(self._apikey_after_id)
        self._apikey_after_id = self.root.after(500, self._validate_api_key)

    def _validate_api_key(self):
        """Validate API key against the server."""
        api_key = self.apikey_entry.get().strip()
        if not api_key:
            return

        self.capture_btn.config(state=tk.DISABLED)
        self.capture_hint.config(text="Validating API key...", foreground='#1565c0')

        def do_validate():
            try:
                response = requests.get(
                    f"{API_BASE_URL}/auth/validate",
                    headers={'X-API-Key': api_key},
                    timeout=10
                )
                if response.ok:
                    result = response.json()
                    display_name = result.get('display_name', '')
                    self.root.after(0, lambda: self._on_apikey_valid(display_name))
                else:
                    try:
                        detail = response.json().get('detail', 'Invalid API key')
                    except Exception:
                        detail = 'Invalid API key'
                    self.root.after(0, lambda d=detail: self._on_apikey_invalid(d))
            except requests.exceptions.ConnectionError:
                self.root.after(0, lambda: self._on_apikey_invalid("Cannot reach API server"))
            except Exception as e:
                self.root.after(0, lambda e=e: self._on_apikey_invalid(str(e)))

        threading.Thread(target=do_validate, daemon=True).start()

    def _on_apikey_valid(self, display_name):
        """Called when API key validation succeeds."""
        self.capture_btn.config(state=tk.NORMAL)
        label = f"Key valid ({display_name})" if display_name else "Key valid"
        self.capture_hint.config(text=f"✓ {label} — Click Start Capture, then open the game",
                                 foreground='#2e7d32')
        self.log(f"API key validated: {display_name}")

    def _on_apikey_invalid(self, error):
        """Called when API key validation fails."""
        self.capture_btn.config(state=tk.DISABLED)
        self.capture_hint.config(text=f"✗ {error}", foreground='#c62828')
        self.log(f"API key invalid: {error}")

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
        self.status_label.config(text="● Capturing... Open Last War now and log in", foreground='#1565c0')
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
        self._capture_src_port = None  # Source port to lock onto specific TCP stream
        self._size_warned = set()
        self._game_pkt_count = 0      # Count of e405/e406 packets seen
        self._unknown_logged = set()  # Unique unknown packet signatures logged
        self.attempt_count = 0
        self._failed_handshakes = set()
        self._credential_queue = []
        self._uploading = False
        self.handshake_label.config(text="○  Handshake: waiting...", style='Waiting.TLabel')
        self.login_label.config(text="○  Login: waiting...", style='Waiting.TLabel')
        self.validate_label.config(text="")
        self.save_btn.config(state=tk.DISABLED)

        self.capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
        self.capture_thread.start()

    def stop_capture(self):
        self.capturing = False
        self.capture_btn.config(text="▶  Start Capture")

        if not self.handshake_data:
            self.status_label.config(text="Stopped - no handshake captured", foreground='#666')
            if self._game_pkt_count == 0:
                self.log("Capture stopped — no game packets seen. "
                         "Check: correct network interface? Game running?")
            else:
                self.log(f"Capture stopped — saw {self._game_pkt_count} game packets "
                         f"but none matched handshake criteria.")
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
                    self.E405_HEADER,
                    self.E406_HEADER,
                    self.E407_HEADER,
                    self.E408_HEADER,
                    self.C405_HEADER,
                    self.C406_HEADER,
                    self.C407_HEADER,
                    self.C408_HEADER,
                )
                is_game_packet = header in (
                    self.E405_HEADER,
                    self.E406_HEADER,
                    self.E407_HEADER,
                    self.E408_HEADER,
                )

                # Diagnostic: log large outbound packets to non-standard ports
                # Skip private IPs (local proxies, VPNs) — only log public destinations
                if (self.handshake_data is None and self._game_pkt_count == 0 and
                        len(data) >= 200 and dport > 10000 and not is_private_ip(dst_ip)):
                    if not hasattr(self, '_unknown_logged'):
                        self._unknown_logged = set()
                    log_key = (dst_ip, dport)
                    if log_key not in self._unknown_logged:
                        self._unknown_logged.add(log_key)
                        self.log(f"[?] Large packet to {dst_ip}:{dport}: "
                                 f"{len(data)} bytes, header={data[:4].hex()}")

                # Diagnostic logging for game packets
                if is_game_packet:
                    self._game_pkt_count += 1
                    if self._game_pkt_count == 1:
                        self.log(f"First game packet: {header.hex()} to {dst_ip}:{dport}, {len(data)} bytes")
                    if self.handshake_data is None:
                        if not (MIN_HANDSHAKE_SIZE <= len(data) <= MAX_HANDSHAKE_SIZE):
                            size_key = len(data)
                            if size_key not in self._size_warned:
                                self._size_warned.add(size_key)
                                self.log(f"[!] Game packet ({header.hex()}) to {dst_ip}:{dport}: "
                                         f"{len(data)} bytes — outside size range "
                                         f"({MIN_HANDSHAKE_SIZE}-{MAX_HANDSHAKE_SIZE})")

                # Step 1: Capture first e405/e406 packet (handshake)
                if (is_game_packet and self.handshake_data is None and
                        MIN_HANDSHAKE_SIZE <= len(data) <= MAX_HANDSHAKE_SIZE):
                    # Skip handshakes that already failed
                    if hash(data) in self._failed_handshakes:
                        self.log(f"Skipping previously failed handshake ({len(data)} bytes)")
                        return
                    self.packets_seen += 1

                    self.protocol = header.hex()
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

                    # Lock onto this specific TCP stream for steps 2+3
                    self._capture_dst_ip = dst_ip
                    self._capture_dst_port = dport
                    self._capture_src_port = sport  # Track source port to identify TCP stream
                    self.root.after(0, self.on_handshake_captured)

                # Steps 2+3: Match on the SAME TCP stream as the handshake
                # (same src_port + dst_port = same connection)
                elif (self.handshake_data is not None and self.login_data is None and
                      self._capture_src_port and sport == self._capture_src_port and
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
                            # Use the full buffer if it starts with a game header
                            # (captures fragmented login packets reassembled across TCP segments)
                            login_candidate = (
                                bytes(buf)
                                if (
                                    len(buf) >= len(data)
                                    and buf[:2] in (
                                        self.E405_HEADER,
                                        self.E406_HEADER,
                                        self.E407_HEADER,
                                        self.E408_HEADER,
                                    )
                                )
                                else data
                            )
                            self.packets_seen += 1
                            self.log(
                                f"[3] Login trigger: {len(login_candidate)} bytes to {dst_ip}:{dport}"
                                f"{' (reassembled from buffer)' if len(login_candidate) > len(data) else ''}"
                            )
                            self.login_data = login_candidate
                            self._stream_buf[key] = bytearray()
                            self.root.after(0, self.on_login_captured)
                            return

                    # Reassembly: scan buffer for a game packet boundary that splits
                    # auth data (before) from login packet (after)
                    for i in range(1, len(buf) - 1):
                        if buf[i] == 0xE4 and buf[i + 1] in (0x05, 0x06, 0x07, 0x08):
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

                            if (
                                self.auth_data is not None
                                and self.login_data is None
                                and login_candidate[:2] in (
                                    self.E405_HEADER,
                                    self.E406_HEADER,
                                    self.E407_HEADER,
                                    self.E408_HEADER,
                                )
                                and MIN_LOGIN_SIZE <= len(login_candidate) <= MAX_LOGIN_SIZE
                            ):
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

        # Queue this credential set
        cred_set = (self.handshake_data, self.auth_data, self.login_data,
                    self.game_server_ip, self.game_server_port, self.protocol)
        self._credential_queue.append(cred_set)
        self.log(f"Queued credential set #{len(self._credential_queue)}")

        # Reset to keep capturing more packets while uploading
        self.handshake_data = None
        self.auth_data = None
        self.login_data = None
        self.game_server_ip = None
        self.game_server_port = None
        self._stream_buf = {}
        self.handshake_label.config(text="○  Handshake: listening for more...", style='Waiting.TLabel')
        self.login_label.config(text="○  Login: listening...", style='Waiting.TLabel')

        # Start uploading if not already
        if not self._uploading:
            self._uploading = True
            threading.Thread(target=self._process_queue, daemon=True).start()

    def _process_queue(self):
        """Process queued credential sets one at a time."""
        while self._credential_queue:
            cred_set = self._credential_queue.pop(0)
            handshake, auth, login, server_ip, server_port, protocol = cred_set
            self.attempt_count += 1
            attempt = self.attempt_count

            self.root.after(0, lambda a=attempt: [
                self.validate_label.config(
                    text=f"⟳  Trying set #{a}...", foreground='#1565c0'),
                self.status_label.config(
                    text=f"Uploading set #{a} ({len(self._credential_queue)} queued)...",
                    foreground='#1565c0')
            ])

            try:
                success, message = self._do_upload_set(handshake, auth, login, server_ip, server_port)
                if success:
                    # Store the winning set back
                    self.handshake_data = handshake
                    self.auth_data = auth
                    self.login_data = login
                    self.game_server_ip = server_ip
                    self.game_server_port = server_port
                    self.protocol = protocol
                    self._uploading = False
                    self.root.after(0, lambda: self._on_upload_success(message))
                    return
                else:
                    self._failed_handshakes.add(hash(handshake))
                    self.log(f"Set #{attempt} failed: {message}")
                    self.root.after(0, lambda a=attempt: self.validate_label.config(
                        text=f"✗  Set #{a} failed — trying next...", foreground='#c62828'))
            except Exception as e:
                self._failed_handshakes.add(hash(handshake))
                self.log(f"Set #{attempt} error: {e}")

        # Queue exhausted, no success — keep capturing
        self._uploading = False
        self.root.after(0, lambda: [
            self.validate_label.config(
                text=f"✗  {self.attempt_count} set(s) failed — waiting for more...",
                foreground='#c62828'),
            self.status_label.config(
                text="Waiting for more packets...", foreground='#e65100')
        ])

    def _do_upload_set(self, handshake, auth, login, server_ip, server_port):
        """Upload a credential set to API. Returns (success: bool, message: str)."""
        api_key = self.apikey_entry.get().strip()

        files = {
            'handshake': ('handshake.bin', handshake, 'application/octet-stream'),
        }
        if auth:
            files['auth_packet'] = ('auth.bin', auth, 'application/octet-stream')
        if login:
            files['login'] = ('login.bin', login, 'application/octet-stream')

        headers = {'X-API-Key': api_key}

        params = {}
        if server_ip and not is_private_ip(server_ip):
            params['server_ip'] = server_ip
            if server_port:
                params['server_port'] = server_port

        self.log(f"Uploading: handshake={len(handshake)}B, "
                 f"auth={len(auth) if auth else 0}B, "
                 f"login={len(login) if login else 0}B, "
                 f"server={server_ip}:{server_port}")

        response = requests.post(
            f"{API_BASE_URL}/auth/credentials/upload",
            headers=headers,
            files=files,
            params=params,
            timeout=30
        )

        if response.ok:
            result = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
            self.log(f"API response: {result}")
            return True, result.get('message', 'Credentials uploaded successfully')
        else:
            self.log(f"API error: HTTP {response.status_code}, body={response.text[:200]}")
            try:
                detail = response.json().get('detail', {})
                if isinstance(detail, dict):
                    error = detail.get('validation_error', detail.get('message', response.text))
                else:
                    error = str(detail)
            except Exception:
                error = response.text
            return False, error

    def _on_upload_success(self, message):
        """Called when API accepts the upload."""
        self.log(f"Upload success: {message}")
        self.validate_label.config(
            text="✓  Uploaded successfully", style='Success.TLabel')
        self.on_capture_complete()

    def on_capture_complete(self):
        self.stop_capture()

        self.status_label.config(text="✓ Done! Credentials captured and uploaded.", foreground='#2e7d32')
        self.save_btn.config(state=tk.NORMAL)
        self.log(f"Complete: server={self.game_server_ip}:{self.game_server_port}")
        self.log(f"  handshake={len(self.handshake_data)}B, "
                 f"auth={len(self.auth_data)}B, "
                 f"login={len(self.login_data)}B")
        self.root.bell()

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

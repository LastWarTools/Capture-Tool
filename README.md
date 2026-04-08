# Last War Credential Capture Tool

Capture your game login credentials for API access.

## For End Users

### Prerequisites

1. **Install Npcap** (required for packet capture on Windows)
   - Download from: https://npcap.com/dist/npcap-1.79.exe
   - Run installer, use default options
   - This is a one-time install

### Usage

1. **Download** `LastWarCapture.exe`
2. **Run** the tool (may need to run as Administrator)
3. **Select** your network interface (usually your Wi-Fi or Ethernet adapter)
4. **Click** "Start Capture"
5. **Launch** Last War on your PC and wait for it to connect
6. **Wait** for "Capture complete!" message
7. **Enter** your API key
8. **Click** "Upload to API"
9. **Done!** Your credentials are saved for API access

### Troubleshooting

**"Scapy not found" error:**
- Make sure Npcap is installed
- Try running as Administrator

**"No packets captured" / Stuck on waiting:**
- Make sure the game connects AFTER you click Start Capture
- Force-close the game completely before starting (Task Manager → End Task)
- Try selecting a different network interface
- Check that Windows Firewall isn't blocking the tool

**Upload fails:**
- Check your internet connection
- Verify your API key is correct
- Make sure you have an active API subscription

---

## For Developers

### Building from Source

```bash
# Install dependencies
pip install -r requirements.txt

# Run directly
python lastwar_capture.py

# Build executable (Windows)
build.bat

# Build executable (Mac/Linux)
chmod +x build.sh
./build.sh
```

### How It Works

The tool captures the game's authentication packets by sniffing TCP traffic during login.

#### Authentication Flow (3 packets)

1. **Handshake** (`e405 4507`, ~1400 bytes) → Relay server (172.65.210.24)
2. **Auth packet** (high-entropy, ~460 bytes) → Same server
3. **Login trigger** (`e405 4505`, ~1361 bytes) → Same server

All three packets go to the **same server**. The login packet has a different header (`4505`) than the handshake (`4507`).

#### Server IPs

| Server | IP | Port | Purpose |
|--------|-----|------|---------|
| Relay | 172.65.210.24 | 18349 | Initial auth relay |
| Game servers | 34.145.128.94, 3.33.246.23, etc. | 18349 | Actual game servers |

For replay, credentials captured to the relay server work when sent to any game server.

### Packet Protocol

| Header | Type | Description |
|--------|------|-------------|
| `e405` | Game packet | Encrypted SmartFox protocol |
| `e406` | Game packet | Alternate protocol (older?) |
| `c405`/`c406` | Response | Server response packets |

The third byte indicates packet type:
- `e405 4507` = Handshake packet
- `e405 4505` = Login trigger packet

### Capture Logic

```
Step 1: Wait for first e405/e406 packet >500 bytes → Save as handshake
        Record server IP and port

Step 2: Wait for non-e405 high-entropy packet >200 bytes to SAME server
        → Save as auth packet

Step 3: Wait for second e405/e406 packet >500 bytes to SAME server
        → Save as login trigger
        This packet has DIFFERENT content than handshake (header 4505 vs 4507)
```

**Important:** The login packet MUST go to the same IP:port as handshake. Packets to different servers are duplicate handshakes, not the real login.

### Output Files

When saving locally, the tool creates:

| File | Description |
|------|-------------|
| `handshake.bin` | First e405 packet |
| `auth.bin` | Auth packet |
| `login.bin` | Second e405 packet (login trigger) |
| `server_info.txt` | Server IP, port, and protocol |
| `capture_log_*.txt` | Debug log with timestamps |

### API Endpoint

Upload endpoint:
```
POST /auth/credentials/upload?server_ip={ip}&server_port={port}
Headers: X-API-Key: {your_api_key}
Content-Type: multipart/form-data

Files:
- handshake: handshake.bin
- login: login.bin
- auth_packet: auth.bin
```

### Common Issues

**Capturing same packet twice:**
If handshake and login have identical content, the tool is capturing TCP retransmissions or the same packet to multiple servers. The fix: ensure Step 3 requires same IP:port as Step 1.

**Wrong server IP saved:**
The game sends handshakes to multiple servers. The tool should capture from the FIRST server (relay), not subsequent game servers.

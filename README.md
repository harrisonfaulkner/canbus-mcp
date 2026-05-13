# canbus-mcp

A CAN bus reverse engineering MCP server for Claude Code. Lets Claude read, analyze, and map CAN bus messages from automotive and motorsport ECUs directly from the conversation.

Built around the PEAK PCAN-USB adapter. Designed for reverse engineering unknown CAN buses without DBC files — though DBC import/export is supported.

## Hardware

- [PEAK PCAN-USB](https://www.peak-system.com/PCAN-USB.199.0.html) (IPEH-002021)

## Requirements

- Python 3.11+
- macOS or Windows
- PEAK PCBUSB driver (macOS) or PEAK Windows driver

## Installation

### 1. Install the PEAK driver

**macOS:**

PEAK does not provide a native macOS driver. Use the open-source PCBUSB library from [mac-can.com](https://www.mac-can.com):

1. Download the PCBUSB package
2. Run the installer — if `install.sh` does nothing, `/usr/local/lib` likely doesn't exist on your machine. Fix it manually:

```bash
sudo mkdir -p /usr/local/lib
sudo cp ~/Downloads/PCBUSB*/libPCBUSB.0.13.dylib /usr/local/lib/
sudo ln -sf /usr/local/lib/libPCBUSB.0.13.dylib /usr/local/lib/libPCBUSB.0.dylib
sudo ln -sf /usr/local/lib/libPCBUSB.0.dylib /usr/local/lib/libPCBUSB.dylib
```

**Windows:**

Download and install the PEAK driver from [peak-system.com](https://www.peak-system.com/Software.68.0.html). No additional steps needed.

### 2. Install canbus-mcp

```bash
git clone https://github.com/YOUR_USERNAME/canbus-mcp
cd canbus-mcp
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
```

### 3. Add to Claude Code

```bash
claude mcp add canbus-re -s user \
  -e DYLD_LIBRARY_PATH=/usr/local/lib \
  -- /absolute/path/to/canbus-mcp/.venv/bin/python -m canbus_mcp.server
```

Replace `/absolute/path/to/canbus-mcp` with the actual path where you cloned the repo.

**Windows:** Use the full path to `.venv\Scripts\python.exe` and omit the `DYLD_LIBRARY_PATH` env var.

Restart Claude Code and run `/mcp` to confirm `canbus-re` appears as connected.

## Usage

Start a Claude Code session and describe what you want to reverse engineer. The recommended workflow:

```
detect_baudrate_auto()     # auto-sniff bus speed from live traffic
connect()                  # open the interface
capture(duration=10)       # record frames
get_traffic_summary()      # see all message IDs, frequencies, DLCs
take_snapshot('idle')      # baseline snapshot

# trigger a physical event (press throttle, turn wheel, etc.)

capture(duration=5)
take_snapshot('event')
compare_snapshots('idle', 'event')   # find what changed

analyze_message(0x1A0)     # byte-level breakdown of a specific ID
track_signal(0x1A0, 2, 2)  # watch bytes [2:4] change over time
define_signal('engine_rpm', 0x1A0, 16, 16, scale=0.25, unit='rpm')
export_dbc('/path/output.dbc')
```

### OBD2

For standard OBD2 vehicles (500k or 250k baud, 11-bit IDs):

```
check_obd2_support()    # check which PIDs are available
read_obd2_pids()        # query RPM, speed, throttle, temps, etc.
```

## Tools

| Tool | Description |
|------|-------------|
| `list_interfaces` | Show available hardware and current connection |
| `detect_baudrate_auto` | Auto-detect baud by listening for valid frames |
| `connect` | Open CAN interface |
| `disconnect` | Close interface |
| `capture` | Record frames for N seconds |
| `take_snapshot` | Save capture buffer as named snapshot |
| `compare_snapshots` | Diff two snapshots to find changed bytes |
| `get_traffic_summary` | All IDs: frequency, DLC, count |
| `analyze_message` | Per-byte entropy, counter/checksum detection |
| `track_signal` | Extract a byte range's values over time |
| `define_signal` | Name a discovered signal (bit position, scale, offset) |
| `decode_frame` | Decode raw hex against known signals |
| `import_dbc` | Load a DBC file |
| `export_dbc` | Export defined signals as DBC |
| `check_obd2_support` | Check OBD2 PID support |
| `read_obd2_pids` | Query all standard OBD2 PIDs |
| `query_obd2_pid` | Send a raw OBD2 request |


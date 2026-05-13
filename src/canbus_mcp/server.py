"""
CAN bus reverse engineering MCP server.
Exposes tools for connecting to a CAN interface, capturing frames, analyzing
message patterns, defining signals, and exporting DBC files.
"""
import asyncio
import logging
import time
import warnings
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

# Suppress the harmless boot-relative timestamp warning from python-can on macOS
warnings.filterwarnings("ignore", message="uptime library not available")
logging.getLogger("can").setLevel(logging.ERROR)

from mcp.server.fastmcp import FastMCP

from .baud_detector import AUTOMOTIVE_BAUDRATES, detect_baudrate
from .can_interface import CANInterface
from .capture_store import CaptureStore, Frame
from .analyzer import analyze_message as _analyze_message
from .analyzer import compare_captures as _compare_captures
from .analyzer import get_traffic_summary as _get_traffic_summary
from .signal_db import SignalDB, SignalDef
from .dbc_handler import load_dbc as _load_dbc, export_dbc as _export_dbc
from . import obd2

# ---------------------------------------------------------------------------
# Shared state (module-level singletons — one CAN session per server process)
# ---------------------------------------------------------------------------
_iface = CANInterface()
_store = CaptureStore()
_signal_db = SignalDB()
_snapshots: dict[str, list[Frame]] = {}
_executor = ThreadPoolExecutor(max_workers=4)

mcp = FastMCP(
    "canbus-re",
    instructions=(
        "CAN bus reverse engineering tools. "
        "Workflow: detect_baudrate_auto → connect → capture → get_traffic_summary → "
        "analyze_message → track_signal → define_signal → export_dbc."
    ),
)


def _require_connection() -> None:
    if not _iface.is_connected:
        raise RuntimeError(
            "Not connected. Call detect_baudrate() then connect() first."
        )


# ---------------------------------------------------------------------------
# Connection tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_interfaces() -> dict:
    """
    List available CAN interface types, channels, and current connection status.
    Use this first to confirm what hardware/channels are available.
    """
    return {
        "interfaces": [
            {
                "interface": "pcan",
                "description": "PEAK PCAN-USB (requires PEAK driver install)",
                "typical_channels": ["PCAN_USBBUS1", "PCAN_USBBUS2"],
                "platform": "macOS + Windows",
                "driver_url": "https://www.peak-system.com/Software.68.0.html",
            },
            {
                "interface": "virtual",
                "description": "Virtual bus — no hardware needed, good for testing",
                "typical_channels": ["test"],
                "platform": "all",
            },
            {
                "interface": "socketcan",
                "description": "Linux SocketCAN kernel interface",
                "typical_channels": ["can0", "can1", "vcan0"],
                "platform": "Linux only",
            },
            {
                "interface": "kvaser",
                "description": "Kvaser hardware",
                "typical_channels": ["0"],
                "platform": "macOS + Windows",
            },
        ],
        "automotive_baudrates": AUTOMOTIVE_BAUDRATES,
        "current_connection": {
            "connected": _iface.is_connected,
            "interface": _iface.connection.interface if _iface.connection else None,
            "channel": _iface.connection.channel if _iface.connection else None,
            "baudrate": _iface.connection.baudrate if _iface.connection else None,
        },
    }


@mcp.tool()
async def detect_baudrate_auto(
    interface: str = "pcan",
    channel: str = "PCAN_USBBUS1",
    timeout_per_rate: float = 2.0,
) -> dict:
    """
    Auto-detect CAN bus baudrate by listening for valid frames at each common rate.
    Tries: 500k, 250k, 1M, 125k, 100k, 83.3k, 50k, 33.3k, 20k, 10k bps.

    Requires live traffic on the bus. If the bus is idle, put the vehicle/ECU into
    a state that generates traffic (ignition on, engine running) before calling this.

    Args:
        interface: CAN interface type. Use 'pcan' for PEAK PCAN-USB.
        channel: Interface channel. Default 'PCAN_USBBUS1' for first PCAN-USB device.
        timeout_per_rate: Seconds to listen at each baudrate before trying next.
    """
    loop = asyncio.get_event_loop()
    baudrate, frames = await loop.run_in_executor(
        _executor, detect_baudrate, interface, channel, timeout_per_rate
    )

    if baudrate:
        return {
            "detected_baudrate": baudrate,
            "sample_frames": [
                {"id": hex(f.arbitration_id), "data": f.data.hex(), "dlc": f.dlc}
                for f in frames[:5]
            ],
            "next_step": (
                f'Call connect(interface="{interface}", channel="{channel}", '
                f"baudrate={baudrate}) to open the interface for capturing."
            ),
        }
    return {
        "detected_baudrate": None,
        "error": (
            "No valid frames found at any baudrate. "
            "Ensure: (1) hardware is connected, (2) CAN bus has active traffic, "
            "(3) correct channel name for your OS."
        ),
        "tried_baudrates": AUTOMOTIVE_BAUDRATES,
    }


@mcp.tool()
async def connect(
    interface: str = "pcan",
    channel: str = "PCAN_USBBUS1",
    baudrate: int = 500_000,
) -> dict:
    """
    Open a connection to a CAN interface.

    Args:
        interface: Interface type ('pcan' for PEAK PCAN-USB, 'virtual' for testing).
        channel: Channel name (e.g. 'PCAN_USBBUS1').
        baudrate: Bus speed in bps. Common: 500000, 250000, 1000000, 125000.
    """
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(_executor, _iface.connect, interface, channel, baudrate)
        _store.clear()
        return {
            "status": "connected",
            "interface": interface,
            "channel": channel,
            "baudrate": baudrate,
            "next_step": "Call capture() to record messages, or get_traffic_summary() after capturing.",
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


@mcp.tool()
def disconnect() -> dict:
    """Close the current CAN interface connection."""
    was_connected = _iface.is_connected
    _iface.disconnect()
    return {"status": "disconnected", "was_connected": was_connected}


# ---------------------------------------------------------------------------
# Capture tools
# ---------------------------------------------------------------------------

def _flush_hw_buffer() -> None:
    """Drain the hardware receive queue without storing any frames."""
    while _iface.recv(timeout=0.0) is not None:
        pass


def _capture_sync(duration: float, filter_ids: Optional[list[int]]) -> list[Frame]:
    _require_connection()
    _flush_hw_buffer()
    frames: list[Frame] = []
    end_time = time.monotonic() + duration

    while time.monotonic() < end_time:
        msg = _iface.recv(timeout=0.0)
        if msg is None:
            time.sleep(0.001)
            continue
        if not msg.is_error_frame:
            if filter_ids is None or msg.arbitration_id in filter_ids:
                frame = Frame(
                    timestamp=msg.timestamp,
                    arbitration_id=msg.arbitration_id,
                    data=bytes(msg.data),
                    dlc=msg.dlc,
                    is_extended_id=msg.is_extended_id,
                )
                frames.append(frame)
                _store.add(frame)
    return frames


@mcp.tool()
async def capture(
    duration: float = 5.0,
    filter_ids: Optional[list[int]] = None,
) -> dict:
    """
    Capture CAN frames for a fixed duration. Frames accumulate in the internal buffer
    for use by analysis tools.

    Args:
        duration: Capture window in seconds.
        filter_ids: Optional list of decimal CAN IDs to capture. None = capture all.
    """
    loop = asyncio.get_event_loop()
    try:
        frames = await loop.run_in_executor(_executor, _capture_sync, duration, filter_ids)
        unique_ids = sorted(set(f.arbitration_id for f in frames))
        return {
            "frames_captured": len(frames),
            "unique_ids": len(unique_ids),
            "ids_seen": [hex(i) for i in unique_ids],
            "duration_seconds": duration,
            "buffer_total": len(_store.frames),
            "next_step": "Call get_traffic_summary() to see message frequencies.",
        }
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def take_snapshot(name: str) -> dict:
    """
    Save the current capture buffer as a named snapshot.

    Use this for before/after comparison:
      1. Capture baseline traffic → take_snapshot('idle')
      2. Trigger an action (press throttle, turn steering, etc.)
      3. Capture again → take_snapshot('throttle_pressed')
      4. compare_snapshots('idle', 'throttle_pressed') to find changed bytes

    Args:
        name: Snapshot label.
    """
    _snapshots[name] = _store.snapshot()
    return {
        "snapshot": name,
        "frames_saved": len(_snapshots[name]),
        "unique_ids": len(set(f.arbitration_id for f in _snapshots[name])),
        "available_snapshots": list(_snapshots.keys()),
    }


@mcp.tool()
def clear_capture() -> dict:
    """Clear all captured frames from the internal buffer. Does not affect snapshots."""
    count = len(_store.frames)
    _store.clear()
    if _iface.is_connected:
        _flush_hw_buffer()
    return {"cleared_frames": count}


# ---------------------------------------------------------------------------
# Analysis tools
# ---------------------------------------------------------------------------

@mcp.tool()
def get_traffic_summary() -> dict:
    """
    Summarize all captured message IDs: frame count, frequency, DLC, and category.
    High-frequency IDs (>100 Hz) are typically sensor loops.
    Low-frequency IDs (<5 Hz) are typically status or event-driven messages.
    """
    summary = _get_traffic_summary(_store)
    return {
        "total_unique_ids": len(summary),
        "messages": summary,
        "tip": (
            "Start analysis with high-frequency IDs for real-time sensor signals "
            "(RPM, throttle, steering). Use analyze_message() on a specific ID for "
            "byte-level breakdown."
        ),
    }


@mcp.tool()
def analyze_message(can_id: int) -> dict:
    """
    Deep-analyze a single CAN message ID across all captured frames.
    Reports per-byte entropy, counter/checksum detection, and signal candidates.

    Args:
        can_id: CAN message ID in decimal (e.g. 1234) or use int('0x4B0', 16).
    """
    frames = _store.get_by_id(can_id)
    if not frames:
        return {
            "error": f"No frames captured for CAN ID {hex(can_id)}.",
            "tip": "Run capture() first, then check get_traffic_summary() for valid IDs.",
        }

    result = _analyze_message(frames)
    if not result:
        return {"error": "Analysis failed."}

    return {
        "can_id": hex(can_id),
        "frame_count": result.frame_count,
        "timing_ms": {
            "avg": result.avg_interval_ms,
            "min": result.min_interval_ms,
            "max": result.max_interval_ms,
        },
        "dlc": result.dlc,
        "byte_analysis": [
            {
                "byte": b.index,
                "pattern": b.pattern_type,
                "unique_values": b.unique_values,
                "range_hex": f"0x{b.min_val:02X}–0x{b.max_val:02X}",
                "entropy": b.entropy,
                "notes": b.notes,
            }
            for b in result.byte_stats
        ],
        "suspected_counters": [f"byte[{i}]" for i in result.suspected_counters],
        "suspected_checksums": [f"byte[{i}]" for i in result.suspected_checksums],
        "tip": (
            "Use track_signal() to extract and observe a specific byte range over time. "
            "Skip counter and checksum bytes. Use define_signal() to name identified signals."
        ),
    }


@mcp.tool()
def track_signal(
    can_id: int,
    start_byte: int,
    num_bytes: int = 1,
    signed: bool = False,
    scale: float = 1.0,
    offset: float = 0.0,
    byte_order: str = "little_endian",
) -> dict:
    """
    Extract a byte range from captured frames and show how the value changes over time.
    Use this to observe a candidate signal while correlating with physical inputs.

    Args:
        can_id: CAN message ID.
        start_byte: First byte index (0-based).
        num_bytes: How many consecutive bytes to read (1–4).
        signed: Interpret as signed integer.
        scale: Physical = raw * scale + offset.
        offset: Physical = raw * scale + offset.
        byte_order: 'little_endian' (Intel) or 'big_endian' (Motorola).
    """
    frames = _store.get_by_id(can_id)
    if not frames:
        return {"error": f"No frames for CAN ID {hex(can_id)}."}

    values = []
    for f in frames:
        end = start_byte + num_bytes
        if len(f.data) >= end:
            raw_bytes = f.data[start_byte:end]
            raw = int.from_bytes(
                raw_bytes,
                "little" if byte_order == "little_endian" else "big",
                signed=signed,
            )
            values.append({
                "timestamp": round(f.timestamp, 4),
                "raw": raw,
                "value": round(raw * scale + offset, 4),
            })

    if not values:
        return {"error": "No valid frames found for that byte range."}

    raw_list = [v["raw"] for v in values]
    return {
        "can_id": hex(can_id),
        "byte_range": f"[{start_byte}:{start_byte + num_bytes}]",
        "sample_count": len(values),
        "raw_range": f"{min(raw_list)}–{max(raw_list)}",
        "scaled_range": f"{min(v['value'] for v in values)}–{max(v['value'] for v in values)}",
        "last_50_samples": values[-50:],
        "tip": "If this correlates with a physical signal, use define_signal() to name it.",
    }


@mcp.tool()
def compare_snapshots(before_name: str, after_name: str) -> dict:
    """
    Diff two named snapshots to find which IDs and bytes changed.

    Args:
        before_name: Label of the baseline snapshot.
        after_name: Label of the post-event snapshot.
    """
    if before_name not in _snapshots:
        return {"error": f'Snapshot "{before_name}" not found.', "available": list(_snapshots.keys())}
    if after_name not in _snapshots:
        return {"error": f'Snapshot "{after_name}" not found.', "available": list(_snapshots.keys())}

    result = _compare_captures(_snapshots[before_name], _snapshots[after_name])
    result["tip"] = (
        "Focus on IDs in changed_data with large byte deltas — "
        "these are the best candidates for the triggered event. "
        "Use analyze_message() + track_signal() to drill in."
    )
    return result


@mcp.tool()
def list_snapshots() -> dict:
    """List all saved snapshots and their frame counts."""
    return {
        "snapshots": {
            name: {
                "frames": len(frames),
                "unique_ids": len(set(f.arbitration_id for f in frames)),
            }
            for name, frames in _snapshots.items()
        }
    }


# ---------------------------------------------------------------------------
# Signal definition tools
# ---------------------------------------------------------------------------

@mcp.tool()
def define_signal(
    name: str,
    can_id: int,
    start_bit: int,
    length: int,
    byte_order: str = "little_endian",
    value_type: str = "unsigned",
    scale: float = 1.0,
    offset: float = 0.0,
    unit: str = "",
    description: str = "",
) -> dict:
    """
    Define a named signal from a CAN message (bit-level precision).
    Physical value = (raw * scale) + offset.

    Args:
        name: Signal name, e.g. 'engine_rpm' or 'throttle_pct'.
        can_id: CAN message ID.
        start_bit: LSB position (little_endian) or MSB position (big_endian), 0-based.
        length: Signal width in bits.
        byte_order: 'little_endian' (Intel/LSB-first) or 'big_endian' (Motorola/MSB-first).
        value_type: 'unsigned' or 'signed'.
        scale: Multiplier for raw→physical conversion.
        offset: Addend for raw→physical conversion.
        unit: Physical unit string, e.g. 'rpm', 'km/h', '%', '°C'.
        description: Human-readable description.
    """
    sig = SignalDef(
        name=name,
        can_id=can_id,
        start_bit=start_bit,
        length=length,
        byte_order=byte_order,
        value_type=value_type,
        scale=scale,
        offset=offset,
        unit=unit,
        description=description,
    )
    _signal_db.add(sig)

    recent_values: list[float] = []
    for f in _store.get_by_id(can_id)[-20:]:
        decoded = _signal_db.decode_frame(can_id, f.data)
        if name in decoded:
            recent_values.append(decoded[name])

    return {
        "defined": name,
        "can_id": hex(can_id),
        "bits": f"[{start_bit}:{start_bit + length - 1}]",
        "formula": f"physical = raw * {scale} + {offset} {unit}",
        "recent_values": recent_values,
    }


@mcp.tool()
def list_signals() -> dict:
    """List all defined signals in the current session."""
    return {
        "count": len(_signal_db.signals),
        "signals": _signal_db.to_dict(),
    }


@mcp.tool()
def remove_signal(name: str) -> dict:
    """Remove a signal definition by name."""
    removed = _signal_db.remove(name)
    return {"removed": removed, "name": name}


@mcp.tool()
def decode_frame(can_id: int, data_hex: str) -> dict:
    """
    Decode a raw CAN frame against all known signal definitions for that CAN ID.

    Args:
        can_id: CAN message ID.
        data_hex: Frame payload as a hex string, e.g. '0A1B2C3D4E5F6789'.
    """
    try:
        data = bytes.fromhex(data_hex.replace(" ", ""))
    except ValueError as exc:
        return {"error": f"Invalid hex string: {exc}"}

    decoded = _signal_db.decode_frame(can_id, data)
    known = _signal_db.get_by_can_id(can_id)

    return {
        "can_id": hex(can_id),
        "data": data.hex(),
        "known_signals": len(known),
        "decoded": decoded,
    }


# ---------------------------------------------------------------------------
# DBC tools
# ---------------------------------------------------------------------------

@mcp.tool()
def import_dbc(file_path: str) -> dict:
    """
    Import a DBC file and add its signal definitions to the current session.
    Signals are named as 'MessageName.SignalName'.

    Args:
        file_path: Absolute path to the .dbc file.
    """
    try:
        return _load_dbc(file_path, _signal_db)
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def export_dbc(file_path: str) -> dict:
    """
    Export all current signal definitions to a DBC file.
    Can be opened in SavvyCAN, PEAK PCAN-Explorer, CANdb++, etc.

    Args:
        file_path: Absolute path for the output .dbc file.
    """
    try:
        return _export_dbc(file_path, _signal_db)
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# OBD2 tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def check_obd2_support() -> dict:
    """
    Query OBD2 service 01 PID 00 to check if the vehicle supports OBD2
    and which PIDs are available. Requires connection to the vehicle CAN bus
    (typically 500k or 250k baud on 11-bit ID bus).
    """
    _require_connection()
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(_executor, obd2.check_supported_pids, _iface.bus)
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
async def read_obd2_pids() -> dict:
    """
    Query all known OBD2 PIDs (RPM, speed, throttle, temps, MAF, fuel level, etc.)
    and return decoded physical values.
    """
    _require_connection()
    loop = asyncio.get_event_loop()
    try:
        results = await loop.run_in_executor(_executor, obd2.decode_known_pids, _iface.bus)
        return {"count": len(results), "values": results}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
async def query_obd2_pid(service: int, pid: int) -> dict:
    """
    Send a raw OBD2 request and return the response bytes.

    Args:
        service: OBD2 service number (e.g. 1 for current data, 3 for DTCs).
        pid: PID/subfunction number.
    """
    _require_connection()
    loop = asyncio.get_event_loop()
    try:
        response = await loop.run_in_executor(_executor, obd2.query_pid, _iface.bus, service, pid)
        if response:
            return {
                "service": hex(service),
                "pid": hex(pid),
                "raw_hex": response.hex(),
                "bytes": list(response),
            }
        return {"error": "No response (timeout). Vehicle may not support this PID."}
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()

"""
OBD2 over CAN (ISO 15765-4).
Standard IDs: request 0x7DF (broadcast), responses 0x7E8-0x7EF.
"""
import can
import time
from typing import Optional

OBD2_REQUEST_ID = 0x7DF
OBD2_RESPONSE_MIN = 0x7E8
OBD2_RESPONSE_MAX = 0x7EF

# (service, pid) -> (name, decoder_fn, unit)
KNOWN_PIDS: dict[tuple[int, int], tuple[str, object, str]] = {
    (0x01, 0x04): ("Engine Load",         lambda d: d[2] * 100 / 255,                 "%"),
    (0x01, 0x05): ("Coolant Temp",         lambda d: d[2] - 40,                        "°C"),
    (0x01, 0x0B): ("Intake Manifold Pres", lambda d: d[2],                             "kPa"),
    (0x01, 0x0C): ("Engine RPM",           lambda d: (d[2] * 256 + d[3]) / 4,          "rpm"),
    (0x01, 0x0D): ("Vehicle Speed",        lambda d: d[2],                             "km/h"),
    (0x01, 0x0E): ("Timing Advance",       lambda d: d[2] / 2 - 64,                   "° BTDC"),
    (0x01, 0x0F): ("Intake Air Temp",      lambda d: d[2] - 40,                        "°C"),
    (0x01, 0x10): ("MAF Rate",             lambda d: (d[2] * 256 + d[3]) / 100,        "g/s"),
    (0x01, 0x11): ("Throttle Position",    lambda d: d[2] * 100 / 255,                 "%"),
    (0x01, 0x1F): ("Engine Run Time",      lambda d: d[2] * 256 + d[3],               "s"),
    (0x01, 0x2F): ("Fuel Level",           lambda d: d[2] * 100 / 255,                 "%"),
    (0x01, 0x33): ("Barometric Pressure",  lambda d: d[2],                             "kPa"),
    (0x01, 0x46): ("Ambient Air Temp",     lambda d: d[2] - 40,                        "°C"),
    (0x01, 0x4C): ("Commanded Throttle",   lambda d: d[2] * 100 / 255,                 "%"),
    (0x01, 0x5C): ("Engine Oil Temp",      lambda d: d[2] - 40,                        "°C"),
    (0x01, 0x5E): ("Fuel Rate",            lambda d: (d[2] * 256 + d[3]) * 0.05,      "L/h"),
    (0x01, 0x67): ("Coolant Temp (alt)",   lambda d: d[3] - 40,                        "°C"),
}


def query_pid(bus: can.BusABC, service: int, pid: int, timeout: float = 1.0) -> Optional[bytes]:
    """Send a single OBD2 PID request; return raw response bytes or None on timeout."""
    request = can.Message(
        arbitration_id=OBD2_REQUEST_ID,
        data=[0x02, service, pid, 0x00, 0x00, 0x00, 0x00, 0x00],
        is_extended_id=False,
    )
    bus.send(request)

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        msg = bus.recv(timeout=0.05)
        if msg and OBD2_RESPONSE_MIN <= msg.arbitration_id <= OBD2_RESPONSE_MAX:
            if len(msg.data) >= 3 and msg.data[1] == service + 0x40 and msg.data[2] == pid:
                return bytes(msg.data)
    return None


def check_supported_pids(bus: can.BusABC) -> dict:
    """
    Query service 01 PID 00 (supported PID bitmask 0x01-0x20).
    Returns dict with obd2_present flag and list of supported PID hex strings.
    """
    supported: list[str] = []
    response = query_pid(bus, 0x01, 0x00)
    if response and len(response) >= 6:
        bitmask = int.from_bytes(response[3:7], "big")
        for bit in range(32):
            pid = 0x01 + bit
            if bitmask & (1 << (31 - bit)):
                supported.append(hex(pid))

    return {
        "obd2_present": bool(supported),
        "supported_pids": supported,
        "note": "Supported PID list covers range 0x01-0x20 only. Query PID 0x20/0x40/0x60 for more.",
    }


def decode_known_pids(bus: can.BusABC) -> list[dict]:
    """Query all PIDs in KNOWN_PIDS and return decoded physical values."""
    results = []
    for (service, pid), (name, decoder, unit) in KNOWN_PIDS.items():
        response = query_pid(bus, service, pid)
        if response:
            try:
                value = decoder(list(response))
                results.append({
                    "name": name,
                    "service": hex(service),
                    "pid": hex(pid),
                    "value": round(float(value), 3),
                    "unit": unit,
                })
            except Exception:
                pass
    return results

import can
import time
from typing import Optional

# Ordered by likelihood in automotive/motorsports:
# 500k = most modern cars, 250k = common OBD2 / older CAN,
# 1M = high-speed motorsport, 125k = low-speed comfort/body bus
AUTOMOTIVE_BAUDRATES = [500_000, 250_000, 1_000_000, 125_000, 100_000, 83_333, 50_000, 33_333, 20_000, 10_000]


def detect_baudrate(
    interface: str,
    channel: str,
    timeout_per_rate: float = 2.0,
) -> tuple[Optional[int], list[can.Message]]:
    """
    Try each baudrate in AUTOMOTIVE_BAUDRATES order.
    Returns (detected_baudrate, sample_frames) on success, (None, []) on failure.
    Requires live CAN traffic to be present on the bus.
    """
    for baud in AUTOMOTIVE_BAUDRATES:
        bus = None
        try:
            bus = can.interface.Bus(interface=interface, channel=channel, bitrate=baud)
            frames: list[can.Message] = []
            end_time = time.monotonic() + timeout_per_rate

            while time.monotonic() < end_time:
                msg = bus.recv(timeout=0.05)
                if msg and not msg.is_error_frame:
                    frames.append(msg)
                    # 3 clean frames is enough confidence
                    if len(frames) >= 3:
                        bus.shutdown()
                        return baud, frames

            bus.shutdown()
            if frames:
                return baud, frames

        except Exception:
            if bus:
                try:
                    bus.shutdown()
                except Exception:
                    pass

    return None, []

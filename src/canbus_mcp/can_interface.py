import can
from dataclasses import dataclass
from typing import Optional


@dataclass
class ConnectionInfo:
    interface: str
    channel: str
    baudrate: int


class CANInterface:
    def __init__(self):
        self.bus: Optional[can.BusABC] = None
        self.connection: Optional[ConnectionInfo] = None

    def connect(self, interface: str, channel: str, baudrate: int) -> None:
        if self.bus:
            self.bus.shutdown()
            self.bus = None
        self.bus = can.interface.Bus(
            interface=interface,
            channel=channel,
            bitrate=baudrate,
        )
        self.connection = ConnectionInfo(interface, channel, baudrate)

    def disconnect(self) -> None:
        if self.bus:
            self.bus.shutdown()
            self.bus = None
            self.connection = None

    def recv(self, timeout: float = 0.1) -> Optional[can.Message]:
        if not self.bus:
            raise RuntimeError("Not connected to CAN bus.")
        return self.bus.recv(timeout=timeout)

    def send(self, msg: can.Message) -> None:
        if not self.bus:
            raise RuntimeError("Not connected to CAN bus.")
        self.bus.send(msg)

    @property
    def is_connected(self) -> bool:
        return self.bus is not None

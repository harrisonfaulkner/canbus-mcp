from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class SignalDef:
    name: str
    can_id: int
    start_bit: int
    length: int
    byte_order: str = "little_endian"   # 'little_endian' (Intel) | 'big_endian' (Motorola)
    value_type: str = "unsigned"         # 'unsigned' | 'signed'
    scale: float = 1.0
    offset: float = 0.0
    unit: str = ""
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    description: str = ""


class SignalDB:
    def __init__(self):
        self.signals: dict[str, SignalDef] = {}

    def add(self, signal: SignalDef) -> None:
        self.signals[signal.name] = signal

    def get(self, name: str) -> Optional[SignalDef]:
        return self.signals.get(name)

    def get_by_can_id(self, can_id: int) -> list[SignalDef]:
        return [s for s in self.signals.values() if s.can_id == can_id]

    def remove(self, name: str) -> bool:
        if name in self.signals:
            del self.signals[name]
            return True
        return False

    def decode_frame(self, can_id: int, data: bytes) -> dict[str, float]:
        results = {}
        for sig in self.get_by_can_id(can_id):
            try:
                raw = _extract_bits(data, sig.start_bit, sig.length, sig.byte_order)
                if sig.value_type == "signed" and raw >= (1 << (sig.length - 1)):
                    raw -= 1 << sig.length
                results[sig.name] = round(raw * sig.scale + sig.offset, 6)
            except Exception:
                pass
        return results

    def to_dict(self) -> dict:
        return {name: asdict(sig) for name, sig in self.signals.items()}


def _extract_bits(data: bytes, start_bit: int, length: int, byte_order: str) -> int:
    """
    Extract a signal value from CAN data bytes.

    little_endian (Intel):  start_bit is the LSB position counting from bit 0 of byte 0.
    big_endian (Motorola):  start_bit is the MSB position in the same bit numbering.
    """
    if byte_order == "little_endian":
        value = int.from_bytes(data, "little")
        mask = (1 << length) - 1
        return (value >> start_bit) & mask
    else:
        value = int.from_bytes(data, "big")
        total_bits = len(data) * 8
        shift = total_bits - start_bit - length
        if shift < 0:
            raise ValueError(f"start_bit={start_bit} length={length} exceeds data length")
        mask = (1 << length) - 1
        return (value >> shift) & mask

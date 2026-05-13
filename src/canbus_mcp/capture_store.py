from collections import defaultdict
from dataclasses import dataclass


@dataclass
class Frame:
    timestamp: float
    arbitration_id: int
    data: bytes
    dlc: int
    is_extended_id: bool


class CaptureStore:
    def __init__(self, max_frames: int = 200_000):
        self.max_frames = max_frames
        self.frames: list[Frame] = []
        self._by_id: dict[int, list[Frame]] = defaultdict(list)

    def add(self, frame: Frame) -> None:
        if len(self.frames) >= self.max_frames:
            evicted = self.frames.pop(0)
            id_list = self._by_id[evicted.arbitration_id]
            if id_list:
                id_list.pop(0)
        self.frames.append(frame)
        self._by_id[frame.arbitration_id].append(frame)

    def get_by_id(self, can_id: int) -> list[Frame]:
        return list(self._by_id.get(can_id, []))

    def get_all_ids(self) -> list[int]:
        return list(self._by_id.keys())

    def clear(self) -> None:
        self.frames.clear()
        self._by_id.clear()

    def snapshot(self) -> list[Frame]:
        return list(self.frames)

    def since(self, timestamp: float) -> list[Frame]:
        return [f for f in self.frames if f.timestamp >= timestamp]

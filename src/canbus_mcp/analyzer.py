import math
from collections import Counter
from dataclasses import dataclass
from typing import Optional

from .capture_store import CaptureStore, Frame


@dataclass
class ByteStats:
    index: int
    unique_values: int
    min_val: int
    max_val: int
    entropy: float
    is_counter: bool
    is_constant: bool
    pattern_type: str  # 'counter' | 'checksum_candidate' | 'constant' | 'signal' | 'unknown'
    notes: str


@dataclass
class MessageAnalysis:
    can_id: int
    frame_count: int
    avg_interval_ms: float
    min_interval_ms: float
    max_interval_ms: float
    dlc: int
    byte_stats: list[ByteStats]
    suspected_counters: list[int]
    suspected_checksums: list[int]


def analyze_message(frames: list[Frame]) -> Optional[MessageAnalysis]:
    if not frames:
        return None

    can_id = frames[0].arbitration_id
    dlc = max(f.dlc for f in frames)

    timestamps = [f.timestamp for f in frames]
    intervals = [(timestamps[i + 1] - timestamps[i]) * 1000 for i in range(len(timestamps) - 1)]
    avg_ms = sum(intervals) / len(intervals) if intervals else 0.0
    min_ms = min(intervals) if intervals else 0.0
    max_ms = max(intervals) if intervals else 0.0

    byte_stats: list[ByteStats] = []
    suspected_counters: list[int] = []
    suspected_checksums: list[int] = []

    for i in range(dlc):
        values = [f.data[i] for f in frames if len(f.data) > i]
        if not values:
            continue

        unique = len(set(values))
        min_v, max_v = min(values), max(values)
        ent = _entropy(values)
        is_ctr = _detect_counter(values)
        is_const = unique == 1
        is_cksum = not is_ctr and not is_const and _detect_xor_checksum(frames, i)

        if is_ctr:
            suspected_counters.append(i)
            pattern = "counter"
            notes = "Incrementing counter — skip when searching for signal bytes"
        elif is_const:
            pattern = "constant"
            notes = f"Always 0x{min_v:02X} — likely message type ID or padding"
        elif is_cksum:
            suspected_checksums.append(i)
            pattern = "checksum_candidate"
            notes = "XOR of other bytes matches ~70%+ of frames — likely checksum"
        elif ent > 3.5:
            pattern = "signal"
            notes = "High entropy, wide value range — likely a real signal"
        elif ent > 1.5:
            pattern = "signal"
            notes = "Moderate entropy — possible enum/status or low-resolution signal"
        else:
            pattern = "unknown"
            notes = "Low entropy, limited values — investigate further"

        byte_stats.append(ByteStats(
            index=i,
            unique_values=unique,
            min_val=min_v,
            max_val=max_v,
            entropy=round(ent, 3),
            is_counter=is_ctr,
            is_constant=is_const,
            pattern_type=pattern,
            notes=notes,
        ))

    return MessageAnalysis(
        can_id=can_id,
        frame_count=len(frames),
        avg_interval_ms=round(avg_ms, 2),
        min_interval_ms=round(min_ms, 2),
        max_interval_ms=round(max_ms, 2),
        dlc=dlc,
        byte_stats=byte_stats,
        suspected_counters=suspected_counters,
        suspected_checksums=suspected_checksums,
    )


def get_traffic_summary(store: CaptureStore) -> list[dict]:
    summary = []
    for can_id in store.get_all_ids():
        frames = store.get_by_id(can_id)
        if not frames:
            continue
        timestamps = [f.timestamp for f in frames]
        if len(timestamps) > 1:
            duration = timestamps[-1] - timestamps[0]
            freq = len(frames) / duration if duration > 0 else 0.0
        else:
            freq = 0.0

        summary.append({
            "can_id": hex(can_id),
            "can_id_dec": can_id,
            "count": len(frames),
            "dlc": frames[0].dlc,
            "frequency_hz": round(freq, 2),
            "is_extended_id": frames[0].is_extended_id,
            "category": _categorize_frequency(freq),
        })

    return sorted(summary, key=lambda x: x["count"], reverse=True)


def compare_captures(before: list[Frame], after: list[Frame]) -> dict:
    before_by_id: dict[int, list[Frame]] = {}
    after_by_id: dict[int, list[Frame]] = {}

    for f in before:
        before_by_id.setdefault(f.arbitration_id, []).append(f)
    for f in after:
        after_by_id.setdefault(f.arbitration_id, []).append(f)

    new_ids = set(after_by_id) - set(before_by_id)
    disappeared = set(before_by_id) - set(after_by_id)
    changed: dict[str, list] = {}

    for can_id in set(before_by_id) & set(after_by_id):
        bf = before_by_id[can_id][-1]
        af = after_by_id[can_id][-1]
        if bf.data == af.data:
            continue
        changed_bytes = []
        for i in range(min(len(bf.data), len(af.data))):
            if bf.data[i] != af.data[i]:
                changed_bytes.append({
                    "byte_index": i,
                    "before": f"0x{bf.data[i]:02X}",
                    "after": f"0x{af.data[i]:02X}",
                    "delta": af.data[i] - bf.data[i],
                })
        if changed_bytes:
            changed[hex(can_id)] = changed_bytes

    return {
        "new_ids": [hex(i) for i in sorted(new_ids)],
        "disappeared_ids": [hex(i) for i in sorted(disappeared)],
        "changed_data": changed,
    }


# --- Internal helpers ---

def _entropy(values: list[int]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _detect_counter(values: list[int]) -> bool:
    """True if most consecutive diffs are the same small positive value (wrapping)."""
    if len(values) < 6:
        return False
    diffs = [(values[i + 1] - values[i]) % 256 for i in range(len(values) - 1)]
    top_diff, top_count = Counter(diffs).most_common(1)[0]
    return top_diff in (1, 2, 4) and (top_count / len(diffs)) > 0.65


def _detect_xor_checksum(frames: list[Frame], byte_idx: int) -> bool:
    """XOR of all other bytes equals this byte in >=70% of frames."""
    if len(frames) < 8:
        return False
    matches = 0
    for f in frames:
        if len(f.data) <= byte_idx:
            continue
        xor = 0
        for i, b in enumerate(f.data):
            if i != byte_idx:
                xor ^= b
        if xor == f.data[byte_idx]:
            matches += 1
    return (matches / len(frames)) >= 0.70


def _categorize_frequency(hz: float) -> str:
    if hz == 0:
        return "sporadic"
    if hz >= 100:
        return "fast (sensor/control loop)"
    if hz >= 20:
        return "medium (powertrain data)"
    if hz >= 5:
        return "slow (status)"
    return "very slow (event-driven)"

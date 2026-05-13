import cantools
import cantools.database
import cantools.database.conversion

from .signal_db import SignalDB, SignalDef


def load_dbc(path: str, signal_db: SignalDB) -> dict:
    """Parse a DBC file and import all signals into signal_db."""
    db = cantools.database.load_file(path)
    loaded_signals: list[str] = []

    for msg in db.messages:
        for sig in msg.signals:
            byte_order = "big_endian" if sig.byte_order == "big_endian" else "little_endian"
            value_type = "signed" if sig.is_signed else "unsigned"

            signal_def = SignalDef(
                name=f"{msg.name}.{sig.name}",
                can_id=msg.frame_id,
                start_bit=sig.start,
                length=sig.length,
                byte_order=byte_order,
                value_type=value_type,
                scale=float(sig.scale) if sig.scale is not None else 1.0,
                offset=float(sig.offset) if sig.offset is not None else 0.0,
                unit=sig.unit or "",
                min_value=float(sig.minimum) if sig.minimum is not None else None,
                max_value=float(sig.maximum) if sig.maximum is not None else None,
                description=sig.comment or "",
            )
            signal_db.add(signal_def)
            loaded_signals.append(signal_def.name)

    return {
        "messages_loaded": len(db.messages),
        "signals_loaded": len(loaded_signals),
        "signal_names": loaded_signals,
    }


def export_dbc(path: str, signal_db: SignalDB) -> dict:
    """Export all signals in signal_db to a DBC file."""
    by_id: dict[int, list[SignalDef]] = {}
    for sig in signal_db.signals.values():
        by_id.setdefault(sig.can_id, []).append(sig)

    messages = []
    for can_id, sigs in by_id.items():
        max_bit = max(s.start_bit + s.length for s in sigs)
        dlc = max(8, (max_bit + 7) // 8)

        can_signals = []
        for sig in sigs:
            sig_name = sig.name.split(".")[-1] if "." in sig.name else sig.name
            conversion = cantools.database.conversion.LinearConversion(
                scale=sig.scale,
                offset=sig.offset,
                is_float=False,
            )
            can_signals.append(
                cantools.database.Signal(
                    name=sig_name,
                    start=sig.start_bit,
                    length=sig.length,
                    byte_order=sig.byte_order,
                    is_signed=sig.value_type == "signed",
                    conversion=conversion,
                    unit=sig.unit or None,
                    comment=sig.description or None,
                )
            )

        msg_name = f"MSG_{can_id:03X}"
        messages.append(
            cantools.database.Message(
                frame_id=can_id,
                name=msg_name,
                length=dlc,
                signals=can_signals,
            )
        )

    db = cantools.database.Database(messages=messages)
    cantools.database.dump_file(db, path)

    return {
        "messages_exported": len(messages),
        "signals_exported": len(signal_db.signals),
        "path": path,
    }

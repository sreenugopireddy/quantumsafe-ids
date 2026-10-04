"""Parses Zeek TSV log files (ssl.log, conn.log) and joins them by
connection UID into TLSSessionRecord objects.

Zeek log format assumed: classic ASCII TSV with `#fields`/`#types`
header lines (configs/zeek/local.zeek sets `LogAscii::use_json = F`).
If Zeek is later switched to JSON output, this parser needs to change too.

KNOWN LIMITATION: stock Zeek ssl.log does not expose the ClientHello's
offered key-exchange groups or the negotiated key-share length without a
custom Zeek script extension. Until such a script is added to
configs/zeek/local.zeek, every TLSSessionRecord produced here has
offered_groups=[] and key_share_length=None - meaning rule engine checks
R03 (group not offered) and R05 (malformed key-share length) can never
trigger on real parsed data. This is a known, documented gap, not a bug.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from src.utils.schemas import TLSSessionRecord

logger = logging.getLogger(__name__)

_UNSET = "-"
_EMPTY = "(empty)"


@dataclass
class ZeekLogFile:
    """Parsed representation of one Zeek TSV log file."""

    path: Path
    fields: list[str]
    types: list[str]
    rows: list[dict[str, Any]] = field(default_factory=list)


def _coerce_value(raw: str, zeek_type: str) -> Any:
    """Convert a raw TSV cell to a Python value based on its Zeek type."""
    if raw == _UNSET:
        return None
    if raw == _EMPTY:
        return ""

    if zeek_type in ("time", "interval", "double"):
        try:
            return float(raw)
        except ValueError:
            return None
    if zeek_type in ("count", "int", "port"):
        try:
            return int(float(raw))
        except ValueError:
            return None
    if zeek_type == "bool":
        return raw == "T"
    # addr, string, enum, and anything else: pass through as-is
    return raw


def parse_zeek_tsv(path: str | Path) -> ZeekLogFile:
    """Parse a single Zeek TSV log file (ssl.log or conn.log) into rows
    keyed by field name, with values type-coerced per the #types header.

    Raises:
        FileNotFoundError: if `path` does not exist.
        ValueError: if a data row appears before the #fields/#types header.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Zeek log file not found: {path}")

    fields: list[str] = []
    types: list[str] = []
    rows: list[dict[str, Any]] = []
    separator = "\t"

    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#separator"):
                parts = line.split(None, 1)
                raw_sep = parts[1] if len(parts) > 1 else "\\x09"
                separator = "\t" if raw_sep.strip() == "\\x09" else raw_sep.strip()
                continue
            if line.startswith("#fields"):
                fields = line.split(separator)[1:]
                continue
            if line.startswith("#types"):
                types = line.split(separator)[1:]
                continue
            if line.startswith("#"):
                continue  # #open, #close, #set_separator, #path, etc.

            if not fields or not types:
                raise ValueError(f"{path}: encountered a data row before #fields/#types header")

            cells = line.split(separator)
            if len(cells) != len(fields):
                logger.warning(
                    "%s: row has %d cells but header declares %d fields; skipping row",
                    path, len(cells), len(fields),
                )
                continue

            row = {
                name: _coerce_value(cell, zeek_type)
                for name, zeek_type, cell in zip(fields, types, cells)
            }
            rows.append(row)

    return ZeekLogFile(path=path, fields=fields, types=types, rows=rows)


def _ts_to_datetime(ts: Optional[float]) -> datetime:
    if ts is None:
        return datetime.now(timezone.utc)
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def build_session_records(ssl_log_path: str | Path, conn_log_path: str | Path) -> list[TLSSessionRecord]:
    """Join ssl.log and conn.log by connection uid and produce one
    TLSSessionRecord per ssl.log row. conn.log rows with no matching
    ssl.log entry (e.g. non-TLS connections) are ignored - this parser
    only builds TLS session records.
    """
    ssl_log = parse_zeek_tsv(ssl_log_path)
    conn_log = parse_zeek_tsv(conn_log_path)

    conn_by_uid: dict[str, dict[str, Any]] = {
        row["uid"]: row for row in conn_log.rows if row.get("uid")
    }

    sessions: list[TLSSessionRecord] = []
    unmatched_count = 0

    for ssl_row in ssl_log.rows:
        uid = ssl_row.get("uid")
        if not uid:
            logger.warning("%s: ssl.log row missing uid, skipping", ssl_log_path)
            continue

        conn_row = conn_by_uid.get(uid)
        if conn_row is None:
            unmatched_count += 1

        extra: dict[str, Any] = {}
        flow_duration_ms: Optional[float] = None
        if conn_row is not None:
            duration = conn_row.get("duration")
            flow_duration_ms = duration * 1000.0 if duration is not None else None
            extra["flow_duration_ms"] = flow_duration_ms

            orig_pkts = conn_row.get("orig_pkts")
            resp_pkts = conn_row.get("resp_pkts")
            extra["client_packets"] = orig_pkts
            extra["server_packets"] = resp_pkts
            if orig_pkts is not None and resp_pkts is not None:
                extra["total_packets"] = orig_pkts + resp_pkts

            orig_bytes = conn_row.get("orig_bytes")
            resp_bytes = conn_row.get("resp_bytes")
            extra["client_bytes"] = orig_bytes
            extra["server_bytes"] = resp_bytes
            if orig_bytes is not None and resp_bytes is not None:
                extra["total_bytes"] = orig_bytes + resp_bytes

            extra["cipher_suite"] = ssl_row.get("cipher")
            extra["destination_port"] = conn_row.get("id.resp_p")

        established = ssl_row.get("established")
        failed = established is False  # explicit False only; None/missing != failed

        session = TLSSessionRecord(
            session_id=uid,
            timestamp=_ts_to_datetime(ssl_row.get("ts")),
            source_ip=ssl_row.get("id.orig_h") or "0.0.0.0",
            destination_ip=ssl_row.get("id.resp_h") or "0.0.0.0",
            destination_service=ssl_row.get("server_name") or ssl_row.get("id.resp_h") or "unknown",
            tls_version=ssl_row.get("version") or "UNKNOWN",
            offered_groups=[],       # KNOWN LIMITATION - see module docstring
            selected_group=ssl_row.get("curve"),
            key_share_length=None,   # KNOWN LIMITATION - see module docstring
            handshake_duration_ms=flow_duration_ms,
            failed=failed,
            extra=extra,
        )
        sessions.append(session)

    if unmatched_count:
        logger.info(
            "%s: %d/%d ssl.log session(s) had no matching conn.log entry (flow features absent for those)",
            ssl_log_path, unmatched_count, len(ssl_log.rows),
        )

    logger.info("Built %d TLSSessionRecord(s) from %s + %s", len(sessions), ssl_log_path, conn_log_path)
    return sessions
    


def find_zeek_log_pairs(zeek_log_dir: str | Path) -> list[tuple[Path, Path]]:
    """Find (ssl.log, conn.log) pairs across all subdirectories under
    zeek_log_dir (one subdirectory per processed pcap, per
    docker/zeek/watch_and_process.sh). Shared by scripts/demo_parse_zeek.py
    and scripts/label_sessions.py so both use identical directory-walking
    logic.
    """
    zeek_log_dir = Path(zeek_log_dir)
    pairs: list[tuple[Path, Path]] = []
    if not zeek_log_dir.exists():
        return pairs
    for subdir in sorted(p for p in zeek_log_dir.iterdir() if p.is_dir()):
        ssl_log = subdir / "ssl.log"
        conn_log = subdir / "conn.log"
        if ssl_log.exists() and conn_log.exists():
            pairs.append((ssl_log, conn_log))
        else:
            logger.warning("%s: missing ssl.log or conn.log, skipping", subdir)
    return pairs
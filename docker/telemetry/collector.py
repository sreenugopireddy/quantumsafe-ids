"""Polls Docker stats for the TLS server containers (Feature Category D)."""
from __future__ import annotations

import csv
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import docker

TARGETS = [t.strip() for t in os.environ.get(
    "TELEMETRY_TARGETS", "tls-classical,tls-pqc"
).split(",") if t.strip()]
INTERVAL = float(os.environ.get("TELEMETRY_INTERVAL_SECONDS", "5"))
OUT_DIR = Path(os.environ.get("TELEMETRY_OUT_DIR", "/telemetry"))
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = OUT_DIR / "endpoint_telemetry.csv"
FIELDS = ["timestamp", "container", "cpu_percent", "mem_usage_bytes", "mem_limit_bytes", "mem_percent"]


def cpu_percent(stats: dict) -> float:
    try:
        cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - stats["precpu_stats"]["cpu_usage"]["total_usage"]
        sys_delta = stats["cpu_stats"]["system_cpu_usage"] - stats["precpu_stats"]["system_cpu_usage"]
        n_cpus = stats["cpu_stats"].get("online_cpus") or len(stats["cpu_stats"]["cpu_usage"].get("percpu_usage", [1]))
        if sys_delta > 0 and cpu_delta > 0:
            return (cpu_delta / sys_delta) * n_cpus * 100.0
    except (KeyError, ZeroDivisionError, TypeError):
        pass
    return 0.0


def main() -> None:
    client = docker.from_env()
    new_file = not OUT_FILE.exists()
    with OUT_FILE.open("a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        if new_file:
            writer.writeheader()
            fh.flush()
        print(f"[telemetry] polling {TARGETS} every {INTERVAL}s -> {OUT_FILE}")
        while True:
            for name in TARGETS:
                try:
                    container = client.containers.get(name)
                    stats = container.stats(stream=False)
                    mem_usage = stats["memory_stats"].get("usage", 0)
                    mem_limit = stats["memory_stats"].get("limit", 1)
                    writer.writerow({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "container": name,
                        "cpu_percent": round(cpu_percent(stats), 3),
                        "mem_usage_bytes": mem_usage,
                        "mem_limit_bytes": mem_limit,
                        "mem_percent": round(100.0 * mem_usage / max(mem_limit, 1), 3),
                    })
                except docker.errors.NotFound:
                    print(f"[telemetry] WARNING: container '{name}' not found yet")
                except Exception as exc:  # noqa: BLE001
                    print(f"[telemetry] ERROR polling '{name}': {exc}")
            fh.flush()
            time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
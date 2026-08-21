from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
import threading
import time
from pathlib import Path
from collections.abc import Callable
from typing import Any, Dict


class EventRecorder:
    def __init__(self, path: Path, *, max_bytes: int = 10 * 1024 * 1024, backup_count: int = 3) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._listeners: list[Callable[[dict[str, Any]], None]] = []

    def subscribe(self, listener: Callable[[dict[str, Any]], None]) -> None:
        """Receive a redacted copy of future events after durable append."""
        self._listeners.append(listener)

    def write(self, event_type: str, **fields: Any) -> None:
        payload: Dict[str, Any] = {
            "ts": time.time(),
            "event_type": event_type,
            **fields,
        }
        line = json.dumps(payload, ensure_ascii=False)
        with self._lock:
            if self.path.exists() and self.path.stat().st_size + len(line.encode("utf-8")) + 1 > self.max_bytes:
                if self.backup_count <= 0:
                    self.path.write_text("", encoding="utf-8")
                else:
                    oldest = self.path.with_name(f"{self.path.name}.{self.backup_count}")
                    if oldest.exists():
                        oldest.unlink()
                    for index in range(self.backup_count - 1, 0, -1):
                        source = self.path.with_name(f"{self.path.name}.{index}")
                        if source.exists():
                            source.replace(self.path.with_name(f"{self.path.name}.{index + 1}"))
                    self.path.replace(self.path.with_name(f"{self.path.name}.1"))
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        for listener in tuple(self._listeners):
            try:
                listener(dict(payload))
            except Exception:
                # Event recording must never fail because a notification sink is down.
                logging.getLogger("webui-home-gateway").exception(
                    "Event subscriber failed for %s", event_type
                )


def setup_logger(
    log_dir: Path,
    *,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 3,
) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("webui-home-gateway")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    file_handler = RotatingFileHandler(
        log_dir / "gateway.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger

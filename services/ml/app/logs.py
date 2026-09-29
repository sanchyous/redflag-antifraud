"""Структурированное логирование ML-сервиса — в том же стиле, что и у Go-ядра.

События — короткие идентификаторы в snake_case (`model_loaded`), всё переменное — в полях. Формат:
  json   — одна строка JSON на событие (продакшен, сбор логов);
  pretty — время, уровень, компонент, событие и поля key=value (консоль, разработка).
Запросы к /v1/score на успешном пути пишутся на уровне debug (иначе поток из тысяч вызовов утопит логи),
ошибки и медленные запросы — на info/warning.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime

COMPONENT = "ml"
_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime", "fields"}


def _fields(record: logging.LogRecord) -> dict:
    return dict(getattr(record, "fields", {}) or {})


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {
            "time": datetime.fromtimestamp(record.created).astimezone().isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "component": COMPONENT,
            "msg": record.getMessage(),
            **_fields(record),
        }
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, ensure_ascii=False, default=str)


class PrettyFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\x1b[90m",
        "INFO": "\x1b[32m",
        "WARNING": "\x1b[33m",
        "ERROR": "\x1b[31m",
        "CRITICAL": "\x1b[31m",
    }

    def __init__(self, color: bool):
        super().__init__()
        self.color = color

    @staticmethod
    def _value(v) -> str:
        s = json.dumps(v, ensure_ascii=False, default=str) if not isinstance(v, str) else v
        return json.dumps(s, ensure_ascii=False) if (not s or any(c in s for c in ' \t\n"=')) else s

    def format(self, record: logging.LogRecord) -> str:
        t = datetime.fromtimestamp(record.created).strftime("%H:%M:%S.") + f"{int(record.msecs):03d}"
        lvl = f"{record.levelname:<5}"[:5]
        if self.color:
            t, lvl = f"\x1b[2m{t}\x1b[0m", f"{self.COLORS.get(record.levelname, '')}{lvl}\x1b[0m"
        comp = f"{COMPONENT:<10}"
        if self.color:
            comp = f"\x1b[36m{comp}\x1b[0m"
        kv = " ".join(f"{k}={self._value(v)}" for k, v in _fields(record).items())
        line = f"{t} {lvl} {comp} {record.getMessage()}" + (f" {kv}" if kv else "")
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def setup_logging(level: str | None = None, fmt: str | None = None) -> logging.Logger:
    """Настраивает корневой логгер. fmt: json | pretty (по умолчанию pretty на терминале, иначе json)."""
    level = (level or os.environ.get("LOG_LEVEL", "info")).upper()
    fmt = (fmt or os.environ.get("LOG_FORMAT", "")).lower()
    tty = sys.stdout.isatty()
    if fmt not in ("json", "pretty"):
        fmt = "pretty" if tty else "json"
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(PrettyFormatter(color=tty) if fmt == "pretty" else JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(getattr(logging, level, logging.INFO))
    for noisy in ("uvicorn.access",):
        logging.getLogger(noisy).disabled = True  # доступ логируем сами, с полями и уровнями
    return logging.getLogger("ml-service")


def event(logger: logging.Logger, level: int, name: str, **fields) -> None:
    """Пишет событие: имя — сообщение, поля — структурой."""
    if logger.isEnabledFor(level):
        logger.log(level, name, extra={"fields": fields})

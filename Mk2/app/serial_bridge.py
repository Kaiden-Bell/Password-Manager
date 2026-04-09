"""
app.serial_bridge
─────────────────
Listens on the configured serial port for RFID UIDs
sent by the Arduino scanner.

The Arduino prints lines like::

    Card UID:A1 B2 C3 D4

This module parses those lines and pushes the UID string
into a thread-safe queue for consumption by the API layer.
"""

from __future__ import annotations

import logging
import queue
import re
import threading
from typing import Optional

import serial

logger = logging.getLogger(__name__)

# Regex to capture UID from "Card UID:XX XX XX XX"
_UID_PATTERN = re.compile(r"Card UID:\s*(.+)$", re.IGNORECASE)


class SerialBridge:
    """
    Background thread that reads RFID UIDs from an Arduino over serial.

    Usage::

        bridge = SerialBridge(port="/dev/ttyUSB0", baud=115200)
        bridge.start()
        uid = bridge.get_uid(timeout=30)  # blocks until a card is scanned
        bridge.stop()
    """

    def __init__(self, port: str, baud: int = 115200) -> None:
        self.port = port
        self.baud = baud
        self._queue: queue.Queue[str] = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._serial: Optional[serial.Serial] = None

    # ── Public API ────────────────────────────────

    def start(self) -> None:
        """Open the serial port and begin listening in a daemon thread."""
        if self._running:
            logger.warning("SerialBridge is already running.")
            return

        self._serial = serial.Serial(self.port, self.baud, timeout=1)
        self._running = True
        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()
        logger.info("SerialBridge started on %s @ %d baud", self.port, self.baud)

    def stop(self) -> None:
        """Signal the listener thread to stop and close the port."""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=3)
        if self._serial is not None and self._serial.is_open:
            self._serial.close()
        logger.info("SerialBridge stopped.")

    def get_uid(self, timeout: float | None = None) -> str | None:
        """
        Block until an RFID UID is available, or *timeout* seconds elapse.

        Returns the UID string (e.g. ``"A1 B2 C3 D4"``) or ``None`` on timeout.
        """
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Internal ──────────────────────────────────

    def _listen(self) -> None:
        """Read lines from serial, parse UIDs, push to queue."""
        while self._running:
            try:
                if self._serial is None or not self._serial.is_open:
                    break

                raw = self._serial.readline()
                if not raw:
                    continue

                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue

                match = _UID_PATTERN.search(line)
                if match:
                    uid = match.group(1).strip()
                    logger.debug("RFID UID received: %s", uid)
                    self._queue.put(uid)

            except serial.SerialException as exc:
                logger.error("Serial error: %s", exc)
                self._running = False
            except Exception as exc:
                logger.exception("Unexpected error in serial listener: %s", exc)

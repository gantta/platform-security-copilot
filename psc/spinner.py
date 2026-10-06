import itertools
import sys
import threading
from types import TracebackType
from typing import TextIO


class Spinner:
    """CLI activity indicator for work that blocks until a response arrives."""

    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(
        self,
        message: str = "Working",
        stream: TextIO | None = None,
        interval: float = 0.1,
    ) -> None:
        self.message = message
        self.stream: TextIO = stream if stream is not None else sys.stderr
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "Spinner":
        if not self.stream.isatty():
            self.stream.write(f"{self.message}...\n")
            self.stream.flush()
            return self
        self.stream.write(f"\r{self.FRAMES[0]} {self.message}")
        self.stream.flush()
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._thread is None:
            return
        self._stop.set()
        self._thread.join()

    def _animate(self) -> None:
        frames = itertools.cycle(self.FRAMES)
        next(frames)
        while not self._stop.wait(self.interval):
            self.stream.write(f"\r{next(frames)} {self.message}")
            self.stream.flush()
        self.stream.write("\r" + " " * (len(self.message) + 2) + "\r")
        self.stream.flush()

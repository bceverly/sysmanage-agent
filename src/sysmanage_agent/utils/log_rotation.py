"""Timed log rotation with gzip compression of the rotated files."""

import gzip
import os
import shutil
from logging.handlers import TimedRotatingFileHandler


class GzipTimedRotatingFileHandler(TimedRotatingFileHandler):
    """``TimedRotatingFileHandler`` that gzip-compresses each rotated file.

    Standard unix-style rotation: at the rollover boundary the current log is
    renamed with a date suffix, compressed to ``.gz``, and a fresh log is
    started.  ``backupCount`` archives are kept; older ones are deleted.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.namer = self._gz_namer
        self.rotator = self._gz_rotator

    @staticmethod
    def _gz_namer(default_name: str) -> str:
        return default_name + ".gz"

    @staticmethod
    def _gz_rotator(source: str, dest: str) -> None:
        with open(source, "rb") as src, gzip.open(dest, "wb") as dst:
            shutil.copyfileobj(src, dst)
        os.remove(source)

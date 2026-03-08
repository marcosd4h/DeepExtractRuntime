"""Centralized logging configuration for the DeepExtractIDA runtime.

Provides a pre-configured logger hierarchy under the ``helpers`` namespace.
All helper modules should use ``_log = logging.getLogger(__name__)`` to get
a module-scoped logger that inherits this configuration.

The structured JSON error protocol (``emit_error``, ``log_warning``,
``log_error``) remains the primary agent-facing output mechanism.
Python logging is for **human debugging** -- cache hit/miss tracing,
DB query timing, module resolution diagnostics, etc.

Configuration is controlled by the ``DEEPEXTRACT_LOG_LEVEL`` environment
variable (default ``WARNING``).  Set to ``DEBUG`` for full tracing.
"""

from __future__ import annotations

import logging
import os
import sys


def configure_logging() -> None:
    """Set up the ``helpers`` logger hierarchy with a stderr handler.

    Safe to call multiple times; only attaches one handler.
    """
    root_logger = logging.getLogger("helpers")
    if root_logger.handlers:
        return

    level_name = os.environ.get("DEEPEXTRACT_LOG_LEVEL", "WARNING").upper()
    level = getattr(logging, level_name, logging.WARNING)
    root_logger.setLevel(level)

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    formatter = logging.Formatter(
        "[%(levelname)s] %(name)s: %(message)s"
    )
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)


configure_logging()

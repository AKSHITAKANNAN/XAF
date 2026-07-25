"""
logger.py (Module 2)
---------------------
Provides a single, consistent logging setup for every class in the
Feature Extraction Engine.

WHY THIS FILE EXISTS
Keeping logger configuration in one place avoids duplicated
`logging.basicConfig(...)` calls scattered across files (which can silently
clobber each other's formatting) and keeps Module 2 fully decoupled from
Module 1's own logger helper in utils.py -- the two modules must be usable
independently.

USED BY
- flow_builder.py
- session_manager.py
- feature_extractor.py
- examples/run_feature_extraction.py
"""

import logging


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Create or retrieve a configured logger for a Module 2 component.

    Args:
        name: Logger name, conventionally the dotted module path
            (e.g. "module2_feature_extraction.flow_builder").
        level: Logging verbosity (e.g. logging.DEBUG, logging.INFO).

    Returns:
        A logging.Logger instance with a single stream handler attached
        (guards against duplicate handlers if called multiple times).
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        # Prevent double-logging if the root logger also has handlers
        # configured elsewhere in the larger XAF application.
        logger.propagate = False

    logger.setLevel(level)
    return logger

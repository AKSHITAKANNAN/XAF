"""
logger.py (Module 3)
-----------------------
Provides a single, consistent logging setup for every class in the AI
Threat Detection Engine.

WHY THIS FILE EXISTS
Keeping logger configuration in one place avoids duplicated
`logging.basicConfig(...)` calls scattered across files, and keeps
Module 3 fully decoupled from Module 1's and Module 2's own logger
helpers -- every module in the XAF project must remain independently
usable and testable.

USED BY
- detector.py
- model_loader.py
- trainer.py
- preprocessor.py
- feature_mapper.py
- inference.py
- run_detection.py
"""

import logging


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Create or retrieve a configured logger for a Module 3 component.

    Args:
        name: Logger name, conventionally the dotted module path
            (e.g. "module3_ai_detection.inference").
        level: Logging verbosity (e.g. logging.DEBUG, logging.INFO).

    Returns:
        A logging.Logger instance with a single stream handler attached
        (guards against duplicate handlers if this is called more than
        once for the same logger name).
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

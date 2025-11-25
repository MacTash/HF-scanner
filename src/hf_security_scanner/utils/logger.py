"""
Logger utility for HF Security Scanner.
Provides colorized logging with rich formatting.
"""

import logging
import sys
from typing import Optional
from rich.logging import RichHandler
from rich.console import Console

console = Console()

# Log levels
DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL


def setup_logger(name: str = "hf_security_scanner", level: int = INFO) -> logging.Logger:
    """
    Set up a logger with rich formatting.
    
    Args:
        name: Logger name
        level: Logging level
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Create rich handler
    handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        markup=True,
        show_time=True,
        show_path=False
    )
    handler.setLevel(level)
    
    # Set format
    formatter = logging.Formatter(
        "%(message)s",
        datefmt="[%X]"
    )
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    logger.propagate = False
    
    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name (optional)
        
    Returns:
        Logger instance
    """
    if name is None:
        name = "hf_security_scanner"
    
    logger = logging.getLogger(name)
    
    # If logger has no handlers, set it up
    if not logger.handlers:
        return setup_logger(name)
    
    return logger


def set_log_level(level: int):
    """
    Set the log level for all loggers.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    logger = logging.getLogger("hf_security_scanner")
    logger.setLevel(level)
    for handler in logger.handlers:
        handler.setLevel(level)

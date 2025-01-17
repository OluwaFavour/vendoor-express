import logging
from logging.handlers import RotatingFileHandler


# Configure the logger
def setup_logger(name: str, log_file: str, level: int = logging.INFO) -> logging.Logger:
    """
    Sets up a logger with a specified name, log file, and logging level.
    This function configures a logger to write log messages to both a rotating file
    and the console. The log messages will include the timestamp, logger name,
    log level, and message.
    Args:
        name (str): The name of the logger.
        log_file (str): The file path where the log messages will be written.
        level (int, optional): The logging level (e.g., logging.INFO, logging.DEBUG). Defaults to logging.INFO.
    Returns:
        logging.Logger: The configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # File handler (with rotation)
    file_handler = RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    file_handler.setLevel(level)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)

    # Define the log format
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

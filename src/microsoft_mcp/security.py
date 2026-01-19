"""Security utilities for path validation."""

import re
from pathlib import Path

# Directories blocked from reading (contain secrets/credentials)
BLOCKED_READ_DIRS = (
    ".ssh",
    ".aws",
    ".gnupg",
    ".config/gcloud",
    ".kube",
    ".docker",
    ".password-store",  # pass password manager
)

# Files blocked from reading (credentials/secrets)
BLOCKED_READ_FILES = (
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".bash_history",
    ".zsh_history",
    ".python_history",
    ".node_repl_history",
    ".psql_history",
    ".mysql_history",
    ".rediscli_history",
)

# System files blocked from reading
BLOCKED_SYSTEM_FILES = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
)

# Extensions that indicate key/certificate files
BLOCKED_READ_EXTENSIONS = (".pem", ".key", ".p12", ".pfx")

# Patterns in filenames that indicate secrets (case-insensitive)
BLOCKED_NAME_PATTERNS = re.compile(
    r"(credentials|secret|token|password)", re.IGNORECASE
)

# Pattern for .env files (.env, .env.local, .env.production, etc.)
ENV_FILE_PATTERN = re.compile(r"^\.env(\..+)?$", re.IGNORECASE)

# Directories blocked from writing (shell configs, auth, persistence)
BLOCKED_WRITE_DIRS = (
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".config/systemd",
    "Library/LaunchAgents",  # macOS persistence
    ".config/autostart",  # Linux autostart
)

# Files blocked from writing (shell configs, cron)
BLOCKED_WRITE_FILES = (
    ".bashrc",
    ".zshrc",
    ".profile",
    ".bash_profile",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".bash_login",
    ".login",
    "authorized_keys",
    "known_hosts",
    "crontab",
)


def _is_path_under_dir(path: Path, blocked_dir: str) -> bool:
    """Check if path is under a blocked directory (case-insensitive for macOS/Windows)."""
    home = Path.home()
    blocked_path = home / blocked_dir
    # Case-insensitive comparison for macOS/Windows filesystems
    path_lower = str(path).lower()
    blocked_lower = str(blocked_path).lower()
    return path_lower.startswith(blocked_lower + "/") or path_lower == blocked_lower


def _check_traversal(file_path: str) -> None:
    """Raise if path contains traversal sequences."""
    if ".." in file_path:
        raise ValueError("Path traversal not allowed")


def validate_read_path(file_path: str) -> Path:
    """Validate that a file path is safe to read.

    Blocks access to sensitive files like SSH keys, AWS credentials,
    environment files, and other secrets.

    Args:
        file_path: Path to validate

    Returns:
        Resolved Path object if valid

    Raises:
        ValueError: If path is blocked for security reasons
    """
    _check_traversal(file_path)

    path = Path(file_path).expanduser().resolve()
    home = Path.home()

    # Check system files (handle macOS /private/etc symlink)
    path_str = str(path)
    for blocked in BLOCKED_SYSTEM_FILES:
        # Also check /private/etc for macOS
        blocked_variants = [blocked, f"/private{blocked}"]
        for variant in blocked_variants:
            if path_str == variant or path_str.startswith(variant + "/"):
                raise ValueError("Access to system files not allowed")

    # Check blocked directories
    for blocked_dir in BLOCKED_READ_DIRS:
        if _is_path_under_dir(path, blocked_dir):
            raise ValueError("Access to sensitive directory not allowed")

    # Check blocked files in home directory
    for blocked_file in BLOCKED_READ_FILES:
        blocked_path = home / blocked_file
        if path == blocked_path:
            raise ValueError("Access to sensitive file not allowed")
        # Also check if the filename matches anywhere
        if path.name == blocked_file:
            raise ValueError("Access to sensitive file not allowed")

    # Check for token cache file anywhere (case-insensitive)
    if "microsoft_mcp_token_cache" in path.name.lower():
        raise ValueError("Access to token cache not allowed")

    # Check blocked extensions
    if path.suffix.lower() in BLOCKED_READ_EXTENSIONS:
        raise ValueError("Access to key/certificate files not allowed")

    # Check .env files
    if ENV_FILE_PATTERN.match(path.name):
        raise ValueError("Access to environment files not allowed")

    # Check for sensitive name patterns
    if BLOCKED_NAME_PATTERNS.search(path.name):
        raise ValueError("Access to files with sensitive names not allowed")

    return path


def validate_write_path(file_path: str) -> Path:
    """Validate that a file path is safe to write to.

    Blocks writes to dangerous locations like shell configs,
    SSH authorized_keys, and system directories.

    Args:
        file_path: Path to validate

    Returns:
        Resolved Path object if valid

    Raises:
        ValueError: If path is blocked for security reasons
    """
    _check_traversal(file_path)

    path = Path(file_path).expanduser().resolve()
    home = Path.home()

    # Check blocked directories
    for blocked_dir in BLOCKED_WRITE_DIRS:
        if _is_path_under_dir(path, blocked_dir):
            raise ValueError("Write to sensitive directory not allowed")

    # Check blocked files in home directory
    for blocked_file in BLOCKED_WRITE_FILES:
        blocked_path = home / blocked_file
        if path == blocked_path:
            raise ValueError("Write to sensitive file not allowed")
        # Also check if the filename matches anywhere
        if path.name == blocked_file:
            raise ValueError("Write to sensitive file not allowed")

    return path

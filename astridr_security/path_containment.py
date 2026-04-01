"""Path containment — prevents directory traversal and zip-bomb attacks.

Validates that file paths stay within designated roots (skills, hooks,
plugins).  Also validates archives before extraction.
"""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

import structlog

logger = structlog.get_logger()


# ─── Errors ──────────────────────────────────────────────────────


class SecurityError(Exception):
    """Raised when a path escapes its designated root."""


class ArchiveValidationError(SecurityError):
    """Raised when an archive fails safety checks."""


# ─── Root directories ────────────────────────────────────────────

SKILLS_ROOT = Path("~/.astridr/skills").expanduser().resolve()
HOOKS_ROOT = Path("~/.astridr/hooks").expanduser().resolve()
PLUGINS_ROOT = Path("~/.astridr/plugins").expanduser().resolve()


# ─── Path validation ─────────────────────────────────────────────


def validate_path(path: str | Path, root: Path) -> Path:
    """Ensure *path* is within the given *root*.

    Resolves symlinks and normalises the path before checking.
    Raises :class:`SecurityError` if the path escapes the root.
    """
    resolved = Path(path).resolve()
    root_resolved = root.resolve()

    if not resolved.is_relative_to(root_resolved):
        raise SecurityError(f"Path escapes root {root_resolved}: {path}")

    return resolved


def validate_skill_path(path: str | Path) -> Path:
    """Validate that *path* is within the skills root."""
    return validate_path(path, SKILLS_ROOT)


def validate_hook_path(path: str | Path) -> Path:
    """Validate that *path* is within the hooks root."""
    return validate_path(path, HOOKS_ROOT)


def validate_plugin_path(path: str | Path) -> Path:
    """Validate that *path* is within the plugins root."""
    return validate_path(path, PLUGINS_ROOT)


# ─── Archive validation ──────────────────────────────────────────

_DEFAULT_MAX_ENTRIES = 1000
_DEFAULT_MAX_TOTAL_BYTES = 100_000_000  # 100 MB


def validate_archive(
    archive_path: Path,
    max_entries: int = _DEFAULT_MAX_ENTRIES,
    max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES,
) -> None:
    """Validate an archive before extraction.

    Checks for:
    * Zip bombs (too many entries or total uncompressed size)
    * Path traversal entries (``..`` in member names)
    * Absolute paths in members
    * Symlink escapes

    Supports ``.zip`` and ``.tar*`` formats.

    Raises :class:`ArchiveValidationError` on any violation.
    """
    archive_path = Path(archive_path)
    suffix = archive_path.suffix.lower()

    if suffix == ".zip":
        _validate_zip(archive_path, max_entries, max_total_bytes)
    elif suffix in (".tar", ".gz", ".tgz", ".bz2", ".xz"):
        _validate_tar(archive_path, max_entries, max_total_bytes)
    else:
        raise ArchiveValidationError(f"Unsupported archive format: {suffix}")


def _validate_zip(
    archive_path: Path,
    max_entries: int,
    max_total_bytes: int,
) -> None:
    """Validate a ZIP archive."""
    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            members = zf.infolist()

            # Entry count check
            if len(members) > max_entries:
                raise ArchiveValidationError(
                    f"Too many entries: {len(members)} > {max_entries}"
                )

            total_size = 0
            for member in members:
                # Path traversal check
                if ".." in member.filename or member.filename.startswith("/"):
                    raise ArchiveValidationError(
                        f"Unsafe path in archive: {member.filename}"
                    )

                # Check for absolute paths (Windows style)
                if len(member.filename) >= 2 and member.filename[1] == ":":
                    raise ArchiveValidationError(
                        f"Absolute path in archive: {member.filename}"
                    )

                # Accumulate size
                total_size += member.file_size
                if total_size > max_total_bytes:
                    raise ArchiveValidationError(
                        f"Total uncompressed size exceeds limit: {total_size} > {max_total_bytes}"
                    )
    except zipfile.BadZipFile as exc:
        raise ArchiveValidationError(f"Invalid ZIP file: {exc}") from exc


def _validate_tar(
    archive_path: Path,
    max_entries: int,
    max_total_bytes: int,
) -> None:
    """Validate a TAR archive."""
    try:
        with tarfile.open(archive_path, "r:*") as tf:
            members = tf.getmembers()

            # Entry count check
            if len(members) > max_entries:
                raise ArchiveValidationError(
                    f"Too many entries: {len(members)} > {max_entries}"
                )

            total_size = 0
            for member in members:
                # Path traversal check
                if ".." in member.name or member.name.startswith("/"):
                    raise ArchiveValidationError(
                        f"Unsafe path in archive: {member.name}"
                    )

                # Symlink escape check
                if member.issym() or member.islnk():
                    link_target = member.linkname
                    if ".." in link_target or link_target.startswith("/"):
                        raise ArchiveValidationError(
                            f"Symlink escape in archive: {member.name} -> {link_target}"
                        )

                # Accumulate size
                total_size += member.size
                if total_size > max_total_bytes:
                    raise ArchiveValidationError(
                        f"Total uncompressed size exceeds limit: {total_size} > {max_total_bytes}"
                    )
    except tarfile.TarError as exc:
        raise ArchiveValidationError(f"Invalid TAR file: {exc}") from exc

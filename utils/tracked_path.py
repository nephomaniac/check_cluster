"""
Tracked Path - A Path wrapper that tracks file access for test reporting.

This module provides a Path-like object that automatically tracks file operations
(existence checks, glob patterns, file opens) and registers them with ClusterData
for per-test file tracking in HTML reports.
"""

from pathlib import Path
from typing import TYPE_CHECKING, Iterator, Union

if TYPE_CHECKING:
    from models.cluster import ClusterData


class TrackedPath:
    """
    A Path wrapper that tracks file operations.

    When tests use cluster_data.data_dir to construct paths, check existence,
    or glob for files, those operations are automatically tracked and will
    appear in the test's Sources section in the HTML report.
    """

    def __init__(self, path: Path, cluster_data: 'ClusterData'):
        """
        Initialize tracked path.

        Args:
            path: The underlying pathlib.Path object
            cluster_data: ClusterData instance to track file access
        """
        self._path = Path(path)
        self._cluster_data = cluster_data

    def __truediv__(self, other: Union[str, Path]) -> 'TrackedPath':
        """
        Path joining with / operator - returns a new TrackedPath.

        Example: cluster_data.data_dir / "file.json"
        """
        new_path = self._path / other
        return TrackedPath(new_path, self._cluster_data)

    def __str__(self) -> str:
        """String representation returns the path string."""
        return str(self._path)

    def __repr__(self) -> str:
        """Repr returns TrackedPath representation."""
        return f"TrackedPath({self._path!r})"

    def __fspath__(self) -> str:
        """Return file system path for os.fspath() compatibility."""
        return str(self._path)

    @property
    def name(self) -> str:
        """File name (e.g., 'file.json')."""
        return self._path.name

    @property
    def stem(self) -> str:
        """File name without suffix (e.g., 'file' from 'file.json')."""
        return self._path.stem

    @property
    def suffix(self) -> str:
        """File extension (e.g., '.json')."""
        return self._path.suffix

    @property
    def parent(self) -> 'TrackedPath':
        """Parent directory as TrackedPath."""
        return TrackedPath(self._path.parent, self._cluster_data)

    def exists(self) -> bool:
        """
        Check if path exists and track this file access.

        Returns:
            True if file exists, False otherwise
        """
        result = self._path.exists()
        if result:
            # File exists, track it
            self._cluster_data._track_direct_file_access(self._path)
        return result

    def is_file(self) -> bool:
        """Check if path is a file."""
        result = self._path.is_file()
        if result:
            self._cluster_data._track_direct_file_access(self._path)
        return result

    def is_dir(self) -> bool:
        """Check if path is a directory."""
        return self._path.is_dir()

    def glob(self, pattern: str) -> Iterator['TrackedPath']:
        """
        Glob for files matching pattern and track all found files.

        Args:
            pattern: Glob pattern (e.g., "*.json")

        Yields:
            TrackedPath objects for matching files
        """
        for path in self._path.glob(pattern):
            # Track each file found by glob
            if path.is_file():
                self._cluster_data._track_direct_file_access(path)
            # Yield as TrackedPath to maintain tracking chain
            yield TrackedPath(path, self._cluster_data)

    def open(self, mode='r', **kwargs):
        """
        Open the file and track this access.

        Args:
            mode: File open mode (default 'r')
            **kwargs: Additional arguments passed to open()

        Returns:
            File object
        """
        # Track file access when opened
        if 'r' in mode and self._path.exists():
            self._cluster_data._track_direct_file_access(self._path)

        # Return the actual file object
        return self._path.open(mode, **kwargs)

    def read_text(self, **kwargs) -> str:
        """Read file as text and track access."""
        if self._path.exists():
            self._cluster_data._track_direct_file_access(self._path)
        return self._path.read_text(**kwargs)

    def read_bytes(self) -> bytes:
        """Read file as bytes and track access."""
        if self._path.exists():
            self._cluster_data._track_direct_file_access(self._path)
        return self._path.read_bytes()

    def resolve(self) -> 'TrackedPath':
        """Resolve to absolute path."""
        return TrackedPath(self._path.resolve(), self._cluster_data)

    def absolute(self) -> 'TrackedPath':
        """Return absolute path."""
        return TrackedPath(self._path.absolute(), self._cluster_data)

    def as_posix(self) -> str:
        """Return path with forward slashes."""
        return self._path.as_posix()

    # Allow iteration for compatibility with Path
    def __iter__(self):
        """Iterate over path parts."""
        return iter(self._path.parts)

    # Comparison operators
    def __eq__(self, other) -> bool:
        """Equality comparison."""
        if isinstance(other, TrackedPath):
            return self._path == other._path
        return self._path == other

    def __hash__(self) -> int:
        """Hash for use in sets/dicts."""
        return hash(self._path)

    def __lt__(self, other) -> bool:
        """Less than comparison."""
        if isinstance(other, TrackedPath):
            return self._path < other._path
        return self._path < other

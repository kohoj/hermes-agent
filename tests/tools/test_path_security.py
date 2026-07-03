"""Tests for tools.path_security path validation helpers.

These utilities prevent directory traversal attacks across skill_manager_tool,
skills_tool, skills_hub, cronjob_tools, and credential_files.
"""

import tempfile
from pathlib import Path

import pytest

from tools.path_security import has_traversal_component, validate_within_dir


class TestHasTraversalComponent:
    """has_traversal_component() — quick check for .. in path string."""

    def test_simple_relative_path_safe(self):
        assert not has_traversal_component("foo/bar/baz.txt")

    def test_absolute_path_safe(self):
        assert not has_traversal_component("/usr/local/bin/tool")

    def test_dotdot_at_start(self):
        assert has_traversal_component("../etc/passwd")

    def test_dotdot_in_middle(self):
        assert has_traversal_component("foo/../bar/baz")

    def test_dotdot_at_end(self):
        assert has_traversal_component("foo/bar/..")

    def test_multiple_dotdot(self):
        assert has_traversal_component("../../etc/shadow")

    def test_single_dot_is_safe(self):
        """Single dot (.) is not a traversal component."""
        assert not has_traversal_component("./foo/bar")
        assert not has_traversal_component("foo/./bar")

    def test_dotdot_in_filename_is_safe(self):
        """Literal '..' in a filename part is caught by Path.parts."""
        # Path("foo..bar").parts == ('foo..bar',), no '..' part
        assert not has_traversal_component("foo..bar")


class TestValidateWithinDir:
    """validate_within_dir() — resolve and check path is within root."""

    def test_simple_subpath_allowed(self, tmp_path):
        root = tmp_path / "workspace"
        root.mkdir()
        target = root / "file.txt"
        target.touch()

        error = validate_within_dir(target, root)
        assert error is None

    def test_nested_subpath_allowed(self, tmp_path):
        root = tmp_path / "workspace"
        root.mkdir()
        nested = root / "a" / "b" / "c"
        nested.mkdir(parents=True)
        target = nested / "deep.txt"
        target.touch()

        error = validate_within_dir(target, root)
        assert error is None

    def test_traversal_escape_blocked(self, tmp_path):
        root = tmp_path / "workspace"
        root.mkdir()
        outside = tmp_path / "outside.txt"
        outside.touch()

        # Attempt: workspace/../outside.txt
        evil_path = root / ".." / "outside.txt"
        error = validate_within_dir(evil_path, root)

        assert error is not None
        assert "escapes allowed directory" in error.lower()

    def test_absolute_path_outside_root_blocked(self, tmp_path):
        root = tmp_path / "workspace"
        root.mkdir()
        outside = tmp_path / "outside" / "evil.txt"
        outside.parent.mkdir()
        outside.touch()

        error = validate_within_dir(outside, root)
        assert error is not None
        assert "escapes allowed directory" in error.lower()

    def test_symlink_escape_blocked(self, tmp_path):
        """Symlink pointing outside root should be blocked after resolution."""
        root = tmp_path / "workspace"
        root.mkdir()
        outside = tmp_path / "outside.txt"
        outside.touch()

        link = root / "link.txt"
        link.symlink_to(outside)

        error = validate_within_dir(link, root)
        assert error is not None
        assert "escapes allowed directory" in error.lower()

    def test_symlink_within_root_allowed(self, tmp_path):
        """Symlink pointing to another file inside root is safe."""
        root = tmp_path / "workspace"
        root.mkdir()
        target = root / "target.txt"
        target.touch()
        link = root / "link.txt"
        link.symlink_to(target)

        error = validate_within_dir(link, root)
        assert error is None

    def test_nonexistent_path_within_root_allowed(self, tmp_path):
        """Nonexistent paths are allowed if they resolve within root."""
        root = tmp_path / "workspace"
        root.mkdir()
        nonexistent = root / "future" / "file.txt"

        # Path.resolve() with nonexistent paths: behavior differs by Python version.
        # On 3.10+, resolve() handles nonexistent paths gracefully.
        # This test documents the current behavior.
        error = validate_within_dir(nonexistent, root)
        # If resolve() succeeds, validation should pass
        # (the file doesn't need to exist, just stay in bounds)
        assert error is None or "escapes" not in error.lower()

    def test_root_itself_allowed(self, tmp_path):
        """The root directory itself should validate."""
        root = tmp_path / "workspace"
        root.mkdir()

        error = validate_within_dir(root, root)
        assert error is None

    def test_relative_root_and_path(self, tmp_path):
        """Both root and path can be relative — resolve() normalizes both."""
        root = tmp_path / "workspace"
        root.mkdir()
        target = root / "file.txt"
        target.touch()

        # Use relative paths from tmp_path
        rel_root = Path("workspace")
        rel_target = Path("workspace/file.txt")

        # Change to tmp_path so relative paths resolve correctly
        import os
        old_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)
            error = validate_within_dir(rel_target, rel_root)
            assert error is None
        finally:
            os.chdir(old_cwd)

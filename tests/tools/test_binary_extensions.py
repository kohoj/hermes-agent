"""Tests for tools.binary_extensions binary file detection.

Used by file tools to skip text-based operations on binary files.
"""

import pytest

from tools.binary_extensions import BINARY_EXTENSIONS, has_binary_extension


class TestBinaryExtensionsConstant:
    """BINARY_EXTENSIONS — immutable set of known binary extensions."""

    def test_is_frozen_set(self):
        """Ensure BINARY_EXTENSIONS is immutable."""
        assert isinstance(BINARY_EXTENSIONS, frozenset)

    def test_all_lowercase_with_dot(self):
        """All extensions should start with '.' and be lowercase."""
        for ext in BINARY_EXTENSIONS:
            assert ext.startswith("."), f"Extension missing dot: {ext}"
            assert ext == ext.lower(), f"Extension not lowercase: {ext}"

    def test_contains_common_image_formats(self):
        """Verify common image extensions are present."""
        for ext in [".png", ".jpg", ".jpeg", ".gif", ".webp"]:
            assert ext in BINARY_EXTENSIONS

    def test_contains_common_video_formats(self):
        for ext in [".mp4", ".mov", ".avi", ".mkv"]:
            assert ext in BINARY_EXTENSIONS

    def test_contains_common_audio_formats(self):
        for ext in [".mp3", ".wav", ".ogg", ".flac"]:
            assert ext in BINARY_EXTENSIONS

    def test_contains_common_archive_formats(self):
        for ext in [".zip", ".tar", ".gz", ".7z", ".rar"]:
            assert ext in BINARY_EXTENSIONS

    def test_contains_executables(self):
        for ext in [".exe", ".dll", ".so", ".dylib"]:
            assert ext in BINARY_EXTENSIONS

    def test_excludes_pdf(self):
        """PDF is text-based and should NOT be in the binary set."""
        assert ".pdf" not in BINARY_EXTENSIONS


class TestHasBinaryExtension:
    """has_binary_extension() — pure string check, no I/O."""

    def test_image_file_detected(self):
        assert has_binary_extension("photo.png")
        assert has_binary_extension("icon.jpg")
        assert has_binary_extension("avatar.webp")

    def test_video_file_detected(self):
        assert has_binary_extension("demo.mp4")
        assert has_binary_extension("clip.mov")

    def test_audio_file_detected(self):
        assert has_binary_extension("song.mp3")
        assert has_binary_extension("track.wav")

    def test_archive_detected(self):
        assert has_binary_extension("backup.zip")
        assert has_binary_extension("release.tar.gz")

    def test_executable_detected(self):
        assert has_binary_extension("program.exe")
        assert has_binary_extension("lib.so")
        assert has_binary_extension("driver.dll")

    def test_case_insensitive(self):
        """Extension check is case-insensitive."""
        assert has_binary_extension("Photo.PNG")
        assert has_binary_extension("VIDEO.MP4")
        assert has_binary_extension("Archive.ZIP")

    def test_text_files_not_binary(self):
        assert not has_binary_extension("readme.txt")
        assert not has_binary_extension("config.yaml")
        assert not has_binary_extension("script.py")
        assert not has_binary_extension("style.css")

    def test_pdf_not_binary(self):
        """PDF should not be flagged as binary (agents may inspect it)."""
        assert not has_binary_extension("document.pdf")

    def test_no_extension_not_binary(self):
        """Files without extension are not binary by default."""
        assert not has_binary_extension("Makefile")
        assert not has_binary_extension("README")
        assert not has_binary_extension("LICENSE")

    def test_hidden_file_with_binary_extension(self):
        """Hidden files (starting with .) can still be binary."""
        assert has_binary_extension(".hidden.png")
        assert has_binary_extension(".cache.sqlite")

    def test_multiple_dots_uses_last_extension(self):
        """archive.tar.gz should detect .gz, not .tar."""
        assert has_binary_extension("file.tar.gz")
        assert has_binary_extension("backup.2024-07-02.zip")

    def test_extension_only_path(self):
        """Edge case: path is just an extension."""
        assert has_binary_extension(".png")
        assert has_binary_extension(".mp3")

    def test_empty_string_not_binary(self):
        assert not has_binary_extension("")

    def test_path_with_directory_components(self):
        """Works with full paths, not just filenames."""
        assert has_binary_extension("/home/user/images/photo.jpg")
        assert has_binary_extension("../assets/video.mp4")
        assert has_binary_extension("C:\\Users\\name\\file.exe")

    def test_mixed_case_path(self):
        """Case insensitivity applies to extension only."""
        assert has_binary_extension("MyPhoto.PNG")
        assert has_binary_extension("PROJECT/Video.MP4")

"""Tests for utils.py URL and proxy normalization helpers.

These utilities provide safe URL parsing and proxy compatibility across
httpx/aiohttp, preventing false-positive hostname matches in security-
sensitive routing decisions.
"""

import pytest

from utils import (
    base_url_host_matches,
    base_url_hostname,
    normalize_proxy_url,
)


class TestNormalizeProxyUrl:
    """normalize_proxy_url() — httpx/aiohttp proxy compatibility."""

    def test_socks_alias_rewritten_to_socks5(self):
        """WSL/Clash environments export socks:// which httpx rejects."""
        assert normalize_proxy_url("socks://127.0.0.1:7890") == "socks5://127.0.0.1:7890"

    def test_case_insensitive_socks_rewrite(self):
        assert normalize_proxy_url("SOCKS://localhost:1080") == "socks5://localhost:1080"
        assert normalize_proxy_url("SoCkS://proxy:9050") == "socks5://proxy:9050"

    def test_http_proxy_unchanged(self):
        assert normalize_proxy_url("http://proxy.example:8080") == "http://proxy.example:8080"

    def test_https_proxy_unchanged(self):
        assert normalize_proxy_url("https://secure-proxy:3128") == "https://secure-proxy:3128"

    def test_socks5_explicit_unchanged(self):
        """Explicit socks5:// doesn't need rewriting."""
        assert normalize_proxy_url("socks5://127.0.0.1:1080") == "socks5://127.0.0.1:1080"

    def test_none_returns_none(self):
        assert normalize_proxy_url(None) is None

    def test_empty_string_returns_none(self):
        assert normalize_proxy_url("") is None
        assert normalize_proxy_url("  ") is None

    def test_whitespace_trimmed(self):
        assert normalize_proxy_url("  socks://127.0.0.1:7890  ") == "socks5://127.0.0.1:7890"


class TestBaseUrlHostname:
    """base_url_hostname() — extract hostname for safe comparison."""

    def test_full_url_with_scheme(self):
        assert base_url_hostname("https://api.openai.com/v1") == "api.openai.com"

    def test_bare_hostname(self):
        """Accepts bare hostnames without scheme."""
        assert base_url_hostname("api.anthropic.com") == "api.anthropic.com"

    def test_hostname_with_port(self):
        assert base_url_hostname("https://localhost:8000") == "localhost"
        assert base_url_hostname("api.example:443") == "api.example"

    def test_lowercased(self):
        assert base_url_hostname("https://API.OpenAI.COM") == "api.openai.com"

    def test_trailing_dot_stripped(self):
        """FQDN trailing dots are stripped for comparison."""
        assert base_url_hostname("https://api.example.com.") == "api.example.com"

    def test_ipv4_address(self):
        assert base_url_hostname("http://127.0.0.1:8080") == "127.0.0.1"

    def test_ipv6_address(self):
        assert base_url_hostname("http://[::1]:8080") == "::1"

    def test_empty_string_returns_empty(self):
        assert base_url_hostname("") == ""
        assert base_url_hostname("  ") == ""

    def test_none_returns_empty(self):
        assert base_url_hostname(None) == ""

    def test_url_with_path_and_query(self):
        """Path and query components are ignored."""
        assert base_url_hostname("https://api.x.ai/v1/chat?key=val") == "api.x.ai"

    def test_malicious_path_not_treated_as_hostname(self):
        """Security: path segments shouldn't leak into hostname extraction."""
        assert base_url_hostname("https://evil.com/api.openai.com/v1") == "evil.com"
        assert base_url_hostname("http://proxy.test/api.anthropic.com") == "proxy.test"


class TestBaseUrlHostMatches:
    """base_url_host_matches() — safe subdomain matching."""

    def test_exact_domain_match(self):
        assert base_url_host_matches("https://moonshot.ai", "moonshot.ai") is True
        assert base_url_host_matches("https://openai.com/v1", "openai.com") is True

    def test_subdomain_match(self):
        assert base_url_host_matches("https://api.moonshot.ai/v1", "moonshot.ai") is True
        assert base_url_host_matches("https://api.openai.com", "openai.com") is True

    def test_nested_subdomain_match(self):
        assert base_url_host_matches("https://dev.api.example.com", "example.com") is True

    def test_bare_hostname_match(self):
        """Accepts bare hostnames without scheme."""
        assert base_url_host_matches("api.anthropic.com", "anthropic.com") is True

    def test_case_insensitive(self):
        assert base_url_host_matches("https://API.MOONSHOT.AI", "moonshot.ai") is True

    def test_rejects_path_based_false_positive(self):
        """Security: attacker-controlled path shouldn't match."""
        assert base_url_host_matches("https://evil.com/moonshot.ai/v1", "moonshot.ai") is False

    def test_rejects_subdomain_prefix_false_positive(self):
        """Security: moonshot.ai.evil should not match moonshot.ai."""
        assert base_url_host_matches("https://moonshot.ai.evil/v1", "moonshot.ai") is False

    def test_rejects_partial_label_match(self):
        """'api.example.com' should NOT match 'example.com.attacker.net'."""
        assert base_url_host_matches("https://example.com.attacker.net", "example.com") is False

    def test_different_domain_rejected(self):
        assert base_url_host_matches("https://api.x.ai", "anthropic.com") is False

    def test_empty_base_url_returns_false(self):
        assert base_url_host_matches("", "example.com") is False

    def test_empty_domain_returns_false(self):
        assert base_url_host_matches("https://api.example.com", "") is False

    def test_both_empty_returns_false(self):
        assert base_url_host_matches("", "") is False

    def test_none_inputs_returns_false(self):
        assert base_url_host_matches(None, "example.com") is False
        assert base_url_host_matches("https://api.example.com", None) is False

    def test_whitespace_trimmed(self):
        assert base_url_host_matches("  https://api.moonshot.ai  ", "  moonshot.ai  ") is True

    def test_trailing_dot_normalized(self):
        """FQDN trailing dots are normalized for comparison."""
        assert base_url_host_matches("https://api.example.com.", "example.com") is True

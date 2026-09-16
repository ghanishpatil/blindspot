"""Repository-URL ingestion tests.

These cover the SSRF-sensitive validation boundary. They are pure unit tests:
no network access and no actual git clone.
"""

from __future__ import annotations

import pytest

from app.config import get_settings
from app.scanner.repository import RepositoryError, validate_repository_url


def _settings():
    return get_settings()


# ── Valid URLs ────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/openssl/openssl",
        "https://github.com/openssl/openssl.git",
        "https://gitlab.com/group/project",
        "https://bitbucket.org/team/repo",
        "https://gist.github.com/user/abc123",  # subdomain of an allowed host
        "  https://github.com/owner/repo  ",  # surrounding whitespace tolerated
    ],
)
def test_valid_urls_are_accepted(url: str) -> None:
    result = validate_repository_url(url, _settings())
    assert result == url.strip()


# ── Scheme rejection ──────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/owner/repo",   # not HTTPS
        "git://github.com/owner/repo",    # git protocol
        "ssh://git@github.com/owner/repo",  # ssh
        "file:///etc/passwd",             # local file
        "ftp://github.com/owner/repo",    # ftp
    ],
)
def test_non_https_schemes_are_rejected(url: str) -> None:
    with pytest.raises(RepositoryError):
        validate_repository_url(url, _settings())


# ── Host / SSRF rejection ─────────────────────────────────────────────────

@pytest.mark.parametrize(
    "url",
    [
        "https://localhost/owner/repo",
        "https://127.0.0.1/owner/repo",       # IPv4 literal
        "https://169.254.169.254/latest",      # cloud metadata IP
        "https://[::1]/owner/repo",            # IPv6 literal
        "https://internal.internal/owner/repo",
        "https://service.local/owner/repo",
        "https://evil.com/owner/repo",         # not on allowlist
        "https://notgithub.com/owner/repo",    # not on allowlist
    ],
)
def test_disallowed_or_internal_hosts_are_rejected(url: str) -> None:
    with pytest.raises(RepositoryError):
        validate_repository_url(url, _settings())


# ── Structural rejection ──────────────────────────────────────────────────

@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "https://github.com",       # no path
        "https://github.com/",      # empty path
        "not-a-url",
    ],
)
def test_malformed_urls_are_rejected(url: str) -> None:
    with pytest.raises(RepositoryError):
        validate_repository_url(url, _settings())


def test_lookalike_host_is_rejected() -> None:
    """A host that merely *ends with* the allowed string but isn't a subdomain."""
    # "github.com.evil.com" ends with neither "github.com" nor ".github.com"
    # as a suffix boundary — it is a subdomain of evil.com, which is not allowed.
    with pytest.raises(RepositoryError):
        validate_repository_url("https://github.com.evil.com/owner/repo", _settings())

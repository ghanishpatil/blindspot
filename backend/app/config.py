"""Environment-driven configuration for the Blindspot ECDAT backend.

All tunable values live here. Nothing that varies between machines or
deployments should be hard-coded elsewhere in the codebase.

Two values deserve special mention because the specification calls them out
explicitly:

``QUANTUM_HORIZON_YEARS`` (Mosca ``Z``)
    The estimated number of years until a cryptographically relevant quantum
    computer exists. This is an *assumption*, not a fact, so it is
    configurable and its provenance is reported alongside every calculation.

``MIGRATION_TIME_YEARS`` (Mosca ``Y``)
    Default organisational migration time. Individual findings may override
    this once the classifier is in place.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/config.py -> backend/app -> backend
BACKEND_ROOT = Path(__file__).resolve().parent.parent
# backend -> repository root
REPO_ROOT = BACKEND_ROOT.parent


class Settings(BaseSettings):
    """Application settings loaded from the environment / ``.env`` file."""

    model_config = SettingsConfigDict(
        env_file=BACKEND_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Application ------------------------------------------------------
    app_name: str = "Blindspot ECDAT"
    app_version: str = "0.1.0"
    blindspot_env: str = Field(
        default="production",
        description=(
            "Deployment environment: development | production. Defaults to "
            "'production' so a deployment that forgets to set it fails closed "
            "(authentication stays enforced). Local development sets it to "
            "'development' explicitly via .env."
        ),
    )

    # Comma-separated rather than a JSON list: pydantic-settings would
    # otherwise try to JSON-decode the raw environment string.
    blindspot_cors_origins: str = Field(
        default="http://127.0.0.1:5173,http://localhost:5173",
        description="Comma-separated list of origins allowed to call the API.",
    )

    # --- Firebase ---------------------------------------------------------
    firebase_project_id: str | None = Field(
        default=None,
        description="Firebase project ID.",
    )
    firebase_credentials_path: str | None = Field(
        default=None,
        description="Absolute path to the Firebase service account JSON file.",
    )
    firebase_storage_bucket: str | None = Field(
        default=None,
        description="Firebase Storage bucket, e.g. my-project.firebasestorage.app.",
    )

    auth_disabled: bool = Field(
        default=False,
        description=(
            "Bypass Firebase token verification. Local development only; "
            "refused when blindspot_env is 'production'."
        ),
    )

    # --- Scanning ---------------------------------------------------------
    demo_repo_path: str = Field(
        default=str(REPO_ROOT / "demo-repo"),
        description="Path to the seeded repository that the demo scans.",
    )
    semgrep_path: str = Field(
        default="semgrep",
        description="Semgrep executable. Override if it is not on PATH.",
    )
    semgrep_timeout_seconds: int = Field(
        default=0,
        ge=0,
        description=(
            "Hard timeout for a single semgrep invocation, in seconds. "
            "Zero (the default) means unlimited -- the scan runs to "
            "completion no matter how long it takes. Set a positive value "
            "only if you deliberately want a safety-net cap."
        ),
    )

    scan_work_dir: str = Field(
        default=str(REPO_ROOT / ".scan-work"),
        description=(
            "Working directory for cloned repos and extracted container images. "
            "Kept on the project volume rather than the OS temp dir (some Windows "
            "security tooling makes scanning %TEMP% paths slow/unreliable), and "
            "placed OUTSIDE the backend directory so uvicorn's --reload watcher "
            "does not restart the process when a container image is extracted."
        ),
    )

    # --- Binary scanning (lite) -------------------------------------------
    binary_scan_enabled: bool = Field(
        default=True,
        description="Fingerprint crypto constants/OIDs/library strings in compiled binaries.",
    )
    binary_max_scan_mb: int = Field(
        default=50,
        ge=1,
        description="Skip individual binaries larger than this (memory guard).",
    )

    # --- HSM / KMS declaration scanning -----------------------------------
    infra_scan_enabled: bool = Field(
        default=True,
        description="Discover HSM/PKCS#11 and cloud-KMS references in IaC and code.",
    )
    infra_max_scan_mb: int = Field(
        default=5,
        ge=1,
        description="Skip individual infra/config files larger than this.",
    )

    # --- Static cert / key / keystore discovery ---------------------------
    # Reads certificates and key material *as bytes* from the scanned target —
    # the file itself is the evidence, so findings sit at high confidence.
    static_crypto_scan_enabled: bool = Field(
        default=True,
        description=(
            "Discover static certificate, key, and keystore artefacts on disk. "
            "Scans .pem/.crt/.cer/.der/.key files and inline PEM markers in "
            "source and config files."
        ),
    )
    static_crypto_max_scan_mb: int = Field(
        default=5,
        ge=1,
        description="Skip individual cert/key files larger than this.",
    )

    # --- Config-file crypto policy scanning -------------------------------
    # Reads protocol / cipher / KEX / MAC / hostkey declarations from server
    # and JDK configuration. Declarations are *what the admin asked for* —
    # live probing (TLS scanner) proves what the server actually negotiates.
    config_policy_scan_enabled: bool = Field(
        default=True,
        description=(
            "Discover crypto policy declarations in server / JDK config files. "
            "Covers nginx, Apache, sshd_config, ssh_config, openssl.cnf, "
            "java.security, postgresql.conf, and .NET web.config."
        ),
    )
    config_policy_max_scan_mb: int = Field(
        default=2,
        ge=1,
        description="Skip individual config files larger than this.",
    )

    # --- Live PKCS#11 / HSM attestation (R7) ------------------------------
    # Opens a real PKCS#11 session against a configured module (SoftHSM,
    # YubiHSM, Luna, nShield, ...) and enumerates keys. Opt-in because it
    # requires a system PKCS#11 library and (optionally) a token PIN.
    pkcs11_scan_enabled: bool = Field(
        default=False,
        description=(
            "Enable live PKCS#11 attestation. Requires python-pkcs11 to be "
            "installed and a valid pkcs11_module_path pointing at the "
            "vendor's PKCS#11 shim (libsofthsm2.so, libykcs11.dll, ...)."
        ),
    )
    pkcs11_module_path: str = Field(
        default="",
        description=(
            "Absolute path to the PKCS#11 shim library. Empty disables the "
            "scanner even when pkcs11_scan_enabled is true."
        ),
    )
    pkcs11_token_label: str = Field(
        default="",
        description=(
            "Optional token label. When empty, every token the module "
            "exposes is enumerated read-only."
        ),
    )
    pkcs11_pin: str = Field(
        default="",
        description=(
            "Optional user PIN for token login. Most HSMs expose public-key "
            "and certificate metadata (algorithm, size, curve) WITHOUT a "
            "PIN, so leaving this empty is often correct."
        ),
    )
    pkcs11_scan_timeout_seconds: int = Field(
        default=30,
        ge=1,
        description="Hard cap on PKCS#11 session time per scan.",
    )

    # --- Live AWS KMS attestation (R8) ------------------------------------
    aws_kms_scan_enabled: bool = Field(
        default=False,
        description=(
            "Enable live AWS KMS attestation. Requires boto3 to be "
            "installed and AWS credentials (env, shared config, or IAM "
            "role) resolvable via the standard boto3 credential chain."
        ),
    )
    aws_kms_region: str = Field(
        default="",
        description=(
            "AWS region to enumerate KMS keys in. Empty falls back to the "
            "boto3 session default."
        ),
    )
    aws_kms_max_keys: int = Field(
        default=100,
        ge=1,
        description=(
            "Cap on the number of KMS keys the scanner will describe. "
            "Prevents unbounded listings on very large AWS accounts."
        ),
    )

    # --- Live TLS / certificate scanning ----------------------------------
    tls_scan_enabled: bool = Field(
        default=True,
        description="Allow live TLS/certificate probing of a hostname.",
    )
    tls_scan_timeout_seconds: int = Field(
        default=10,
        ge=1,
        description="Hard timeout for a single TLS handshake probe.",
    )

    # --- Container image scanning -----------------------------------------
    container_scan_enabled: bool = Field(
        default=True,
        description="Allow scanning container images (archive or CLI pull).",
    )
    container_max_extract_mb: int = Field(
        default=1024,
        ge=1,
        description="Cap on total bytes extracted from an image (bomb guard).",
    )
    container_cli_timeout_seconds: int = Field(
        default=0,
        ge=0,
        description=(
            "Hard timeout for a container CLI 'save' when pulling by "
            "reference, in seconds. Zero (the default) means unlimited "
            "-- the pull runs to completion no matter how long it takes."
        ),
    )

    # --- Repository URL ingestion -----------------------------------------
    # A user-supplied repository URL is an SSRF-sensitive boundary: the server
    # clones it. Cloning is HTTPS-only and restricted to an allowlist of hosts.
    git_path: str = Field(
        default="git",
        description="git executable used to clone remote repositories for URL scans.",
    )
    git_clone_depth: int = Field(
        default=1,
        ge=1,
        description="Shallow-clone depth for repository-URL scans.",
    )
    repo_clone_timeout_seconds: int = Field(
        default=0,
        ge=0,
        description=(
            "Hard timeout for a single git clone, in seconds. Zero (the "
            "default) means unlimited -- the clone runs to completion no "
            "matter how long it takes. Large repositories on slow "
            "connections need this: pycryptodome / boringssl / openssl "
            "regularly take longer than any fixed cap you would pick."
        ),
    )
    allowed_git_hosts: str = Field(
        default="github.com,gitlab.com,bitbucket.org",
        description=(
            "Comma-separated allowlist of hosts permitted for repository-URL "
            "scans. Exact host or a subdomain of an allowed host is accepted."
        ),
    )

    # --- Mosca risk model -------------------------------------------------
    quantum_horizon_years: float = Field(
        default=10.0,
        gt=0,
        description="Mosca Z: years until a cryptographically relevant quantum computer.",
    )
    quantum_horizon_source: str = Field(
        default="Demo assumption (configurable via QUANTUM_HORIZON_YEARS)",
        description="Provenance string reported with every Mosca calculation.",
    )
    migration_time_years: float = Field(
        default=3.0,
        gt=0,
        description="Mosca Y: default organisational migration time in years.",
    )

    # --- Named Z presets --------------------------------------------------
    # DEMO_REQUIREMENTS §4.4 requires at least one alternate Z source.
    # These are named regulatory/research timelines a demo can switch between
    # to show the same findings shifting tiers under different assumptions.
    # The active Z is always QUANTUM_HORIZON_YEARS; these are reference values
    # available to the UI and the recommend/risk stages.
    @computed_field  # type: ignore[prop-decorator]
    @property
    def z_presets(self) -> list[dict[str, object]]:
        """Named Z presets for the dashboard timeline selector."""
        current_year = 2026
        return [
            {
                "name": "Demo default",
                "z": self.quantum_horizon_years,
                "targetYear": current_year + self.quantum_horizon_years,
                "source": self.quantum_horizon_source,
            },
            {
                "name": "India CII — Category A (sensitive infra)",
                "z": max(1, 2027 - current_year),
                "targetYear": 2027,
                "source": "India MeitY/CII PQC advisory 2027 deadline for Category A systems",
            },
            {
                "name": "India CII — Category B",
                "z": max(2, 2028 - current_year),
                "targetYear": 2028,
                "source": "India MeitY/CII PQC advisory 2028 deadline for Category B systems",
            },
            {
                "name": "India CII — Category C",
                "z": max(3, 2029 - current_year),
                "targetYear": 2029,
                "source": "India MeitY/CII PQC advisory 2029 deadline for Category C systems",
            },
            {
                "name": "NIST IR 8547 — 2030 deprecation",
                "z": max(4, 2030 - current_year),
                "targetYear": 2030,
                "source": "NIST IR 8547 recommendation to deprecate classical asymmetric by 2030",
            },
            {
                "name": "NIST IR 8547 — 2035 disallow",
                "z": max(9, 2035 - current_year),
                "targetYear": 2035,
                "source": "NIST IR 8547 recommendation to disallow classical asymmetric by 2035",
            },
            {
                "name": "CRQC mid-range estimate",
                "z": 15.0,
                "targetYear": current_year + 15,
                "source": "Mid-range expert survey estimate for fault-tolerant quantum computer",
            },
        ]

    # --- Artefacts / fallback --------------------------------------------
    artifacts_dir: str = Field(
        default=str(BACKEND_ROOT / "artifacts"),
        description="Local directory for generated CBOM and report files.",
    )
    fallback_cache_path: str = Field(
        default=str(BACKEND_ROOT / "app" / "data" / "cache" / "last_scan.json"),
        description="Cached last-successful scan used by the demo fallback mode.",
    )

    # --- Derived values ---------------------------------------------------
    @computed_field  # type: ignore[prop-decorator]
    @property
    def cors_origins(self) -> list[str]:
        """CORS origins as a cleaned list."""
        return [
            origin.strip()
            for origin in self.blindspot_cors_origins.split(",")
            if origin.strip()
        ]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def git_host_allowlist(self) -> list[str]:
        """Allowed git hosts as a cleaned, lowercased list."""
        return [
            host.strip().lower()
            for host in self.allowed_git_hosts.split(",")
            if host.strip()
        ]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_production(self) -> bool:
        return self.blindspot_env.strip().lower() == "production"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def firebase_configured(self) -> bool:
        """True when enough Firebase configuration exists to initialise Admin SDK."""
        if not self.firebase_project_id:
            return False
        if not self.firebase_credentials_path:
            return False
        return Path(self.firebase_credentials_path).expanduser().is_file()

    @property
    def demo_repo(self) -> Path:
        return Path(self.demo_repo_path).expanduser().resolve()

    @property
    def artifacts(self) -> Path:
        return Path(self.artifacts_dir).expanduser().resolve()

    @property
    def fallback_cache(self) -> Path:
        return Path(self.fallback_cache_path).expanduser().resolve()

    @property
    def credentials_file(self) -> Path | None:
        if not self.firebase_credentials_path:
            return None
        return Path(self.firebase_credentials_path).expanduser().resolve()

    def auth_bypass_allowed(self) -> bool:
        """Auth may be bypassed only in an explicitly-development environment.

        Fail-closed: the bypass requires the environment to be the literal
        string ``development``. Any other value — ``production``, ``staging``,
        an empty string, a typo, or an unset variable (which defaults to
        ``production``) — refuses the bypass. This makes accidental exposure in
        a deployment take two deliberate mistakes, not one.
        """
        return self.auth_disabled and self.blindspot_env.strip().lower() == "development"

    @property
    def scan_work(self) -> Path:
        return Path(self.scan_work_dir).expanduser().resolve()

    def ensure_directories(self) -> None:
        """Create local directories the application writes to."""
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.fallback_cache.parent.mkdir(parents=True, exist_ok=True)
        self.scan_work.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor, suitable for use as a FastAPI dependency."""
    return Settings()


def subprocess_timeout(seconds: int) -> float | None:
    """Translate a config timeout value to :func:`subprocess.run`'s argument.

    * ``0`` (the new default across every scanner) means *unlimited* --
      return :data:`None` so ``subprocess.run`` waits indefinitely.
    * Any positive value is passed straight through as the second cap.

    Keeping this in one function ensures the "0 = unlimited" convention
    is honoured by every caller and cannot silently drift if we add new
    scanners later.
    """
    return None if seconds <= 0 else float(seconds)

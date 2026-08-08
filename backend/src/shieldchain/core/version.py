"""Public build identifiers with no host or source-control metadata."""

from importlib.metadata import PackageNotFoundError, version

EXPECTED_SCHEMA_REVISION = "20260729_01"

try:
    SERVICE_VERSION = version("shieldchain")
except PackageNotFoundError:  # pragma: no cover - editable installs provide metadata
    SERVICE_VERSION = "0.0.0+unknown"

SERVICE_NAME = "shieldchain"

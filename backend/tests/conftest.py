from collections.abc import Iterator

import pytest
import structlog
from fastapi.testclient import TestClient

from shieldchain.main import create_app


@pytest.fixture(autouse=True)
def reset_structlog_configuration() -> Iterator[None]:
    """Prevent a captured output stream configured by one test leaking into the next."""
    yield
    structlog.reset_defaults()


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(create_app()) as test_client:
        yield test_client

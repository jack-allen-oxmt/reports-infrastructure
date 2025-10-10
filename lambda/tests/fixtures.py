import pytest
from unittest.mock import MagicMock
import json


class DummyResponse:
    """Mock for urlopen responses."""
    def __init__(self, data):
        self._data = data.encode('utf-8')

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        pass

@pytest.fixture
def fake_urlopen_success(monkeypatch):
    # Mock response object
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "items": [{"index": {"status": 201}}]  # mimic successful bulk response
    }).encode("utf-8")

    # Mock context manager: urlopen().__enter__() returns mock_response
    mock_urlopen = MagicMock()
    mock_urlopen.__enter__.return_value = mock_response

    # Patch urlopen in the module where it is used
    monkeypatch.setattr("opensearch_lambda_function.urlopen", lambda *args, **kwargs: mock_urlopen)

    return mock_urlopen

@pytest.fixture
def fake_urlopen_failure(monkeypatch):
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "items": [{"index": {"status": 500}}]  # mimic failed bulk response
    }).encode("utf-8")

    mock_urlopen = MagicMock()
    mock_urlopen.__enter__.return_value = mock_response

    monkeypatch.setattr("opensearch_lambda_function.urlopen", lambda *args, **kwargs: mock_urlopen)

    return mock_urlopen


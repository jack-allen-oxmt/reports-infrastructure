# fixtures.py
import pytest
import json
from unittest.mock import MagicMock

class DummyResponse:
    """Context manager that returns bytes from .read()"""
    def __init__(self, body):
        self._body = json.dumps(body).encode('utf-8')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def read(self):
        return self._body

@pytest.fixture
def fake_urlopen(monkeypatch):
    """
    Factory: call fake_urlopen('success'|'update'|'created'|'failure'|'index_created')
    It patches opensearch_lambda_function.urlopen and returns a dict `captured`
    with captured['req'] containing the Request object that the code sent.
    """
    def _mock_urlopen(response_type='success'):
        if response_type == 'success':
            body = {"items": [{"index": {"status": 201}}]}
        elif response_type == 'update':
            body = {"items": [{"update": {"status": 200, "result": "updated"}}]}
        elif response_type == 'created':
            body = {"items": [{"update": {"status": 201, "result": "created"}}]}
        elif response_type == 'index_created':
            body = {"items": [{"index": {"status": 201}}]}
        elif response_type == 'failure':
            body = {"items": [{"index": {"status": 500}}]}
        else:
            raise ValueError(f"Unknown response_type: {response_type}")

        captured = {}

        def _urlopen(req, timeout=None):
            # capture the Request (it may be a urllib.request.Request)
            captured['req'] = req
            return DummyResponse(body)

        monkeypatch.setattr("opensearch_lambda_function.urlopen", _urlopen)
        return captured

    return _mock_urlopen

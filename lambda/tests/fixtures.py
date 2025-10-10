"""
Test fixtures for mocking urllib.request.urlopen calls to OpenSearch.

IMPORTANT:
- send_events_to_opensearch()  -> uses bulk "index" actions for events
  -> bulk response items should be shaped like: {"items":[ {"index": {"status": 201, ...}}, ... ]}

- update_session_summaries() -> uses bulk "update" actions with upsert
  -> bulk response items should be shaped like: {"items":[ {"update": {"status": 200, "result":"updated"}}, ... ]}

Use fake_urlopen('success') for an index-success (events).
Use fake_urlopen('update') for an update-success (session upsert updated).
Use fake_urlopen('created') to simulate update->created (upsert created a new doc, status 201).
Use fake_urlopen('failure') to simulate failure (status 500, etc).
"""
import pytest
import json

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
            captured['req'] = req
            return DummyResponse(body)

        monkeypatch.setattr("opensearch_lambda_function.urlopen", _urlopen)
        return captured

    return _mock_urlopen

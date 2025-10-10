# tests/test_send_events.py
import json
from opensearch_lambda_function import send_events_to_opensearch

class DummyResponse:
    def __init__(self, data):
        self._data = data.encode('utf-8')
    def read(self):
        return self._data
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        pass

def fake_urlopen_factory(result_json):
    def fake(req, timeout=10):
        return DummyResponse(result_json)
    return fake

def test_send_events_bulk_build_and_send(monkeypatch):
    docs = [{'timestamp': 1600000000000, 'path': '/a', 'session_id': 's1', 'user': 'u1'}]
    result = {"items": [{"index": {"status": 201}}]}
    monkeypatch.setattr('opensearch_lambda_function.urlopen', fake_urlopen_factory(json.dumps(result)))
    count = send_events_to_opensearch(docs, 'search.example.com', 'ap-southeast-2')
    assert count == 1

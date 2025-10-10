import json
from unittest.mock import patch
from opensearch_lambda_function import send_events_to_opensearch

class DummyResponse:
    def __init__(self, data):
        # store bytes that .read() will return
        self._data = data.encode('utf-8')
    def read(self):
        return self._data
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        pass

def test_send_events_bulk_build_and_send():
    docs = [{'timestamp': 1600000000000, 'path': '/a', 'session_id': 's1', 'user': 'u1'}]
    result = {"items": [{"index": {"status": 201}}]}

    # Patch urlopen in the module that uses it (opensearch_lambda_function)
    with patch('opensearch_lambda_function.urlopen') as mock_urlopen:
        mock_urlopen.return_value = DummyResponse(json.dumps(result))
        count = send_events_to_opensearch(docs, 'search.example.com', 'ap-southeast-2')
        assert count == 1

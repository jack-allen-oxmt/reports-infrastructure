from opensearch_lambda_function import send_events_to_opensearch, update_session_summaries, lambda_handler
from fixtures import fake_urlopen


def test_send_events_success(fake_urlopen):
    # Use the 'success' response (index created) for bulk events
    captured = fake_urlopen('success')

    docs = [{'timestamp': 1600000000000, 'path': '/a', 'session_id': 's1', 'user': 'u1'}]
    count = send_events_to_opensearch(docs, 'search.example.com', 'ap-southeast-2')
    assert count == 1

    # optional: inspect body sent
    body_sent = captured['req'].data.decode('utf-8')
    assert '/a' in body_sent


def test_send_events_failure(fake_urlopen):
    fake_urlopen('failure')

    docs = [{'timestamp': 1600000000000, 'path': '/a', 'session_id': 's1', 'user': 'u1'}]
    count = send_events_to_opensearch(docs, 'search.example.com', 'ap-southeast-2')
    assert count == 0


def test_lambda_handler_processing(monkeypatch, fake_urlopen):
    monkeypatch.setenv('OPENSEARCH_ENDPOINT', 'search.example.com')
    monkeypatch.setenv('AWS_REGION', 'ap-southeast-2')

    fake_urlopen('update')  # simulate successful bulk update

    event = {"test_mode": True, "logEvents": [{"message": "USER:[u1] PATH:[/a] SESSION:[s1]", "timestamp": 123}]}
    context = {}
    result = lambda_handler(event, context)

    assert result['statusCode'] == 200
    assert "Processed 1 events" in result['body']


def test_lambda_handler_missing_endpoint(monkeypatch):
    monkeypatch.delenv('OPENSEARCH_ENDPOINT', raising=False)
    event = {"test_mode": True, "logEvents": []}
    context = {}
    result = lambda_handler(event, context)
    assert result['statusCode'] == 500

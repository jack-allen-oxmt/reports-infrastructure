import json
from opensearch_lambda_function import parse_log_message, extract_asset_types, extract_site_tokens, should_include_log


def make_event(message, timestamp=0):
    return {'message': message, 'timestamp': timestamp}


def test_parse_basic_fields():
    msg = "SESSION:[abc123] USER:[isaac.newton@oxmt.com] PATH:[/foo/bar] REQ_METHOD:[GET] STATUS_CODE:[200] RESPONSE-TIME:[123]"
    doc = parse_log_message(make_event(msg, timestamp=1600000000000))
    assert doc['session_id'] == 'abc123'
    assert doc['user'] == 'isaac.newton@oxmt.com'
    assert doc['path'] == '/foo/bar'
    assert doc['method'] == 'GET'
    assert doc['status_code'] == 200
    assert doc['response_time'] == 123


def test_extract_v2_body_list():
    v2_body = [
        {'include': {'assetType': 'video,audio', 'siteToken': 'foo'}},
        {'include': {'assetType': 'audio', 'siteToken': 'bar'}}
    ]
    assert extract_asset_types(v2_body) == ['audio', 'video']
    assert extract_site_tokens(v2_body) == ['bar', 'foo']


def test_should_include_log_filters():
    # unauthenticated
    doc = {'user': 'UNAUTHENTICATED', 'path': '/foo'}
    assert not should_include_log(doc)
    # noise path
    doc = {'user': 'joe', 'path': '/health'}
    assert not should_include_log(doc)
    # good doc
    doc = {'user': 'joe', 'path': '/app/endpoint', 'raw_message': ''}
    assert should_include_log(doc)

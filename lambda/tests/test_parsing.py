import pytest
from opensearch_lambda_function import (
    parse_log_message, extract_asset_types, extract_site_tokens, should_include_log
)

@pytest.mark.parametrize("message,expected_session,expected_user,expected_path", [
    ("SESSION:[s1] USER:[u1] PATH:[/a]", "s1", "u1", "/a"),
    ("SESSION:[s2] USER:[u2] PATH:[/b]", "s2", "u2", "/b"),
    ("SESSION:[] USER:[] PATH:[]", None, None, None),
])
def test_parse_basic_fields(message, expected_session, expected_user, expected_path):
    log_event = {"message": message, "timestamp": 1234567890}
    doc = parse_log_message(log_event)
    assert doc.get('session_id') == expected_session
    assert doc.get('user') == expected_user
    assert doc.get('path') == expected_path

def test_extract_asset_types_various():
    assert extract_asset_types([{"include": {"assetType": "A,B"}}]) == ["A", "B"]
    assert extract_asset_types({"include": {"assetType": "X"}}) == ["X"]
    assert extract_asset_types([]) is None
    assert extract_asset_types({}) is None

def test_extract_site_tokens_various():
    assert extract_site_tokens([{"include": {"siteToken": "T1,T2"}}]) == ["T1", "T2"]
    assert extract_site_tokens({"include": {"siteToken": "Z"}}) == ["Z"]
    assert extract_site_tokens([]) is None
    assert extract_site_tokens({}) is None

@pytest.mark.parametrize("doc,expected", [
    ({"user": "UNAUTHENTICATED", "path": "/a"}, False),
    ({"user": "u1", "path": "/health"}, False),
    ({"user": "u1", "path": "/a"}, True),
    ({"user": "u1", "path": "/im_api/img/x", "status_code": 400}, False),
])
def test_should_include_log_logic(doc, expected):
    assert should_include_log(doc) == expected

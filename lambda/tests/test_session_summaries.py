from opensearch_lambda_function import update_session_summaries
from fixtures import fake_urlopen

def test_update_session_summaries_merging(fake_urlopen):
    captured = fake_urlopen('update')   # simulate existing session merge

    documents = [
        {'timestamp': 1_600_000_000_000, 'session_id': 's1', 'user': 'u1', 'path': '/a',
         'module': 'mod1', 'assetTypes': ['video'], 'siteTokens': ['site1']},
        {'timestamp': 1_600_000_001_000, 'session_id': 's1', 'user': 'u1', 'path': '/b',
         'module': 'mod2', 'assetTypes': ['image'], 'siteTokens': ['site2']}
    ]

    count = update_session_summaries(documents, 'search.example.com', 'ap-southeast-2')
    assert count == 1

    req = captured['req']
    body_sent = req.data.decode('utf-8')
    for field in ['mod1', 'mod2', 'video', 'image', 'site1', 'site2']:
        assert field in body_sent


def test_update_session_summaries_new_session(fake_urlopen):
    captured = fake_urlopen('created')

    documents = [
        {'timestamp': 1_600_000_000_000, 'session_id': 's2', 'user': 'u2', 'path': '/c',
         'module': 'mod3', 'assetTypes': ['pdf'], 'siteTokens': ['site3']}
    ]

    count = update_session_summaries(documents, 'search.example.com', 'ap-southeast-2')

    assert count == 1
    assert 'mod3' in captured['req'].data.decode()


def test_update_session_summaries_failure(fake_urlopen):
    fake_urlopen('failure')

    documents = [
        {'timestamp': 1_600_000_000_000, 'session_id': 's3', 'user': 'u3', 'path': '/d'}
    ]

    count = update_session_summaries(documents, 'search.example.com', 'ap-southeast-2')
    assert count == 0


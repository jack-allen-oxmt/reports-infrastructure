import json
import gzip
import base64
import re
import os
import boto3
from typing import Optional, Dict, List
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from datetime import datetime

# ---- Constants / Regex ----
NOISE_PATH_PREFIXES = ('/health', '/static/', '/public/', '/ui/v2/_nuxt/', '.locales/')
PAGE_BEACON_PREFIX = '/im_ws/page-beacon'
V2_BODY_REGEX = re.compile(r'V2_BODY:\s*\[(.*?)]\s*$', re.DOTALL)

# ---- SigV4 helpers ----
def _signed_request(method: str, url: str, body: Optional[bytes], headers: dict, region: str) -> Request:
    """
    Build a SigV4-signed urllib Request for Amazon OpenSearch Service.
    """
    session = boto3.Session()
    credentials = session.get_credentials().get_frozen_credentials()
    awsreq = AWSRequest(method=method, url=url, data=body, headers=headers.copy())
    SigV4Auth(credentials, 'es', region).add_auth(awsreq)
    return Request(awsreq.url, data=awsreq.body, headers=dict(awsreq.headers), method=method)

# ---- Lambda handler ----
def lambda_handler(event, context):
    """
    Processes CloudWatch Logs and sends them to OpenSearch.
    Maintains both individual events and session summaries.
    """
    # 0) Input
    if event.get('test_mode'):
        log_data = {'logEvents': event.get('logEvents', [])}
    else:
        payload = base64.b64decode(event['awslogs']['data'])
        log_data = json.loads(gzip.decompress(payload).decode('utf-8'))

    # 1) Config
    endpoint = os.environ.get('OPENSEARCH_ENDPOINT')
    if not endpoint:
        print("ERROR: OPENSEARCH_ENDPOINT environment variable not set")
        return {'statusCode': 500, 'body': 'Missing configuration'}
    region = os.environ.get('AWS_REGION') or os.environ.get('AWS_DEFAULT_REGION') or 'ap-southeast-2'

    # 2) Parse & filter
    documents = []
    for log_event in log_data.get('logEvents', []):
        doc = parse_log_message(log_event)
        if should_include_log(doc):
            documents.append(doc)

    # 3) Send individual events
    events_sent = 0
    if documents:
        events_sent = send_events_to_opensearch(documents, endpoint, region)
        print(f"Successfully sent {events_sent}/{len(documents)} event documents to OpenSearch")

    # 4) Update session summaries
    sessions_updated = 0
    if documents:
        sessions_updated = update_session_summaries(documents, endpoint, region)
        print(f"Successfully updated {sessions_updated} session summaries")

    return {
        'statusCode': 200,
        'body': f'Processed {len(documents)} events, updated {sessions_updated} sessions'
    }

# ---- Parsing helpers (unchanged) ----
def parse_log_message(log_event):
    message = log_event.get('message', '')
    timestamp = log_event.get('timestamp')

    doc = {'timestamp': timestamp, 'raw_message': message}

    def grab(pattern: str):
        m = re.search(pattern, message)
        return m.group(1).strip() if m else None

    session = grab(r'SESSION:\s*\[(.*?)]')
    if session: doc['session_id'] = session

    user = grab(r'USER:\s*\[(.*?)]')
    if user: doc['user'] = user

    path = grab(r'PATH:\s*\[(.*?)]')
    if path: doc['path'] = path

    method = grab(r'REQ_METHOD:\s*\[(.*?)]')
    if method: doc['method'] = method

    status = grab(r'STATUS_CODE:\s*\[(.*?)]')
    if status:
        try:
            doc['status_code'] = int(status)
        except ValueError:
            print(f"Invalid status code: {status}")

    rt = grab(r'RESPONSE[-_]TIME:\s*\[(.*?)]')
    if rt:
        try:
            doc['response_time'] = int(rt)
        except ValueError:
            print(f"Invalid response time: {rt}")

    if 'path' in doc and doc['path'].startswith(PAGE_BEACON_PREFIX):
        suffix = doc['path'][len(PAGE_BEACON_PREFIX):]
        if suffix.startswith('/'):
            suffix = suffix[1:]
        doc['module'] = suffix or '/'

    m = V2_BODY_REGEX.search(message)
    if m:
        try:
            v2_body_json = json.loads(m.group(1).strip())
            asset_types = extract_asset_types(v2_body_json)
            if asset_types: doc['assetTypes'] = asset_types
            site_tokens = extract_site_tokens(v2_body_json)
            if site_tokens: doc['siteTokens'] = site_tokens
        except json.JSONDecodeError as e:
            print(f'Failed to parse V2_BODY JSON: {e}')

    return doc

def extract_asset_types(v2_body):
    asset_types = []
    if isinstance(v2_body, list):
        for item in v2_body:
            if isinstance(item, dict) and 'include' in item:
                s = (item.get('include') or {}).get('assetType', '')
                if s:
                    asset_types.extend([p.strip() for p in s.split(',') if p.strip()])
    elif isinstance(v2_body, dict) and 'include' in v2_body:
        s = (v2_body.get('include') or {}).get('assetType', '')
        if s:
            asset_types.extend([p.strip() for p in s.split(',') if p.strip()])
    return sorted(set(asset_types)) if asset_types else None

def extract_site_tokens(v2_body):
    site_tokens = []
    if isinstance(v2_body, list):
        for item in v2_body:
            if isinstance(item, dict) and 'include' in item:
                s = (item.get('include') or {}).get('siteToken', '')
                if s:
                    site_tokens.extend([p.strip() for p in s.split(',') if p.strip()])
    elif isinstance(v2_body, dict) and 'include' in v2_body:
        s = (v2_body.get('include') or {}).get('siteToken', '')
        if s:
            site_tokens.extend([p.strip() for p in s.split(',') if p.strip()])
    return sorted(set(site_tokens)) if site_tokens else None

def should_include_log(doc):
    user = doc.get('user')
    if not user or user == 'UNAUTHENTICATED' or user == 'canary@oxmt.net':
        return False

    path = doc.get('path')
    if not path:
        return False

    if path.startswith(NOISE_PATH_PREFIXES):
        return False

    if '[HPM]' in doc.get('raw_message', ''):
        return False

    if path.startswith('/im_api/img/') and doc.get('status_code') == 400:
        return False

    return True

# ---- OpenSearch bulk (events) ----
def send_events_to_opensearch(documents, endpoint, region):
    """
    Send individual event documents to daily indices.
    """
    docs_by_date = {}
    for doc in documents:
        ts = (doc.get('timestamp') or 0) / 1000.0
        date_str = datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d')
        docs_by_date.setdefault(date_str, []).append(doc)

    total_success = 0
    for date_str, docs in docs_by_date.items():
        index_name = f'request-events-{date_str}'

        lines = []
        for d in docs:
            d = dict(d)
            d.pop('raw_message', None)
            lines.append(json.dumps({"index": {"_index": index_name}}, separators=(',', ':')))
            lines.append(json.dumps(d, separators=(',', ':')))
        bulk_body = '\n'.join(lines) + '\n'

        url = f'https://{endpoint}/_bulk'
        headers = {'Content-Type': 'application/x-ndjson'}

        try:
            req = _signed_request('POST', url, bulk_body.encode('utf-8'), headers, region)
            with urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode('utf-8'))
            success_count = sum(
                1 for item in result.get('items', [])
                if (item.get('index') or item.get('create') or {}).get('status') in (200, 201)
            )
            total_success += success_count
            print(f"Sent {success_count}/{len(docs)} event documents to index {index_name}")

        except HTTPError as e:
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                body = '<no body>'
            print(f"Error sending events to {index_name}: {e} | body={body}")
            continue
        except URLError as e:
            print(f"Network error sending events to {index_name}: {e}")
            continue

    return total_success

# ---- Session aggregation and upsert ----
def update_session_summaries(documents: List[Dict], endpoint: str, region: str) -> int:
    """
    Group documents by session_id and upsert session summary documents.
    Uses OpenSearch scripted upsert to merge new data with existing sessions.
    """
    # Group events by session
    sessions = {}
    for doc in documents:
        session_id = doc.get('session_id')
        if not session_id:
            continue

        if session_id not in sessions:
            sessions[session_id] = {
                'session_id': session_id,
                'user': doc.get('user'),
                'events': []
            }
        sessions[session_id]['events'].append(doc)

    if not sessions:
        return 0

    # Build upsert operations
    lines = []
    for session_id, session_data in sessions.items():
        events = session_data['events']

        # Extract aggregated data from events
        modules = set()
        paths = set()
        asset_types = set()
        site_tokens = set()
        timestamps = []

        for event in events:
            if event.get('module'):
                modules.add(event['module'])
            if event.get('path'):
                paths.add(event['path'])
            if event.get('assetTypes'):
                asset_types.update(event['assetTypes'])
            if event.get('siteTokens'):
                site_tokens.update(event['siteTokens'])
            if event.get('timestamp'):
                timestamps.append(event['timestamp'])

        # Build the update script
        # This script merges new data with existing session data
        script = {
            "script": {
                "source": """
                    if (ctx._source.containsKey('modules')) {
                        ctx._source.modules.addAll(params.modules);
                    } else {
                        ctx._source.modules = params.modules;
                    }
                    if (ctx._source.containsKey('paths')) {
                        ctx._source.paths.addAll(params.paths);
                    } else {
                        ctx._source.paths = params.paths;
                    }
                    if (ctx._source.containsKey('assetTypes')) {
                        ctx._source.assetTypes.addAll(params.assetTypes);
                    } else {
                        ctx._source.assetTypes = params.assetTypes;
                    }
                    if (ctx._source.containsKey('siteTokens')) {
                        ctx._source.siteTokens.addAll(params.siteTokens);
                    } else {
                        ctx._source.siteTokens = params.siteTokens;
                    }
                    ctx._source.start_time = Math.min(ctx._source.start_time, params.min_timestamp);
                    ctx._source.end_time = Math.max(ctx._source.end_time, params.max_timestamp);
                    ctx._source.event_count += params.new_event_count;
                    ctx._source.duration_seconds = (ctx._source.end_time - ctx._source.start_time) / 1000;
                    ctx._source.last_updated = params.last_updated;
                """,
                "params": {
                    "modules": sorted(list(modules)),
                    "paths": sorted(list(paths)),
                    "assetTypes": sorted(list(asset_types)),
                    "siteTokens": sorted(list(site_tokens)),
                    "min_timestamp": min(timestamps) if timestamps else 0,
                    "max_timestamp": max(timestamps) if timestamps else 0,
                    "new_event_count": len(events),
                    "last_updated": int(datetime.utcnow().timestamp() * 1000)
                },
                "lang": "painless"
            },
            "upsert": {
                "session_id": session_id,
                "user": session_data['user'],
                "modules": sorted(list(modules)),
                "paths": sorted(list(paths)),
                "assetTypes": sorted(list(asset_types)),
                "siteTokens": sorted(list(site_tokens)),
                "start_time": min(timestamps) if timestamps else 0,
                "end_time": max(timestamps) if timestamps else 0,
                "event_count": len(events),
                "duration_seconds": (max(timestamps) - min(timestamps)) / 1000 if timestamps else 0,
                "last_updated": int(datetime.utcnow().timestamp() * 1000)
            }
        }

        # Add to bulk operations
        lines.append(json.dumps({
            "update": {
                "_index": "session-summaries",
                "_id": session_id
            }
        }, separators=(',', ':')))
        lines.append(json.dumps(script, separators=(',', ':')))

    bulk_body = '\n'.join(lines) + '\n'

    # Send to OpenSearch
    url = f'https://{endpoint}/_bulk'
    headers = {'Content-Type': 'application/x-ndjson'}

    try:
        req = _signed_request('POST', url, bulk_body.encode('utf-8'), headers, region)
        with urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode('utf-8'))

        success_count = sum(
            1 for item in result.get('items', [])
            if (item.get('update') or {}).get('status') in (200, 201)
        )

        print(f"Updated {success_count}/{len(sessions)} session summaries")
        return success_count

    except HTTPError as e:
        try:
            body = e.read().decode('utf-8', errors='replace')
        except Exception:
            body = '<no body>'
        print(f"Error updating session summaries: {e} | body={body}")
        return 0
    except URLError as e:
        print(f"Network error updating session summaries: {e}")
        return 0
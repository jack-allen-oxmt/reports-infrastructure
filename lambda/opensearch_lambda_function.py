import json
import gzip
import base64
import re
import os
import boto3
from typing import Optional
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

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

def _debug_authinfo(endpoint: str, region: str):
    """
    GET /_plugins/_security/authinfo to see how OpenSearch identifies this caller.
    """
    url = f'https://{endpoint}/_plugins/_security/authinfo'
    req = _signed_request('GET', url, None, {}, region)
    with urlopen(req, timeout=10) as resp:
        print('AUTHINFO:', resp.read().decode('utf-8', errors='replace'))

# ---- Lambda handler ----
def lambda_handler(event, context):
    """
    Processes CloudWatch Logs and sends them to OpenSearch
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

    # Optional: print how OpenSearch sees this caller
    if event.get('debug_authinfo'):
        try:
            _debug_authinfo(endpoint, region)
        except Exception as e:
            print('AUTHINFO probe failed:', e)

    # 2) Parse & filter
    documents = []
    for log_event in log_data.get('logEvents', []):
        doc = parse_log_message(log_event)
        if should_include_log(doc):
            documents.append(doc)

    # 3) Send
    sent = 0
    if documents:
        sent = send_to_opensearch(documents, endpoint, region)
        print(f"Successfully sent {sent}/{len(documents)} documents to OpenSearch")
    else:
        print("No documents to send after filtering")

    return {'statusCode': 200, 'body': f'Processed {len(documents)} logs'}

# ---- Parsing helpers ----
def parse_log_message(log_event):
    message = log_event.get('message', '')
    timestamp = log_event.get('timestamp')

    doc = {'timestamp': timestamp, 'raw_message': message}

    def grab(pattern: str):
        m = re.search(pattern, message)
        return m.group(1).strip() if m else None

    # Extract fields
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

    # RESPONSE-TIME or RESPONSE_TIME
    rt = grab(r'RESPONSE[-_]TIME:\s*\[(.*?)]')
    if rt:
        try:
            doc['response_time'] = int(rt)
        except ValueError:
            print(f"Invalid response time: {rt}")

    # Page-beacon module: slice known prefix
    if 'path' in doc and doc['path'].startswith(PAGE_BEACON_PREFIX):
        suffix = doc['path'][len(PAGE_BEACON_PREFIX):]  # keep nested segments
        if suffix.startswith('/'):
            suffix = suffix[1:]
        doc['module'] = suffix or '/'

    # V2_BODY (may be multiline)
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

# ---- OpenSearch bulk ----
def send_to_opensearch(documents, endpoint, region):
    """
    Send documents to OpenSearch via bulk API using IAM authentication.
    Groups by event date so each day gets its own index.
    """
    from datetime import datetime

    docs_by_date = {}
    for doc in documents:
        ts = (doc.get('timestamp') or 0) / 1000.0
        date_str = datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d')
        docs_by_date.setdefault(date_str, []).append(doc)

    total_success = 0
    for date_str, docs in docs_by_date.items():
        index_name = f'request-events-{date_str}'

        # Bulk NDJSON
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
            print(f"Sent {success_count}/{len(docs)} documents to index {index_name}")

        except HTTPError as e:
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                body = '<no body>'
            print(f"Error sending to OpenSearch index {index_name}: {e} | body={body}")
            continue
        except URLError as e:
            print(f"Network error sending to OpenSearch index {index_name}: {e}")
            continue

    return total_success

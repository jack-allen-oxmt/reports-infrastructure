import json
import gzip
import base64
import re
import os
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

def lambda_handler(event, context):
    """
    Processes CloudWatch Logs and sends them to OpenSearch

    Args:
        event: The event data from CloudWatch Logs (dict)
        context: Lambda execution content (contains runtime info)

    Returns:
        dict: Status code and message
    """

    # Step 1: Decode the compressed CloudWatch data
    payload = base64.b64decode(event['awslogs']['data'])
    log_data = json.loads(gzip.decompress(payload).decode('utf-8'))

    # Step 2: Get OpenSearch configuration
    opensearch_endpoint = os.environ.get('OPENSEARCH_ENDPOINT')
    if not opensearch_endpoint:
        print("ERROR: OPENSEARCH_ENDPOINT environment variable not set")
        return {'statusCode': 500, 'body': 'Missing configuration'}

    # Step 3: Parse and filter log events
    documents = []
    for log_event in log_data['logEvents']:
        doc = parse_log_message(log_event)

        if should_include_log(doc):
            documents.append(doc)

    # Step 4: Send batch to OpenSearch
    if documents:
        success_count = send_to_opensearch(documents, opensearch_endpoint)
        print(f"Successfully sent {success_count}/{len(documents)} documents to OpenSearch")
    else:
        print("No documents to send after filtering")

    return {'statusCode': 200, 'body': f'Processed {len(documents)} logs'}

def parse_log_message(log_event):
    """
    Parse a single log message and extract fields.
    """
    message = log_event['message']
    timestamp = log_event['timestamp']

    # Extract fields
    doc = {
        'timestamp': timestamp,
        'raw_message': message # Debugging purposes
    }

    # Extract SESSION
    session_match = re.search(r'SESSION: \[(.*?)]', message)
    if session_match:
        doc['session_id'] = session_match.group(1)

    # Extract USER
    user_match = re.search(r'USER: \[(.*?)]', message)
    if user_match:
        doc['user'] = user_match.group(1)

    # Extract PATH
    path_match = re.search(r'PATH: \[(.*?)]', message)
    if path_match:
        doc['path'] = path_match.group(1)

    # Extract REQ_METHOD
    method_match = re.search(r'REQ_METHOD: \[(.*?)]', message)
    if method_match:
        doc['method'] = method_match.group(1)

    # Extract STATUS_CODE
    status_match = re.search(r'STATUS_CODE: \[(.*?)]', message)
    if status_match:
        try:
            doc['status_code'] = int(status_match.group(1))
        except ValueError:
            print(f"Invalid status code: {status_match.group(1)}")

    # Extract RESPONSE_TIME
    response_time_match = re.search(r'RESPONSE-TIME: \[(.*?)]', message)
    if response_time_match:
        try:
            doc['response_time'] = int(response_time_match.group(1))
        except ValueError:
            print(f"Invalid response time: {response_time_match.group(1)}")

    # Extract module from page-beacon paths
    if 'path' in doc and doc['path'].startswith('/im_ws/page-beacon/'):
        doc['module'] = doc['path'].split('/')[-1]

    # Extract V2_BODY and parse JSON
    v2_body_match = re.search(r'V2_BODY: \[(.*)]$', message)
    if v2_body_match:
        try:
            v2_body_json = json.loads(v2_body_match.group(1))

            # Extract assetTypes
            asset_types = extract_asset_types(v2_body_json)
            if asset_types:
                doc['assetTypes'] = asset_types

            # Extract siteTokens
            site_tokens = extract_site_tokens(v2_body_json)
            if site_tokens:
                doc['siteTokens'] = site_tokens

        except json.JSONDecodeError as e:
            print(f'Failed to parse V2_BODY JSON: {e}')

    return doc


def extract_asset_types(v2_body):
    """
    Extract assetTypes from V2_BODY JSON structure
    """
    asset_types = []

    # V2 BODY can be a list or dict, handle both cases - todo: verify this?
    if isinstance(v2_body, list):
        for item in v2_body:
            if isinstance(item, dict) and 'include' in item:
                asset_type_str: str = item['include'].get('assetType', '')
                if asset_type_str:
                    # assetType is comma-seperated string
                    asset_types.extend(asset_type_str.split(','))
    elif isinstance(v2_body, dict) and 'include' in v2_body:
        asset_type_str: str = v2_body['include'].get('assetType', '')
        if asset_type_str:
            asset_types.extend(asset_type_str.split(','))

    return list(set(asset_types)) if asset_types else None


def extract_site_tokens(v2_body):
    """
    Extract siteTokens from V2_BODY JSON structure
    """
    site_tokens = []

    # V2_BODY can be a list or dict, handle both
    if isinstance(v2_body, list):
        for item in v2_body:
            if isinstance(item, dict) and 'include' in item:
                site_token_str = item['include'].get('siteToken', '')
                if site_token_str:
                    # siteToken is comma-separated string
                    site_tokens.extend(site_token_str.split(','))
    elif isinstance(v2_body, dict) and 'include' in v2_body:
        site_token_str = v2_body['include'].get('siteToken', '')
        if site_token_str:
            site_tokens.extend(site_token_str.split(','))

    # Return unique values
    return list(set(site_tokens)) if site_tokens else None


def should_include_log(doc):
    """
    Filter logic - return True if log should be included
    """
    # Must have user
    if 'user' not in doc:
        return False

    # Filter out UNAUTHENTICATED
    if doc['user'] == 'UNAUTHENTICATED':
        return False

    # Filter out canary
    if doc['user'] == 'canary@oxmt.net':
        return False

    # Must have a path
    if 'path' not in doc:
        return False

    path = doc['path']

    # Filter out noise path
    noise_paths = ['/health', '/static/', '/public/', '/ui/v2/_nuxt/', '.locales/']
    if any(path.startswith(noise_path) for noise_path in noise_paths):
        return False

    # Filter out HPM proxy logs
    if '[HPM]' in doc.get('raw_message', ''):
        return False

    # Filter out failed image requests
    if path.startswith('/im_api/img/') and doc.get('status_code') == 400:
        return False

    return True


def send_to_opensearch(documents, endpoint):
    """
    Send documents to OpenSearch via bulk API
    Groups documents by date to ensure they land in the correct daily index
    """
    from datetime import datetime

    # Group documents by their event date (not current date)
    docs_by_date = {}
    for doc in documents:
        # Convert milliseconds timestamp to datetime
        event_date = datetime.utcfromtimestamp(doc['timestamp'] / 1000.0)
        date_str = event_date.strftime('%Y-%m-%d')

        if date_str not in docs_by_date:
            docs_by_date[date_str] = []
        docs_by_date[date_str].append(doc)

    # Send documents to their respective daily indices
    total_success = 0

    for date_str, docs in docs_by_date.items():
        index_name = f'request-events-{date_str}'

        # Build bulk request body
        bulk_data = []
        for doc in docs:
            # Remove raw_message before indexing (was for debugging only)
            doc.pop('raw_message', None)

            # Index action
            bulk_data.append(json.dumps({"index": {"_index": index_name}}))
            # Document
            bulk_data.append(json.dumps(doc))

        bulk_body = '\n'.join(bulk_data) + '\n'

        # Send to OpenSearch
        url = f'https://{endpoint}/_bulk'
        headers = {
            'Content-Type': 'application/x-ndjson'
        }

        try:
            request = Request(url, data=bulk_body.encode('utf-8'), headers=headers, method='POST')
            response = urlopen(request, timeout=10)  # 10 second timeout
            result = json.loads(response.read().decode('utf-8'))

            # Count successes
            success_count = sum(1 for item in result.get('items', []) if item.get('index', {}).get('status') in [200, 201])
            total_success += success_count

            print(f"Sent {success_count}/{len(docs)} documents to index {index_name}")

        except (URLError, HTTPError) as e:
            print(f"Error sending to OpenSearch index {index_name}: {e}")
            continue

    return total_success
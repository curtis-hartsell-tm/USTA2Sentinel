import requests
import json
import uuid
from datetime import datetime
import time
import logging

# Set up logging
logging.basicConfig(filename='/root/prodaft/indicator_upload.log', level=logging.INFO, 
                    format='%(asctime)s:%(levelname)s:%(message)s')

def get_azure_token(tenant_id, client_id, client_secret):
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://management.azure.com/.default'
    }
    response = requests.post(url, data=data)
    if response.status_code == 200:
        access_token = response.json().get('access_token')
        logging.info("Access Token retrieved successfully.")
        return access_token
    else:
        logging.error(f"Failed to retrieve access token: {response.text}")
        return None

def format_indicator_url(url_entry, uuid_str=None):
    current_time = datetime.utcnow().isoformat() + "Z"
    indicator_id = f"indicator--{uuid_str if uuid_str else uuid.uuid4()}"
    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": current_time,
        "modified": current_time,
        "name": f"URL Threat Indicator for {url_entry.get('domain', 'Unknown domain')}",
        "description": f"Threat type: {url_entry.get('threat_type', 'N/A')}. Tags: {', '.join(url_entry.get('tags', []))}",
        "pattern": f"[url:value = '{url_entry['url']}']",
        "pattern_type": "stix",
        "valid_from": current_time,
        "labels": url_entry.get('tags', []),
        "indicator_types": ["malicious-activity"],
        "external_references": [{"source_name": "PRODAFT", "url": url_entry['url']}]
    }
    logging.info(f"Formatted URL indicator for {url_entry['url']}")
    return indicator

def format_indicator_hash(hash_entry, uuid_str=None):
    current_time = datetime.utcnow().isoformat() + "Z"
    indicator_id = f"indicator--{uuid_str if uuid_str else uuid.uuid4()}"
    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": current_time,
        "modified": current_time,
        "name": "Malware Hash Indicator",
        "pattern": f"[file:hashes.MD5 = '{hash_entry['md5']}' OR file:hashes.SHA1 = '{hash_entry['sha1']}' OR file:hashes.SHA256 = '{hash_entry['sha256']}']",
        "pattern_type": "stix",
        "valid_from": current_time,
        "labels": hash_entry.get('tags', []),
        "indicator_types": ["malicious-code"]
    }
    logging.info(f"Formatted hash indicator for MD5: {hash_entry['md5']}")
    return indicator

def chunked(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def upload_indicators(workspace_id, token, indicators):
    url = f"https://sentinelus.azure-api.net/{workspace_id}/threatintelligence:upload-indicators?api-version=2022-07-01"
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    responses = []
    chunks = list(chunked(indicators, 100))
    for i, chunk in enumerate(chunks):
        body = {
            "sourcesystem": "PRODAFT",
            "value": chunk
        }
        response = requests.post(url, headers=headers, json=body)
        responses.append(response)
        logging.info(f"Batch {i+1} upload response: {response.status_code}")
        if i % 99 == 98:
            logging.info("Rate limit approaching, pausing for 60 seconds...")
            time.sleep(60)
    return responses

def check_and_log(indicator, log_path='/root/prodaft/uploaded_indicators.log'):
    try:
        with open(log_path, 'r+') as file:
            existing_indicators = file.read().splitlines()
            if indicator['pattern'] in existing_indicators:
                logging.info(f"Duplicate indicator found: {indicator['pattern']}")
                return False
            else:
                file.write(indicator['pattern'] + "\n")
                return True
    except FileNotFoundError:
        with open(log_path, 'w') as file:
            file.write(indicator['pattern'] + "\n")
        return True

def fetch_iocs(base_url, api_token, tenant_id, client_id, client_secret, workspace_id):
    azure_token = get_azure_token(tenant_id, client_id, client_secret)
    if not azure_token:
        logging.error("Failed to fetch Azure token. Exiting script.")
        return
    headers = {'Authorization': f'Token {api_token}'}
    indicators = []

    url_malicious_urls = f"{base_url}/threat-stream/malicious-urls"
    response_urls = requests.get(url_malicious_urls, headers=headers)
    if response_urls.status_code == 200:
        urls_data = response_urls.json()
        for url in urls_data:
            indicator = format_indicator_url(url)
            if check_and_log(indicator):
                indicators.append(indicator)

    url_malware_hashes = f"{base_url}/threat-stream/malware-hashs"
    response_hashes = requests.get(url_malware_hashes, headers=headers)
    if response_hashes.status_code == 200:
        hashes_data = response_hashes.json()
        for hash in hashes_data:
            indicator = format_indicator_hash(hash)
            if check_and_log(indicator):
                indicators.append(indicator)

    if indicators:
        upload_responses = upload_indicators(workspace_id, azure_token, indicators)
        for response in upload_responses:
            logging.info(f"Upload response status: {response.status_code}")

# Example usage
tenant_id = 'YOUR-AZURE-TENANT-ID'
client_id = 'YOUR-AZURE-CLIENT-ID'
client_secret = 'YOUR-AZURE-CLIENT-SECRET'
workspace_id = 'YOUR-AZURE-WORKSPACE-ID'
base_url = "https://usta.prodaft.com/api"
api_token = "YOUR-PRODAFT-API-KEY"

fetch_iocs(base_url, api_token, tenant_id, client_id, client_secret, workspace_id)

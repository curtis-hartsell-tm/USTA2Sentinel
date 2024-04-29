# USTA2Sentinel
This script runs from TMNA CTI's Sentinel-IOC-Feeder.

## Overview
This script automates the process of fetching threat indicators from PRODAFT's external API and uploads them to Azure Sentinel. It handles indicators such as URLs and malware hashes and checks for duplicates before uploading to ensure that only new indicators are submitted.

## Features
- Fetches URL and hash indicators from the PRODAFT API.
- Checks for duplicate indicators using a local log file.
- Uploads new indicators to Azure Sentinel.
- Logs all operations, including duplicate detections and upload results.

## Prerequisites
- Python 3
- `requests` library
- Access to Azure Sentinel API
- Valid credentials for the PRODAFT API and Azure Sentinel

## Setup
1. Ensure Python 3 is installed on your system.
2. Install the `requests` module using pip:
   ```bash
   pip install requests
   ```
3. Configure the script with your Azure and PRODAFT API credentials. This includes `tenant_id`, `client_id`, `client_secret`, `workspace_id`, and `api_token`.

## Configuration
Edit the script to include your API credentials and workspace details:
- `tenant_id`: Your Azure tenant ID.
- `client_id`: Your Azure client ID.
- `client_secret`: Your Azure client secret.
- `workspace_id`: Your Azure Sentinel workspace ID.
- `base_url`: The base URL for the PRODAFT API.
- `api_token`: Your PRODAFT API key.

## Usage
Run the script manually or set it up as a cron job to run at regular intervals:
```bash
*/30 * * * * /usr/bin/python3 /path/to/script.py
```

## Logging
- The script logs its operations to `/root/prodaft/indicator_upload.log`.
- Uploaded indicators and detected duplicates are logged to `/root/prodaft/uploaded_indicators.log`.

## Notes
- Ensure the log file paths in the script are correct and accessible.
- Adjust the frequency of the cron job as needed based on your operational requirements.
- Create or utilize a registered application within Azure Sentinel and ensure the Object ID has the necessary permissions of `Microsoft Sentinel Contributor` and `Microsoft Sentinel Reader`.

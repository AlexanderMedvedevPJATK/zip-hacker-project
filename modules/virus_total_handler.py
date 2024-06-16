import logging
import requests

logger = logging.getLogger(__name__)
api_key = "3a26fa55935280f9489a2a0f511f627261a011e70ca46b05ca9384195bd7149f"
headers = {
    "x-apikey": api_key
}


def verify_checksum(checksum):
    logger.info(f"Verifying checksum with VirusTotal")
    url = f"https://www.virustotal.com/api/v3/files/{checksum}"
    response = requests.get(url, headers=headers)

    json_response = response.json()
    if response.status_code == 200:
        malicious_count = json_response["data"]["attributes"]["last_analysis_stats"]["malicious"]
        filename = json_response["data"]["attributes"]["meaningful_name"]
        message = f"not considered malicious"
        if malicious_count > 0:
            message = f"considered malicious by {malicious_count} {'engine' if malicious_count == 1 else 'engines'}"
            logger.warning(f"File: {filename} is {message}")
        else:
            logger.info(f"File: {filename} is {message}")

        return message
    else:
        logger.error(f"An error occurred: {json_response['error']['message']}")

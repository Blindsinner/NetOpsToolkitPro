# -*- coding: utf-8 -*-
import logging
from typing import Dict, Any
import httpx

class ThreatIntel:
    """Handles lookups against external threat intelligence APIs."""

    def __init__(self):
        self.base_url = "https://api.abuseipdb.com/api/v2/check"

    async def query_abuseipdb(self, ip_address: str, api_key: str) -> Dict[str, Any]:
        """Queries the AbuseIPDB API for a given IP address."""
        if not api_key:
            return {"error": "AbuseIPDB API key is missing."}

        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90'
        }
        
        logging.info(f"Querying AbuseIPDB for IP: {ip_address}")
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.base_url, headers=headers, params=params, timeout=15)
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as e:
            logging.error(f"AbuseIPDB API error: {e.response.status_code} - {e.response.text}")
            error_data = e.response.json()
            error_detail = error_data.get('errors', [{}])[0].get('detail', 'Unknown API error')
            return {"error": f"API Error ({e.response.status_code}): {error_detail}"}
        except httpx.RequestError as e:
            logging.error(f"AbuseIPDB request error: {e}")
            return {"error": f"Request failed: {e}"}
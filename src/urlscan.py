

import requests
from src.utils import get_domain
from src.config import URLSCAN_API_KEY, URLSCAN_TIMEOUT

def check_urlscan(url):
    domain = get_domain(url)

    if not domain:
        return {
            "available": False,
            "malicious": None,
            "results_found": 0,
            "error": "Could not extract domain"
        }

    if not URLSCAN_API_KEY:
        return {
            "available": False,
            "malicious": None,
            "results_found": 0,
            "error": "URLSCAN_API_KEY not configured"
        }

    endpoint = "https://urlscan.io/api/v1/search/"
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }
    params = {
        "q": f"domain:{domain}",
        "size": 10
    }

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            params=params,
            timeout=URLSCAN_TIMEOUT
        )

        if response.status_code in [401, 403]:
            return {
                "available": False,
                "malicious": None,
                "results_found": 0,
                "error": "Invalid or unauthorized urlscan.io API Key"
            }
        
        if response.status_code == 429:
             return {
                "available": False,
                "malicious": None,
                "results_found": 0,
                "error": "urlscan.io API rate limit exceeded"
            }

        if response.status_code != 200:
            return {
                "available": False,
                "malicious": None,
                "results_found": 0,
                "error": f"urlscan API error: {response.status_code}"
            }

        data = response.json()
        results = data.get("results", [])
        malicious = False

        for result in results:
            verdicts = result.get("verdicts", {})
            overall = verdicts.get("overall", {})
            if overall.get("malicious", False):
                malicious = True
                break

        return {
            "available": True,
            "malicious": malicious,
            "results_found": len(results),
            "error": None
        }

    except requests.exceptions.Timeout:
        return {
            "available": False,
            "malicious": None,
            "results_found": 0,
            "error": "urlscan request timed out"
        }
    except requests.exceptions.RequestException as e:
        return {
            "available": False,
            "malicious": None,
            "results_found": 0,
            "error": f"Connection error: {str(e)}"
        }
    except Exception as e:
        return {
            "available": False,
            "malicious": None,
            "results_found": 0,
            "error": str(e)
        }

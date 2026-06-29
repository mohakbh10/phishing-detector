

import os
import requests

from src.utils import get_domain

# ============================================================
# URLSCAN CONFIG
# ============================================================

API_KEY = os.environ.get("URLSCAN_API_KEY")

# ============================================================
# URLSCAN CHECK
# ============================================================

def check_urlscan(url):

    domain = get_domain(url)

    # If domain extraction fails
    if not domain:

        return {
            "available": False,
            "malicious": None,
            "results_found": 0,
            "error": "Could not extract domain"
        }
    if not API_KEY:
        return {
            "available": False,
            "malicious": None,
            "results_found": 0,
            "error": "URLSCAN_API_KEY not set in environment"
        }
    
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    headers = {
        "API-Key": API_KEY
    }

    params = {
        "q": f"domain:{domain}"
    }

    try:

        response = requests.get(
            endpoint,
            headers=headers,
            params=params,
            timeout=5
        )

        # API failure
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

        # Check every result
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

    except requests.exceptions.ConnectionError:

        return {
            "available": False,
            "malicious": None,
            "results_found": 0,
            "error": "Could not connect to urlscan"
        }

    except Exception as e:

        return {
            "available": False,
            "malicious": None,
            "results_found": 0,
            "error": str(e)
        }
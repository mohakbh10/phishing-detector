import requests

def check_phishtank(url):

    api_url = "https://checkurl.phishtank.com/checkurl/"

    data = {
        "url": url,
        "format": "json"
    }

    headers = {
        "User-Agent": "phishtank-test"
    }

    try:
        response = requests.post(api_url, data=data, headers=headers)

        if response.status_code != 200:
            return {
                "found": False,
                "verified": False,
                "error": "PhishTank request failed"
            }

        result = response.json()

        in_database = result["results"]["in_database"]
        verified = result["results"]["verified"]
        return {
            "available": True,
            "found": in_database,
            "verified": verified,
            "error": None
        }

    except Exception as e:
        return {
            "available": False,
            "found": None,
            "verified": None,
            "error": "PhishTank unavailable"
        }
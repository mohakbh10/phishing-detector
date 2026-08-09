import requests
from urllib.parse import urljoin
from src.config import REDIRECT_MAX_HOPS, REDIRECT_TIMEOUT

def get_redirect_chain(url, max_hops=REDIRECT_MAX_HOPS):
    chain = [url]
    current_url = url
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        for _ in range(max_hops):
            try:
                response = requests.head(
                    current_url,
                    allow_redirects=False,
                    timeout=REDIRECT_TIMEOUT,
                    headers=headers
                )
                # If HEAD fails or is not allowed, try GET but only for headers
                if response.status_code == 405:
                     response = requests.get(
                        current_url,
                        allow_redirects=False,
                        timeout=REDIRECT_TIMEOUT,
                        headers=headers,
                        stream=True
                    )
            except requests.exceptions.RequestException:
                break

            if response.status_code not in [301, 302, 303, 307, 308]:
                break

            next_url = response.headers.get("Location")
            if not next_url:
                break

            # Handle relative URLs
            next_url = urljoin(current_url, next_url)
            
            if next_url in chain: # Avoid infinite loops
                break
                
            chain.append(next_url)
            current_url = next_url

        return chain, None

    except Exception as e:
        return chain, f"Redirect analysis interrupted: {str(e)}"


from urllib.parse import urljoin
import requests
from src.config import REDIRECT_MAX_HOPS, REDIRECT_TIMEOUT
from src.utils import get_domain

def get_redirect_chain(url, max_hops=REDIRECT_MAX_HOPS):
    chain = [url]
    if not get_domain(url): return chain, "Malformed or unsupported URL"
    current = url
    try:
        for _ in range(max(0, max_hops)):
            try:
                response = requests.head(current, allow_redirects=False, timeout=REDIRECT_TIMEOUT, headers={"User-Agent":"PhishingDetector/1.0"})
                if response.status_code in (405, 501): response = requests.get(current, allow_redirects=False, timeout=REDIRECT_TIMEOUT, headers={"User-Agent":"PhishingDetector/1.0"}, stream=True)
            except requests.RequestException as exc:
                return chain, f"Redirect request failed: {exc.__class__.__name__}"
            if response.status_code not in (301, 302, 303, 307, 308): return chain, None
            location = response.headers.get("Location")
            if not location: return chain, "Redirect response missing Location header"
            next_url = urljoin(current, location)
            if not get_domain(next_url): return chain, "Redirect location is malformed"
            if next_url in chain: return chain, "Redirect loop detected"
            chain.append(next_url); current = next_url
        return chain, "Redirect hop limit reached"
    except Exception as exc:
        return chain, f"Redirect analysis failed: {exc.__class__.__name__}"

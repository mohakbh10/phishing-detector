import re
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

def extract_urls(text):
    if not isinstance(text, str):
        return []
    seen, result = set(), []
    for value in URL_RE.findall(text):
        value = value.rstrip(".,!?;:)]}")
        if value and value not in seen:
            seen.add(value); result.append(value)
    return result

def get_domain(url):
    if not isinstance(url, str) or not url.strip():
        return ""
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme not in {"http", "https"}:
            return ""
        return (parsed.hostname or "").lower().rstrip(".")
    except (ValueError, TypeError):
        return ""

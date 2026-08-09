import re
from urllib.parse import urlparse

def extract_urls(text):
    """
    Extracts URLs from text.
    Handles both plain text and basic HTML.
    """
    if not text:
        return []
    
    # Improved regex for URLs
    pattern = r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(pattern, text)
    
    # Basic cleaning - remove trailing punctuation that might be part of a sentence but not the URL
    cleaned_urls = []
    for url in urls:
        while url and url[-1] in '.,!?;:)':
            url = url[:-1]
        if url:
            cleaned_urls.append(url)
            
    return list(set(cleaned_urls))

def get_domain(url):
    """
    Extracts the domain from a URL.
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if not domain:
            # Fallback for URLs that urlparse might struggle with if they are malformed but have a domain
            match = re.search(r'https?://(?:www\.)?([^\s/:?#]+)', url)
            if match:
                domain = match.group(1).lower()
        
        # Remove port
        domain = domain.split(':')[0]
        return domain
    except Exception:
        return ""


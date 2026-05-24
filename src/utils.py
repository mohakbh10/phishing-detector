import re

def extract_urls(text):
    pattern = r'https?://[^\s]+'
    return re.findall(pattern, text)

def get_domain(url):
    match = re.search(r'https?://([^\s/]+)', url)
    if match:
        return match.group(1)
    return ""
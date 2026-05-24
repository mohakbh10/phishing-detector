from src.utils import get_domain
from src.config import WHITELISTED_DOMAINS

def is_whitelisted(url):
    domain = get_domain(url)

    if not domain:
        return False, None

    domain = domain.split(':')[0]

    for trusted in WHITELISTED_DOMAINS:
        if domain == trusted or domain.endswith('.' + trusted):
            return True, trusted

    return False, None
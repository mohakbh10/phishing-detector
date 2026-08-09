from src.utils import get_domain
from src.config import WHITELISTED_DOMAINS

def is_whitelisted(url):
    domain = get_domain(url)

    if not domain:
        return False, None

    # Handle port in domain
    domain = domain.split(':')[0]

    for trusted in WHITELISTED_DOMAINS:
        # Secure matching: exactly the domain or a subdomain
        if domain == trusted or domain.endswith('.' + trusted):
            return True, trusted

    return False, None

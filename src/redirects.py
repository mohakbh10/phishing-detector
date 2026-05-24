import requests

def get_redirect_chain(url, max_hops=10):

    chain = [url]
    current_url = url

    headers = {
        'User-Agent': 'Mozilla/5.0'
    }

    try:
        for _ in range(max_hops):

            response = requests.get(
                current_url,
                allow_redirects=False,
                timeout=5,
                headers=headers
            )

            if response.status_code not in [301, 302, 303, 307, 308]:
                break

            next_url = response.headers.get("Location")

            if not next_url:
                break

            chain.append(next_url)
            current_url = next_url

        return chain, None

    except Exception:
        return chain, "Could not resolve or reach domain"
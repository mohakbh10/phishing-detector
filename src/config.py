"""Central configuration. Secrets are read only from the environment."""
import os
from pathlib import Path


def _load_project_env() -> None:
    """Load simple root .env values without replacing real environment settings."""
    env_file = Path(__file__).resolve().parents[1] / ".env"
    try:
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key:
                os.environ.setdefault(key, value)
    except OSError:
        pass


_load_project_env()

WHITELISTED_DOMAINS = ("google.com", "github.com", "stackoverflow.com", "amazon.com", "paypal.com", "linkedin.com", "reddit.com", "microsoft.com", "apple.com", "netflix.com", "facebook.com", "twitter.com", "instagram.com")
HIGH_RISK_KEYWORDS = ("verify", "confirm", "suspend", "billing", "invoice", "password", "signin")
MEDIUM_RISK_KEYWORDS = ("account", "update", "secure", "alert", "notice", "banking", "payment", "login")
SUSPICIOUS_TLDS = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw", ".loan", ".click", ".zip")
SUSPICIOUS_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".zip", ".rar", ".iso", ".img", ".docm", ".xlsm", ".jar", ".msi"}
REDIRECT_MAX_HOPS = int(os.getenv("REDIRECT_MAX_HOPS", "8"))
REDIRECT_TIMEOUT = float(os.getenv("REDIRECT_TIMEOUT", "3"))
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
GOOGLE_SAFE_BROWSING_TIMEOUT = float(os.getenv("GOOGLE_SAFE_BROWSING_TIMEOUT", "5"))

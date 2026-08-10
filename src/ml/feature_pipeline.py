"""Single URL-only feature contract for training and inference.

Excluded PhiUSIIL fields include URL/Domain/TLD strings (identifiers), URL similarity
and TLD probability (dataset-derived / not reproducible), and all page-content,
redirect, form, DOM, title, and resource-count fields because production receives
only a raw URL. Label is excluded as the target.
"""
import ipaddress, re
from urllib.parse import urlparse
import pandas as pd

FEATURE_NAMES=("URLLength","DomainLength","IsDomainIP","TLDLength","NoOfSubDomain","HasObfuscation","NoOfObfuscatedChar","ObfuscationRatio","NoOfLettersInURL","LetterRatioInURL","NoOfDegitsInURL","DegitRatioInURL","NoOfEqualsInURL","NoOfQMarkInURL","NoOfAmpersandInURL","NoOfOtherSpecialCharsInURL","SpacialCharRatioInURL","IsHTTPS")

def url_features(url):
    raw=url if isinstance(url,str) else ""
    parsed=urlparse(raw); domain=(parsed.hostname or "").lower()
    try: is_ip=int(bool(domain) and ipaddress.ip_address(domain) is not None)
    except ValueError: is_ip=0
    path_query=(parsed.path or "") + (("?"+parsed.query) if parsed.query else "")
    letters=sum(c.isalpha() for c in raw); digits=sum(c.isdigit() for c in raw)
    special=sum(not c.isalnum() for c in raw)
    encoded=len(re.findall(r"%[0-9a-fA-F]{2}",raw))
    length=max(len(raw),1); labels=[x for x in domain.split(".") if x]
    tld=labels[-1] if labels else ""
    return {"URLLength":len(raw),"DomainLength":len(domain),"IsDomainIP":is_ip,"TLDLength":len(tld),"NoOfSubDomain":max(0,len(labels)-2),"HasObfuscation":int(encoded>0 or "@" in raw),"NoOfObfuscatedChar":encoded,"ObfuscationRatio":round(encoded/length,6),"NoOfLettersInURL":letters,"LetterRatioInURL":round(letters/length,6),"NoOfDegitsInURL":digits,"DegitRatioInURL":round(digits/length,6),"NoOfEqualsInURL":raw.count("="),"NoOfQMarkInURL":raw.count("?"),"NoOfAmpersandInURL":raw.count("&"),"NoOfOtherSpecialCharsInURL":special,"SpacialCharRatioInURL":round(special/length,6),"IsHTTPS":int(parsed.scheme.lower()=="https")}

def feature_frame(urls): return pd.DataFrame([url_features(url) for url in urls],columns=FEATURE_NAMES)

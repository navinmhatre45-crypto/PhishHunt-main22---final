# feature_extractor.py
import re
from urllib.parse import urlparse
import tldextract

IP_PATTERN = re.compile(r'^(?:http[s]?://)?\d{1,3}(?:\.\d{1,3}){3}(:\d+)?(?:/|$)')
SUSPICIOUS_TOKENS = ['login', 'secure', 'update', 'verify', 'account', 'signin', 'bank', 'confirm', 'ebay', 'paypal']

def extract_features(url):
    """
    Return a dict of numeric features for a single URL.
    These are simple, fast, and useful for ML baselines.
    """
    try:
        parsed = urlparse(url if url.startswith(('http://','https://')) else 'http://' + url)
    except Exception:
        parsed = urlparse('http://' + url)

    ext = tldextract.extract(url)
    netloc = parsed.netloc or ext.registered_domain or ''
    path = parsed.path or ''
    query = parsed.query or ''

    features = {}
    features['url_len'] = len(url)
    features['hostname_len'] = len(netloc)
    features['path_len'] = len(path)
    features['count_dots'] = url.count('.')
    features['count_hyphen'] = url.count('-')
    features['count_at'] = 1 if '@' in url else 0
    features['count_q'] = url.count('?')
    features['count_eq'] = url.count('=')
    features['num_params'] = len(query.split('&')) if query else 0
    features['has_ip'] = 1 if IP_PATTERN.search(netloc) else 0
    features['https'] = 1 if parsed.scheme == 'https' else 0
    features['subdomain_len'] = len(ext.subdomain or '')
    # suspicious tokens count
    lower = url.lower()
    features['suspicious_tokens'] = sum(1 for t in SUSPICIOUS_TOKENS if t in lower)
    # number of path segments
    features['path_segments'] = len([p for p in path.split('/') if p])
    return features

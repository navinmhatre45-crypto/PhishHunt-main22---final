import os
import re
from urllib.parse import urlparse

try:
    import joblib
except Exception:  # pragma: no cover - optional dependency for trained model
    joblib = None

try:
    import requests
except Exception:  # pragma: no cover - optional dependency for API checks
    requests = None

from config import GOOGLE_SAFE_BROWSING_KEY, PHISHTANK_API_KEY

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')
FEATURE_ORDER = [
    'url_length',
    'num_dots',
    'num_digits',
    'num_special',
    'has_https',
    'has_ip',
    'suspicious_tld',
]

_model = None


def _load_model():
    global _model
    if _model is not None:
        return _model
    if joblib is None:
        return None
    if not os.path.exists(MODEL_PATH):
        return None
    try:
        _model = joblib.load(MODEL_PATH)
    except Exception:
        _model = None
    return _model


def extract_features(url: str) -> dict:
    """Extract the feature set used during model training."""
    if not isinstance(url, str):
        raise ValueError('URL must be a string')

    normalized = url.strip()
    if not normalized:
        raise ValueError('URL cannot be empty')
    if not normalized.startswith(('http://', 'https://')):
        normalized = 'http://' + normalized

    parsed = urlparse(normalized)
    host = parsed.netloc or parsed.path or ''
    url_lower = normalized.lower()

    features = {
        'url_length': len(url),
        'num_dots': url.count('.'),
        'num_digits': sum(char.isdigit() for char in url),
        'num_special': sum(char in ['@', '-', '_', '?', '=', '&', '%'] for char in url),
        'has_https': 1 if url_lower.startswith('https') else 0,
        'has_ip': 1 if re.match(r'^https?://\d+\.\d+\.\d+\.\d+', url_lower) else 0,
        'suspicious_tld': 1 if any(tld in url_lower for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']) else 0,
    }
    return features


def _heuristic_prediction(url: str):
    lower = url.lower()
    suspicious_conditions = [
        '@' in lower,
        re.match(r'^https?://\d+\.\d+\.\d+\.\d+', lower) is not None,
        len(lower) > 90,
        lower.count('.') > 4,
        any(token in lower for token in ['login', 'verify', 'secure', 'account', 'bank', 'update', 'signin', 'confirm']),
        any(tld in lower for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']),
    ]
    is_phishing = any(suspicious_conditions)
    confidence = 75.0 if is_phishing else 65.0
    return ('Phishing' if is_phishing else 'Legitimate', confidence, {})


def predict_url_ml(url: str):
    """Predict the phishing probability using the trained model or a safe fallback."""
    if not isinstance(url, str) or not url.strip():
        return 'Legitimate', 0.0, {}

    normalized = url.strip()
    model = _load_model()
    if model is None:
        return _heuristic_prediction(normalized)

    try:
        features = extract_features(normalized)
        feature_vector = [features[key] for key in FEATURE_ORDER]

        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba([feature_vector])[0]
            phishing_prob = float(probabilities[1] * 100) if len(probabilities) > 1 else float(probabilities[0] * 100)
        elif hasattr(model, 'predict'):
            prediction = model.predict([feature_vector])[0]
            phishing_prob = 100.0 if int(prediction) == 1 else 0.0
        else:
            return _heuristic_prediction(normalized)

        if phishing_prob >= 60:
            label = 'Phishing'
            confidence = min(95.0, phishing_prob + 10.0)
        elif phishing_prob <= 40:
            label = 'Legitimate'
            confidence = min(95.0, (100.0 - phishing_prob) + 10.0)
        else:
            label = 'Suspicious'
            confidence = max(phishing_prob, 100.0 - phishing_prob)

        return label, round(confidence, 2), {}
    except Exception:
        return _heuristic_prediction(normalized)


def rule_checks(url: str):
    """Return common phishing indicators and short user guidance."""
    reasons = []
    tips = [
        'Always check for HTTPS before entering sensitive data.',
        'Hover over links to verify the real destination before clicking.',
    ]

    if not isinstance(url, str) or not url.strip():
        return reasons, tips

    normalized = url.strip()
    if not normalized.startswith(('http://', 'https://')):
        normalized = 'http://' + normalized

    parsed = urlparse(normalized)
    domain = (parsed.netloc or parsed.path).lower()
    lower_url = normalized.lower()

    if '@' in lower_url:
        reasons.append("URL contains '@' symbol (hiding the real hostname)")
    if re.match(r'^https?://\d+\.\d+\.\d+\.\d+', lower_url):
        reasons.append('IP address used as domain')
    if any(tld in lower_url for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']):
        reasons.append('Free or suspicious top-level domain')
    if '-' in domain:
        reasons.append('Domain contains hyphen(s)')
    if lower_url.count('.') > 4:
        reasons.append('Too many dots in URL')
    if not lower_url.startswith('https'):
        reasons.append('URL does not use HTTPS')
    if len(lower_url) > 100:
        reasons.append('URL is unusually long')
    if any(keyword in lower_url for keyword in ['login', 'secure', 'verify', 'update', 'account', 'bank', 'signin', 'confirm']):
        reasons.append("Contains suspicious keywords like 'login' or 'secure'")

    if not reasons:
        tips = ['This URL looks normal so far.', 'Keep browsers and security tools up to date.']

    return reasons, tips


def check_phishtank(url: str):
    """Simple PhishTank-style fallback without hard dependency on an API key."""
    if not PHISHTANK_API_KEY:
        return False, {}
    if requests is None:
        return False, {'error': 'requests is unavailable'}

    try:
        response = requests.post(
            'https://checkurl.phishtank.com/checkurl/',
            data={'url': url, 'format': 'json', 'app_key': PHISHTANK_API_KEY},
            timeout=10,
        )
        if response.status_code != 200:
            return False, {'error': f'API status {response.status_code}'}
        result = response.json()
        if 'results' in result and result['results'].get('in_database'):
            return True, result['results']
        return False, {}
    except Exception as exc:  # pragma: no cover - network dependent
        return False, {'error': str(exc)}


def check_google_safe_browsing(url: str):
    """Simple Google Safe Browsing wrapper which gracefully falls back when no API key exists."""
    if not GOOGLE_SAFE_BROWSING_KEY:
        return False, {}
    if requests is None:
        return False, {'error': 'requests is unavailable'}

    payload = {
        'client': {'clientId': 'phishhunt', 'clientVersion': '1.0.0'},
        'threatInfo': {
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}],
        },
    }

    try:
        response = requests.post(
            f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}',
            json=payload,
            timeout=10,
        )
        if response.status_code != 200:
            return False, {'error': f'API status {response.status_code}'}
        result = response.json()
        return ('matches' in result and bool(result.get('matches'))), result
    except Exception as exc:  # pragma: no cover - network dependent
        return False, {'error': str(exc)}


def analyze_url(url: str):
    """Run the hybrid phishing analysis and return a structured result."""
    if not isinstance(url, str) or not url.strip():
        return {'final_result': 'Error', 'error': 'Invalid URL provided'}

    normalized = url.strip()
    if not normalized.startswith(('http://', 'https://')):
        normalized = 'http://' + normalized

    reasons, tips = rule_checks(normalized)
    ml_label, ml_confidence, per_model = predict_url_ml(normalized)

    phishtank_flag, phish_data = check_phishtank(normalized)
    google_flag, google_data = check_google_safe_browsing(normalized)

    suspicious_score = 0
    if reasons:
        suspicious_score += 1
    if ml_label == 'Phishing':
        suspicious_score += 2 if ml_confidence >= 75 else 1
    if phishtank_flag:
        suspicious_score += 3
        reasons.append('Confirmed in PhishTank database')
    if google_flag:
        suspicious_score += 3
        reasons.append('Flagged by Google Safe Browsing')

    if suspicious_score >= 4:
        final_result = 'Phishing'
    elif suspicious_score >= 2:
        final_result = 'Suspicious'
    else:
        final_result = 'Legitimate'

    if phishtank_flag or google_flag:
        tips = [
            'Do not visit this website.',
            'Avoid entering any personal or banking information.',
            'Report this URL to your IT/security team if needed.',
        ]
    elif final_result == 'Phishing':
        tips = [
            'High risk of phishing - avoid this site.',
            'Verify the website through official channels before interacting.',
            'Check for spelling mistakes and unusual domains.',
        ]
    elif final_result == 'Suspicious':
        tips = [
            'Exercise caution and do not enter passwords or financial information.',
            'Use the official app or website instead of clicking links.',
            'Confirm the destination by checking the URL carefully.',
        ]
    else:
        tips = [
            'This URL appears safe based on the current checks.',
            'Always verify HTTPS before entering sensitive data.',
            'Keep browser protections and endpoints up to date.',
        ]

    return {
        'final_result': final_result,
        'suspicious_score': suspicious_score,
        'rule_reasons': reasons or ['No suspicious patterns detected.'],
        'awareness_tips': tips,
        'ml_label': ml_label,
        'ml_confidence': ml_confidence,
        'per_model': per_model,
        'phishtank_flag': phishtank_flag,
        'google_flag': google_flag,
        'phish_data': phish_data if phishtank_flag else {},
        'google_data': google_data if google_flag else {},
    }

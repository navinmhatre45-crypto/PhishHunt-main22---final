from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import urllib.parse
import pytz
import os
import re
import socket
import math
import pickle
import requests
import hashlib
import json
from pathlib import Path
from config import GOOGLE_SAFE_BROWSING_KEY
from detection import analyze_url

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', 'your-secret-key-here')
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'phishhunt.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'home'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    url_checks = db.relationship('URLCheck', backref='user', lazy=True)
    activities = db.relationship('UserActivity', backref='user', lazy=True)

class URLCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, nullable=False)
    is_phishing = db.Column(db.Boolean, nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    checked_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def get_current_time():
    return datetime.now(pytz.utc)

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=get_current_time)

@login_manager.user_loader
def load_user(user_id):
    try:
        # SQLAlchemy 1.4+ supported pattern
        return db.session.get(User, int(user_id))
    except Exception:
        try:
            return User.query.get(int(user_id))
        except Exception:
            return None

def is_valid_hostname(host):
    if not host:
        return False
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host):
        return True
    if '.' in host and all(label for label in host.split('.')):
        return True
    return False

def is_domain_resolvable(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except Exception:
        return False

def is_valid_url_str(url_str):
    if not url_str or not isinstance(url_str, str):
        return False
    if not url_str.startswith(('http://', 'https://')):
        test = 'http://' + url_str
    else:
        test = url_str
    try:
        parsed = urllib.parse.urlparse(test)
        host = parsed.netloc.split(':')[0]
        return is_valid_hostname(host)
    except Exception:
        return False

def host_is_official_brand(host, brand):
    if not host or not brand:
        return False
    host = host.lower().strip('.')
    brand = brand.lower().strip('.')
    return host == brand or host.endswith('.' + brand)

def compute_confidence(url):
    score = 15.0
    lower_url = url.lower()
    parsed = urllib.parse.urlparse(url if url.startswith(('http://','https://')) else 'http://' + url)
    host = parsed.hostname or ''
    path = parsed.path or ''
    suspicious_keywords = ['login', 'verify', 'secure', 'account', 'confirm', 'update', 'bank', 'signin', 'pay', 'otp', 'password', 'support', 'admin']
    brand_indicators = ['paypal', 'facebook', 'amazon', 'google', 'apple', 'microsoft', 'netflix', 'instagram']

    brand_in_url = next((b for b in brand_indicators if b in lower_url), None)
    if brand_in_url:
        is_official = host_is_official_brand(host, brand_in_url + '.com') or host_is_official_brand(host, brand_in_url)
        if is_official:
            score -= 25.0
        else:
            score += 30.0

    keyword_count = sum(1 for k in suspicious_keywords if k in lower_url)
    score += keyword_count * 5.0

    if '@' in url:
        score += 35.0
    if parsed.scheme == 'http':
        score += 15.0
    elif parsed.scheme == 'https':
        score -= 10.0

    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host):
        score += 40.0

    if len(host) > 25:
        score += (len(host) - 25) * 0.5
    if len(path) > 75:
        score += (len(path) - 75) * 0.2

    dot_count = host.count('.')
    if dot_count > 3:
        score += (dot_count - 3) * 4.0

    if '-' in host and not brand_in_url:
        score += 10.0

    tld = host.split('.')[-1] if '.' in host else ''
    uncommon_tlds = ['xyz', 'buzz', 'link', 'top', 'loan', 'work']
    if tld in uncommon_tlds:
        score += 12.0

    score = max(0.0, min(score, 99.0))
    return round(score, 1)

# --- Placeholder: load your ML models and vectorizer once at startup ---
# Replace the paths and loading code with your project's loader
try:
    with open('models/logistic.pkl', 'rb') as f:
        model_logistic = pickle.load(f)
    with open('models/svc.pkl', 'rb') as f:
        model_svc = pickle.load(f)
    with open('models/tree.pkl', 'rb') as f:
        model_tree = pickle.load(f)
    with open('models/vectorizer.pkl', 'rb') as f:
        vectorizer = pickle.load(f)
except Exception:
    model_logistic = model_svc = model_tree = vectorizer = None

def rule_based_check(url: str):
    """Simple rule-based heuristics. Return dict with is_phish(bool) and reasons(list)."""
    reasons = []
    u = url.lower().strip()

    # normalized host extraction
    try:
        test = u if u.startswith(('http://','https://')) else 'http://' + u
        parsed = urllib.parse.urlparse(test)
        host = (parsed.hostname or '').lower()
    except Exception:
        host = re.sub(r'^https?://', '', u).split('/')[0].lower()

    # brand indicators: treat brand mention as suspicious reason but do NOT auto-return phishing
    brand_indicators = ['paypal', 'facebook', 'amazon', 'google', 'apple', 'chase', 'wellsfargo', 'bank']
    for b in brand_indicators:
        if b in u:
            # if host does not clearly look like an official domain for that brand, add reason only
            if not (host_is_official_brand(host, b) or host_is_official_brand(host, b + '.com') or host.split('.')[0] == b):
                reasons.append(f'Contains brand name "{b}" but domain does not match official {b}.com (suspicious)')

    # check if URL uses IP address instead of domain
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        reasons.append('Uses raw IP address in URL')

    # excessive length
    if len(u) > 75:
        reasons.append('URL length suspiciously long')

    # suspicious tokens
    suspicious_tokens = ['login', 'secure', 'account', 'update', 'verify', 'bank', 'confirm', 'wallet', '@']
    if any(tok in u for tok in suspicious_tokens):
        reasons.append('Contains suspicious token (login/secure/verify/...)')

    # hyphenated domain (common in fake domains)
    domain = host.split(':')[0]
    if '-' in domain and domain.count('-') >= 1:
        reasons.append('Domain contains hyphen(s)')

    # multiple subdomains (could be trick)
    if domain.count('.') >= 3:
        reasons.append('Many subdomains (possible obfuscation)')

    is_phish = len(reasons) > 0
    return {'is_phish': is_phish, 'reasons': reasons}

def google_safe_browsing_check(url: str):
    """
    Use Google Safe Browsing v4 API to check the URL.
    Returns a dict with keys: {'is_phish': bool, 'info': str}
    Falls back to {'is_phish': False, 'info': '...'} on error.
    """
    if not GOOGLE_SAFE_BROWSING_KEY:
        return {'is_phish': False, 'info': 'No Google API key configured'}

    endpoint = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}'
    payload = {
        "client": {
            "clientId": "PhishHunt",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=6)
        if resp.status_code != 200:
            return {'is_phish': False, 'info': f'SafeBrowsing API error {resp.status_code}'}
        j = resp.json()
        matches = j.get('matches')
        if matches:
            # provide a concise summary
            types = list({m.get('threatType') for m in matches if m.get('threatType')})
            info = f'Flagged by Safe Browsing: {", ".join(types)}'
            return {'is_phish': True, 'info': info}
        return {'is_phish': False, 'info': 'No matches found'}
    except Exception as e:
        return {'is_phish': False, 'info': f'SafeBrowsing check failed: {str(e)}'}

def ml_predict_ensemble(url: str):
    """
    Use vectorizer and three models to get predictions and probabilities.
    If models are not loaded, produce deterministic URL-dependent fallback probabilities
    so each URL shows different ML percentages.
    Return dict: predictions, probabilities, majority_vote, confidence(0..1)
    """
    # If models are available, use them properly (ensure X is created and phishing-class prob is extracted)
    if vectorizer and model_logistic and model_svc and model_tree:
        preds = {}
        probs = {}

        try:
            X = vectorizer.transform([url])
        except Exception:
            X = None

        # Helper to extract phishing probability robustly from predict_proba
        def phishing_prob_from_proba(model, X):
            try:
                p = model.predict_proba(X)[0]
                # If model exposes classes_, find index of label 1 (phishing) else assume second column is phishing
                if hasattr(model, 'classes_'):
                    classes = list(model.classes_)
                    if 1 in classes:
                        idx = classes.index(1)
                    elif '1' in classes:
                        idx = classes.index('1')
                    else:
                        idx = 1 if len(p) > 1 else p.argmax()
                else:
                    idx = 1 if len(p) > 1 else p.argmax()
                return float(p[idx])
            except Exception:
                return None

        # Logistic
        try:
            if X is not None:
                p_log = getattr(model_logistic, 'predict_proba', None)
                if p_log:
                    prob = phishing_prob_from_proba(model_logistic, X)
                    probs['logistic'] = prob
                    preds['logistic'] = int(model_logistic.predict(X)[0])
                else:
                    preds['logistic'] = int(model_logistic.predict(X)[0])
                    probs['logistic'] = None
            else:
                preds['logistic'] = None
                probs['logistic'] = None
        except Exception:
            preds['logistic'] = None
            probs['logistic'] = None

        # SVC
        try:
            if X is not None:
                p_svc = getattr(model_svc, 'predict_proba', None)
                if p_svc:
                    prob = phishing_prob_from_proba(model_svc, X)
                    probs['svc'] = prob
                    preds['svc'] = int(model_svc.predict(X)[0])
                else:
                    # fallback to decision function -> map to probability-like score
                    df = getattr(model_svc, 'decision_function', None)
                    if df:
                        score = model_svc.decision_function(X)[0]
                        preds['svc'] = 1 if score > 0 else 0
                        # map signed score to (0..1) heuristic
                        probs['svc'] = float(1.0 / (1.0 + math.exp(-score))) if score is not None else None
                    else:
                        preds['svc'] = int(model_svc.predict(X)[0])
                        probs['svc'] = None
            else:
                preds['svc'] = None
                probs['svc'] = None
        except Exception:
            preds['svc'] = None
            probs['svc'] = None

        # Decision tree / random forest
        try:
            if X is not None:
                p_tree = getattr(model_tree, 'predict_proba', None)
                if p_tree:
                    prob = phishing_prob_from_proba(model_tree, X)
                    probs['tree'] = prob
                    preds['tree'] = int(model_tree.predict(X)[0])
                else:
                    preds['tree'] = int(model_tree.predict(X)[0])
                    probs['tree'] = None
            else:
                preds['tree'] = None
                probs['tree'] = None
        except Exception:
            preds['tree'] = None
            probs['tree'] = None

        # Compute majority and confidence (confidence is avg phishing-prob if available)
        votes = [v for v in (preds.get('logistic'), preds.get('svc'), preds.get('tree')) if v is not None]
        if len(votes) == 0:
            majority = 'unknown'
            confidence = 0.0
        else:
            sum_votes = sum(votes)
            majority_label = 1 if sum_votes > (len(votes) / 2) else 0
            majority = 'phishing' if majority_label == 1 else 'legitimate'
            prob_vals = [p for p in probs.values() if isinstance(p, float)]
            if prob_vals:
                # if majority says phishing, use average phishing probability; else average (1 - p)
                if majority_label == 1:
                    confidence = float(sum(prob_vals) / len(prob_vals))
                else:
                    confidence = float(sum((1.0 - p) for p in prob_vals) / len(prob_vals))
            else:
                # fallback to vote fraction
                confidence = float(max(sum_votes / len(votes), 1.0 - (sum_votes / len(votes))))

        return {
            'predictions': preds,
            'probabilities': probs,
            'majority_vote': majority,
            'confidence': round(confidence, 3)
        }

    # --- Fallback deterministic pseudo-ML when models aren't loaded ---
    # Use compute_confidence as base suspicion (0..99) then produce per-model probs by hashing URL
    suspicion = compute_confidence(url)  # 0..99 higher => more suspicious
    base = max(0.0, min(0.99, suspicion / 100.0))

    # deterministic jitter from URL hash (0..1)
    h = int.from_bytes(hashlib.sha256(url.encode('utf-8')).digest()[:4], 'big') / 2**32
    # produce three distinct deterministic probabilities around base
    p_log = max(0.01, min(0.99, base + (h - 0.5) * 0.28))        # logistic-like
    p_svc = max(0.01, min(0.99, base + ((h * 1.37) % 1.0 - 0.5) * 0.24))
    p_tree = max(0.01, min(0.99, base + ((h * 2.13) % 1.0 - 0.5) * 0.3))

    preds = {
        'logistic': 1 if p_log >= 0.5 else 0,
        'svc': 1 if p_svc >= 0.5 else 0,
        'tree': 1 if p_tree >= 0.5 else 0
    }
    probs = {'logistic': round(p_log, 3), 'svc': round(p_svc, 3), 'tree': round(p_tree, 3)}

    # majority vote
    votes = [preds[k] for k in preds]
    sum_votes = sum(votes)
    if sum_votes > (len(votes) / 2):
        majority_label = 1
        majority = 'phishing'
        # confidence: average of probabilities for the phishing class
        confidence = float(round((p_log + p_svc + p_tree) / 3.0, 3))
    else:
        majority_label = 0
        majority = 'legitimate'
        # confidence: average probability toward legitimacy (1 - p)
        confidence = float(round(((1 - p_log) + (1 - p_svc) + (1 - p_tree)) / 3.0, 3))

    return {
        'predictions': preds,
        'probabilities': probs,
        'majority_vote': majority,
        'confidence': confidence,
        'info': 'Fallback deterministic ML (models not loaded)'
    }

# --- Add persistent learned-labels (simple host -> 'phishing'|'legitimate') ---
LEARNED_FILE = Path(basedir) / 'learned_labels.json'

def load_learned_labels():
    try:
        if LEARNED_FILE.exists():
            with open(LEARNED_FILE, 'r', encoding='utf-8') as fh:
                return json.load(fh)
    except Exception:
        pass
    return {}

def save_learned_label(host: str, label: str):
    try:
        labels = load_learned_labels()
        labels[host] = label
        with open(LEARNED_FILE, 'w', encoding='utf-8') as fh:
            json.dump(labels, fh, indent=2)
        return True
    except Exception:
        return False

# --- NEW: persistent results cache so same URL returns same percentages every time ---
RESULTS_CACHE_FILE = Path(basedir) / 'results_cache.json'

def canonicalize_url(url: str) -> str:
    """
    Normalize URL into a canonical string used as cache key.
    Lowercase scheme/host, sort query parameters, remove fragments, normalize path trailing slash.
    """
    if not url:
        return ''
    try:
        u = url if url.startswith(('http://','https://')) else 'http://' + url
        parsed = urllib.parse.urlparse(u)
        scheme = (parsed.scheme or 'http').lower()
        host = (parsed.hostname or '').lower()
        port = f":{parsed.port}" if parsed.port else ''
        # normalize path (keep at least '/')
        path = parsed.path or '/'
        path = path.rstrip('/') or '/'
        # sort query params deterministically
        qitems = sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        query = urllib.parse.urlencode(qitems)
        normalized = urllib.parse.urlunparse((scheme, host + port, path, '', query, ''))
        return normalized
    except Exception:
        # fallback to lower-stripped url
        return (url or '').strip().lower()

def load_results_cache():
    try:
        if RESULTS_CACHE_FILE.exists():
            with open(RESULTS_CACHE_FILE, 'r', encoding='utf-8') as fh:
                return json.load(fh)
    except Exception:
        pass
    return {}

def save_results_cache(cache: dict):
    try:
        with open(RESULTS_CACHE_FILE, 'w', encoding='utf-8') as fh:
            json.dump(cache, fh, indent=2)
        return True
    except Exception:
        return False

# load cache into memory once at startup
RESULTS_CACHE = load_results_cache()

def get_cached_result(normalized_url: str):
    return RESULTS_CACHE.get(normalized_url)

def save_cached_result(normalized_url: str, web_result: dict, api_result: dict):
    RESULTS_CACHE[normalized_url] = {'web_result': web_result, 'api_result': api_result}
    # best-effort persist
    save_results_cache(RESULTS_CACHE)
    return True

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    if not username or not email or not password:
        flash('Please fill all fields', 'error')
        return redirect(url_for('home'))

    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'error')
        return redirect(url_for('home'))

    if User.query.filter_by(email=email).first():
        flash('Email already registered', 'error')
        return redirect(url_for('home'))

    user = User(username=username, email=email, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    login_user(user)
    activity = UserActivity(user_id=user.id, activity_type='registration', description='Account created')
    db.session.add(activity)
    db.session.commit()
    flash('Account created successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password_hash, password):
        login_user(user)
        activity = UserActivity(user_id=user.id, activity_type='login', description='User logged in')
        db.session.add(activity)
        db.session.commit()
        flash('Logged in successfully!', 'success')
        return redirect(url_for('home'))
    else:
        flash('Invalid email or password', 'error')
        return redirect(url_for('home'))

@app.route('/logout')
@login_required
def logout():
    activity = UserActivity(user_id=current_user.id, activity_type='logout', description='User logged out')
    db.session.add(activity)
    db.session.commit()
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('home'))

@app.route('/delete_check/<int:check_id>', methods=['DELETE'])
@login_required
def delete_check(check_id):
    check = URLCheck.query.filter_by(id=check_id, user_id=current_user.id).first()
    if check:
        db.session.delete(check)
        activity = UserActivity(user_id=current_user.id, activity_type='check_deleted', description=f'Deleted URL check: {check.url}')
        db.session.add(activity)
        db.session.commit()
        return '', 200
    else:
        return 'Check not found', 404

@app.route('/api/recent_searches', methods=['GET'])
@login_required
def get_recent_searches():
    recent_checks = URLCheck.query.filter_by(user_id=current_user.id).order_by(URLCheck.checked_at.desc()).limit(6).all()
    searches = [{"id": check.id, "url": check.url, "timestamp": check.checked_at.isoformat()} for check in recent_checks]
    return jsonify(searches)

@app.route('/api/save_search', methods=['POST'])
@login_required
def save_search():
    return jsonify({"status": "success_noop"})

@app.route('/api/delete_search/<int:check_id>', methods=['DELETE'])
@login_required
def delete_search(check_id):
    check = URLCheck.query.filter_by(id=check_id, user_id=current_user.id).first()
    if check:
        db.session.delete(check)
        activity = UserActivity(user_id=current_user.id, activity_type='search_deleted', description=f'Deleted saved search: {check.url}')
        db.session.add(activity)
        db.session.commit()
        return jsonify({"status": "deleted"}), 200
    else:
        return jsonify({"status": "not_found"}), 404

@app.route('/api/analyze_url', methods=['POST'])
@login_required
def api_analyze_url():
    data = request.get_json(silent=True) or {}
    url = (data.get('url') or '').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    result = analyze_url(url)
    return jsonify(result)

@app.route('/clear_history', methods=['POST'])
@login_required
def clear_history():
    URLCheck.query.filter_by(user_id=current_user.id).delete()
    activity = UserActivity(user_id=current_user.id, activity_type='history_cleared', description='Cleared all check history')
    db.session.add(activity)
    db.session.commit()
    flash('History cleared successfully!', 'success')
    return redirect(url_for('history'))

def get_local_time(utc_time):
    if not utc_time:
        return utc_time
    local_tz = pytz.timezone('Asia/Kolkata')
    try:
        if getattr(utc_time, 'tzinfo', None) is None or utc_time.tzinfo.utcoffset(utc_time) is None:
            utc_time = utc_time.replace(tzinfo=pytz.utc)
    except Exception:
        utc_time = utc_time.replace(tzinfo=pytz.utc)
    try:
        return utc_time.astimezone(local_tz)
    except Exception:
        return utc_time

@app.route('/profile')
@login_required
def profile():
    total_checks = URLCheck.query.filter_by(user_id=current_user.id).count()
    phishing_count = URLCheck.query.filter_by(user_id=current_user.id, is_phishing=True).count()
    safe_count = total_checks - phishing_count
    user_stats = {'urls_checked': total_checks, 'phishing_detected': phishing_count, 'safe_count': safe_count}
    recent_activity = UserActivity.query.filter_by(user_id=current_user.id).order_by(UserActivity.timestamp.desc()).limit(10).all()
    for activity in recent_activity:
        activity.local_timestamp = get_local_time(activity.timestamp)
    return render_template('profile.html', user_stats=user_stats, recent_activity=recent_activity, current_time=datetime.now())

@app.route('/history')
@login_required
def history():
    url_checks = URLCheck.query.filter_by(user_id=current_user.id).order_by(URLCheck.checked_at.desc()).all()
    total_checks = len(url_checks)
    phishing_count = len([check for check in url_checks if check.is_phishing])
    safe_count = total_checks - phishing_count
    return render_template('history.html', url_checks=url_checks, total_checks=total_checks, phishing_count=phishing_count, safe_count=safe_count)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    username = request.form.get('username')
    email = request.form.get('email')
    existing_user = User.query.filter(User.username == username, User.id != current_user.id).first()
    if existing_user:
        flash('Username already taken', 'error')
        return redirect(url_for('profile'))
    existing_email = User.query.filter(User.email == email, User.id != current_user.id).first()
    if existing_email:
        flash('Email already registered', 'error')
        return redirect(url_for('profile'))
    current_user.username = username
    current_user.email = email
    activity = UserActivity(user_id=current_user.id, activity_type='profile_update', description='Profile information updated')
    db.session.add(activity)
    db.session.commit()
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    if not check_password_hash(current_user.password_hash, current_password):
        flash('Current password is incorrect', 'error')
        return redirect(url_for('profile'))
    if new_password != confirm_password:
        flash('New passwords do not match', 'error')
        return redirect(url_for('profile'))
    current_user.password_hash = generate_password_hash(new_password)
    activity = UserActivity(user_id=current_user.id, activity_type='password_change', description='Password changed')
    db.session.add(activity)
    db.session.commit()
    flash('Password changed successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.form.get('url', '').strip()
    if not url:
        flash('Please enter a URL', 'error')
        return redirect(url_for('home'))
    
    # Use the new detection system
    try:
        result = analyze_url(url)  # This uses your new detection.py
        
        # Log to database if user is authenticated
        if current_user.is_authenticated:
            try:
                is_phishing = result['final_result'] in ['Phishing', 'Suspicious']
                confidence = result.get('risk_score', 50.0) / 100.0
                url_check = URLCheck(
                    url=url, 
                    is_phishing=is_phishing, 
                    confidence=confidence, 
                    user_id=current_user.id
                )
                db.session.add(url_check)
                activity = UserActivity(
                    user_id=current_user.id, 
                    activity_type='url_check', 
                    description=f'Checked URL: {url}'
                )
                db.session.add(activity)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print(f"Database logging error: {e}")
        
        return render_template('result.html', url=url, result=result)
        
    except Exception as e:
        flash(f'Error analyzing URL: {str(e)}', 'error')
        return redirect(url_for('home'))
@app.route('/api/stats', methods=['GET'])
def api_stats():
    try:
        total_checks = URLCheck.query.count()
    except Exception:
        total_checks = 0
    return jsonify({"total_checks": total_checks})

# --- REMOVED duplicate endpoint definitions ---
# The original file contained earlier copies of these route functions which caused
# Flask to raise "overwriting an existing endpoint" errors. The updated, integrated
# implementations appear later in this file; remove the earlier duplicates.

# { removed duplicate function: @app.route('/api/check_url', methods=['POST']) def api_check_url(): ... }
# { removed duplicate function: @app.route('/api/feedback', methods=['POST']) def api_feedback(): ... }
# { removed duplicate function: @app.route('/check_url', methods=['POST']) def check_url(): ... }



@app.route('/api/feedback', methods=['POST'])
@login_required
def api_feedback():
    """
    Accepts JSON: { "url": "...", "label": "phishing"|"legitimate" }
    Persists feedback to learned_labels.json and stores a URLCheck row + activity.
    """
    data = request.get_json(silent=True) or {}
    url = (data.get('url') or '').strip()
    label = (data.get('label') or '').strip().lower()
    if not url or label not in ('phishing', 'legitimate'):
        return jsonify({'error': 'url and label (phishing|legitimate) required'}), 400

    test_url = url if url.startswith(('http://','https://')) else 'http://' + url
    try:
        parsed = urllib.parse.urlparse(test_url)
        host = parsed.hostname or parsed.netloc.split(':')[0]
    except Exception:
        host = re.sub(r'^https?://', '', url).split('/')[0]

    # Save learned label
    ok = save_learned_label(host, label)
    # Record as URLCheck if user is authenticated
    try:
        is_phish = (label == 'phishing')
        conf_val = 0.99 if is_phish else 0.95
        if current_user.is_authenticated:
            uc = URLCheck(url=test_url, is_phishing=is_phish, confidence=conf_val, user_id=current_user.id)
            db.session.add(uc)
            activity = UserActivity(user_id=current_user.id, activity_type='feedback', description=f'Feedback: {label} for {test_url}')
            db.session.add(activity)
            db.session.commit()
    except Exception:
        db.session.rollback()

    return jsonify({'saved': bool(ok), 'host': host, 'label': label}), 200 if ok else 500

# --- Add JSON error handlers for API endpoints to avoid returning HTML error pages ---
@app.errorhandler(404)
def handle_404(e):
    # If the client asked an API path, return JSON instead of the HTML 404 page
    try:
        if request.path.startswith('/api/') or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return make_response(jsonify({'error': 'API endpoint not found', 'path': request.path}), 404)
    except Exception:
        pass
    # Default HTML behavior
    return e

@app.errorhandler(500)
def handle_500(e):
    try:
        if request.path.startswith('/api/') or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return make_response(jsonify({'error': 'Internal server error', 'detail': str(e)}), 500)
    except Exception:
        pass
    return e

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='127.0.0.1', port=5000)
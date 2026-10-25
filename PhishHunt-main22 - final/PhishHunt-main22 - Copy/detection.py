# detection.py
# Core logic for URL phishing detection using hybrid rule-based and ML approaches

import re
import requests
from urllib.parse import urlparse
from ml_model import predict_url_ml
from config import GOOGLE_SAFE_BROWSING_KEY

class SafeBrowsingAPI:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    
    def check_url(self, url: str) -> dict:
        """Check URL against Google Safe Browsing API"""
        if not self.api_key or self.api_key == "YOUR_ACTUAL_GOOGLE_API_KEY_HERE":
            return {"safe": True, "error": "API key not configured"}
        
        payload = {
            "client": {
                "clientId": "phishhunt-detector",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        try:
            response = requests.post(
                f"{self.base_url}?key={self.api_key}",
                json=payload,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                # If matches found, URL is malicious
                is_safe = "matches" not in data or len(data.get("matches", [])) == 0
                return {
                    "safe": is_safe,
                    "matches": data.get("matches", []),
                    "error": None
                }
            else:
                return {"safe": True, "error": f"API error: {response.status_code}"}
                
        except Exception as e:
            return {"safe": True, "error": f"Connection error: {str(e)}"}

# Initialize Google Safe Browsing API
google_api = SafeBrowsingAPI(GOOGLE_SAFE_BROWSING_KEY)

def calculate_risk_score(url: str, reasons: list, ml_confidence: float, ml_label: str) -> tuple:
    """Calculate comprehensive risk score and determine final result"""
    
    # Base score from ML model
    if ml_label == "Phishing":
        base_score = ml_confidence
    else:
        base_score = 100 - ml_confidence  # Invert for legitimate
    
    # Rule-based penalties
    rule_penalty = len(reasons) * 15  # Increased weight for rule violations
    total_score = min(base_score + rule_penalty, 100)
    
    # Determine final result based on score
    if total_score >= 70:
        return "Phishing", total_score
    elif total_score >= 40:
        return "Suspicious", total_score
    else:
        return "Legitimate", total_score

def generate_context_aware_explanation(url: str, reasons: list, ml_label: str, ml_confidence: float, 
                                     final_result: str, risk_score: float, google_flag: bool = False):
    """Generate dynamic explanations based on actual analysis results"""
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower() if parsed.netloc else ""
    url_lower = url.lower()
    
    explanations = []
    tips = []
    
    # GOOGLE SAFE BROWSING RESULTS
    if google_flag:
        explanations.append("🚨 **Google Safe Browsing** flagged this as malicious")
        tips.append("This URL is in Google's known threats database - avoid visiting!")
        tips.append("Google has verified this as a dangerous website")
    
    # ANALYSIS OF WHY IT'S UNSAFE
    if final_result in ["Phishing", "Suspicious"]:
        
        # Domain-specific warnings
        if 'paypal' in url_lower:
            explanations.append("❌ This appears to be a fake PayPal website")
            tips.append("Always go to paypal.com directly - never through links in emails")
            tips.append("Real PayPal uses 'https://www.paypal.com' - check for spelling mistakes")
            
        elif 'facebook' in url_lower:
            explanations.append("❌ This appears to be a fake Facebook login page") 
            tips.append("Real Facebook is 'facebook.com' - this domain is different")
            tips.append("Use the official Facebook app instead of clicking login links")
            
        elif 'bank' in url_lower or any(bank in url_lower for bank in ['wellsfargo', 'chase', 'bankofamerica']):
            explanations.append("❌ This appears to be a fake banking website")
            tips.append("Banks never ask you to login through email links")
            tips.append("Always type your bank's URL directly into the browser")
        
        # Pattern-specific explanations
        if any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']):
            explanations.append("🌐 This uses a free domain extension (.tk, .ml, .ga) commonly used by phishing sites")
            tips.append("Legitimate companies rarely use free domain extensions")
            
        if '@' in url:
            explanations.append("🔍 The '@' symbol is hiding the real website address")
            tips.append("Everything before '@' is ignored - you're actually going to what's after it")
            
        if not url_lower.startswith("https"):
            explanations.append("🔓 No HTTPS encryption - your data would be sent unsecured")
            tips.append("Never enter passwords on sites without HTTPS")
            
        if url.count('.') > 4:
            explanations.append("🕸️ Too many subdomains - this is a common trick to look legitimate")
            tips.append("Legitimate sites usually have simple domain structures")
            
        if len(url) > 100:
            explanations.append("📏 Very long URL - often used to hide malicious content")
            tips.append("Short, simple URLs are more trustworthy")
            
        # ML confidence explanations
        if ml_confidence >= 80:
            explanations.append(f"🤖 Our AI detected strong phishing patterns ({ml_confidence}% confidence)")
        elif ml_confidence >= 60:
            explanations.append(f"🤖 Our AI found suspicious characteristics ({ml_confidence}% confidence)")
            
        # Add any rule-based reasons as explanations
        for reason in reasons:
            if "suspicious" in reason.lower() or "phishing" in reason.lower():
                explanations.append(f"🔍 {reason}")
                
    # ANALYSIS OF WHY IT'S SAFE  
    else:
        # Known legitimate domains
        legitimate_domains = {
            'google.com': "Google's official domain",
            'github.com': "GitHub's official domain", 
            'wikipedia.org': "Wikipedia's official domain",
            'amazon.com': "Amazon's official domain",
            'microsoft.com': "Microsoft's official domain",
            'apple.com': "Apple's official domain",
            'facebook.com': "Facebook's official domain",
            'twitter.com': "Twitter's official domain",
            'paypal.com': "PayPal's official domain"
        }
        
        domain_found = False
        for legit_domain, description in legitimate_domains.items():
            if legit_domain in domain:
                explanations.append(f"✅ This is {description}")
                tips.append("This is the official website you can trust")
                domain_found = True
                break
                
        if not domain_found:
            explanations.append("✅ No suspicious patterns detected")
            
        # Positive security indicators
        if url_lower.startswith("https"):
            explanations.append("🔒 HTTPS encryption protects your data")
            tips.append("Your connection to this site is secure")
            
        if domain.count('.') <= 3:
            explanations.append("🌐 Clean domain structure - looks legitimate")
            
        if len(url) < 60:
            explanations.append("📏 Reasonable URL length - not trying to hide anything")
            
        if ml_confidence >= 70:
            explanations.append(f"🤖 Our AI confirms this looks legitimate ({ml_confidence}% confidence)")
            
        # General safety tips for legitimate sites
        tips.append("Always check for HTTPS before entering passwords")
        tips.append("Look for security indicators in your browser")
        tips.append("Keep your browser updated for the latest security")
        
    # Final summary based on result
    if final_result == "Phishing":
        explanations.insert(0, "🚨 **HIGH RISK PHISHING SITE DETECTED**")
        tips.insert(0, "🚫 DO NOT ENTER ANY PERSONAL INFORMATION")
        tips.append("📧 Report this site to your email provider")
        tips.append("🗑️ Delete any emails containing this link")
        
    elif final_result == "Suspicious":
        explanations.insert(0, "⚠️ **SUSPICIOUS WEBSITE DETECTED**") 
        tips.insert(0, "🔒 Avoid entering sensitive information")
        tips.append("🔍 Verify this website through other sources")
        tips.append("📱 Use official apps when possible")
        
    else:
        explanations.insert(0, "✅ **SAFE WEBSITE DETECTED**")
        tips.insert(0, "🔒 You can proceed with caution")
        tips.append("👀 Always stay vigilant online")
        
    return explanations, tips

def is_educational_domain(domain: str) -> bool:
    """
    Return True if domain is an educational / academic domain we should treat leniently.
    Matches common educational suffixes like .ac.in, .edu, .ac.uk, etc.
    """
    if not domain:
        return False
    edu_suffixes = ['.ac.in', '.edu', '.ac.uk', '.edu.in', '.ac.nz', '.edu.au', '.ac.za', '.edu.au']
    domain = domain.lower()
    return any(domain.endswith(suf) for suf in edu_suffixes)

def analyze_url(url: str):
    """Main function to analyze URL for phishing attempts"""
    
    # Input validation
    if not url or not isinstance(url, str):
        return {
            "final_result": "Error",
            "error": "Invalid URL provided"
        }
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    reasons = []
    parsed = urlparse(url)
    domain = parsed.netloc.lower() if parsed.netloc else ""
    url_lower = url.lower()
    
    # --- GOOGLE SAFE BROWSING API CHECK (Primary) ---
    google_result = google_api.check_url(url)
    google_flag = not google_result.get("safe", True)
    
    # If Google flags it as malicious, trust this immediately
    if google_flag:
        explanations, tips = generate_context_aware_explanation(
            url, ["Flagged by Google Safe Browsing"], "Phishing", 95.0, "Phishing", 95.0, True
        )
        
        return {
            "final_result": "Phishing",
            "rule_based": "Phishing (Google Safe Browsing)",
            "ml_based": "Phishing (95%)",
            "ml_label": "Phishing",
            "ml_confidence": 95.0,
            "risk_score": 95.0,
            "reasons": explanations,
            "awareness_tips": tips,
            "per_model": {"google_safe_browsing": 95.0},
            "google_flag": True,
            "api_checked": True
        }
    
    # --- RULE-BASED CHECKS (Enhanced, lenient for educational domains) ---
    is_edu = is_educational_domain(domain)

    # Immediate high-risk indicators (always considered)
    if "@" in url:
        reasons.append("URL contains '@' symbol (high risk)")
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        reasons.append("IP address used as domain (high risk)")
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.download', '.loan']
    if any(tld in domain for tld in suspicious_tlds):
        reasons.append("Free/suspicious domain extension")

    # Lower-confidence indicators: only apply these if NOT an educational domain
    if not is_edu:
        if "-" in domain:
            reasons.append("Hyphens in domain name")
        if url.count('.') > 4:
            reasons.append(f"Too many dots ({url.count('.')}) - common in phishing")
        if not url_lower.startswith("https"):
            reasons.append("No HTTPS encryption")
        if len(url) > 100:
            reasons.append("Very long URL (potential obfuscation)")
        # Suspicious keywords (non-edu only)
        suspicious_keywords = ['login', 'secure', 'verify', 'update', 'account', 'banking', 'signin', 
                              'authenticate', 'confirm', 'validation', 'security']
        if any(keyword in domain for keyword in suspicious_keywords):
            reasons.append("Suspicious keywords in domain")

    else:
        # For educational domains we keep only truly high-risk reasons (IP/@/suspicious tld).
        # This avoids false positives for valid multi-subdomain academic URLs like www.phcet.ac.in
        reasons = [r for r in reasons if any(x in r.lower() for x in ['ip address', "@" , 'suspicious domain extension'])]

    # --- ML-BASED CHECK ---
    try:
        ml_label, ml_confidence, per_model = predict_url_ml(url)
    except Exception as e:
        ml_label = "Unknown"
        ml_confidence = 50.0
        per_model = {"error": str(e)}
    
    # --- CALCULATE COMPREHENSIVE RISK SCORE ---
    final_result, risk_score = calculate_risk_score(url, reasons, ml_confidence, ml_label)
    
    # --- OVERRIDE: If ML is very confident about phishing, trust it ---
    if ml_label == "Phishing" and ml_confidence >= 85:
        final_result = "Phishing"
        risk_score = max(risk_score, 85)
    elif ml_label == "Legitimate" and ml_confidence >= 90 and len(reasons) < 2:
        final_result = "Legitimate"
        risk_score = min(risk_score, 20)
    
    # If educational domain and risk is moderate, prefer Legitimate
    if is_edu and risk_score < 60:
        final_result = "Legitimate"
        # lower the score for display
        risk_score = min(risk_score, 25)
    
    explanations, tips = generate_context_aware_explanation(
        url, reasons, ml_label, ml_confidence, final_result, risk_score, google_flag
    )
    
    return {
        "final_result": final_result,
        "rule_based": "Phishing" if reasons else "Legitimate",
        "ml_based": f"{ml_label} ({ml_confidence}%)",
        "ml_label": ml_label,
        "ml_confidence": ml_confidence,
        "risk_score": risk_score,
        "reasons": explanations,
        "awareness_tips": tips,
        "per_model": per_model,
        "google_flag": google_flag,
        "api_checked": True
    }

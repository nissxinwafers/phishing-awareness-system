import re

# Keywords that are commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'secure', 'update', 'bank',
    'free', 'confirm', 'account', 'password', 'signin'
]

# Common URL shortener domains
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
    'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly'
]

def analyze_url(url):
    score = 0
    reasons = []

    # Check 1: Missing HTTPS
    if not url.startswith('https://'):
        score += 15
        reasons.append("Does not use HTTPS (insecure connection)")

    # Check 2: IP address used instead of domain name
    ip_pattern = re.compile(r'http[s]?://(\d{1,3}\.){3}\d{1,3}')
    if ip_pattern.match(url):
        score += 30
        reasons.append("Uses an IP address instead of a domain name")

    # Check 3: Suspicious keywords in URL
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            score += 20
            reasons.append(f"Contains suspicious keyword: '{keyword}'")
            break  # Only count once even if multiple keywords found

    # Check 4: Too many hyphens in domain
    try:
        domain = url.split('/')[2]
        if domain.count('-') >= 3:
            score += 15
            reasons.append("Domain contains too many hyphens")
    except IndexError:
        pass

    # Check 5: URL shortener detected
    for shortener in URL_SHORTENERS:
        if shortener in url.lower():
            score += 20
            reasons.append(f"Uses a URL shortener: '{shortener}'")
            break

    # Check 6: Suspiciously long URL
    if len(url) > 100:
        score += 10
        reasons.append("URL is suspiciously long")

    # Check 7: Multiple subdomains
    try:
        domain = url.split('/')[2]
        if domain.count('.') >= 3:
            score += 10
            reasons.append("URL has multiple subdomains")
    except IndexError:
        pass

    # Cap score at 100
    score = min(score, 100)

    # Determine risk level based on score
    if score <= 30:
        result = 'Low Risk'
    elif score <= 60:
        result = 'Medium Risk'
    else:
        result = 'High Risk'

    return {
        'score': score,
        'result': result,
        'reasons': reasons
    }

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

# Known legitimate domains used to detect lookalike / typo-squatting attempts
TRUSTED_DOMAINS = [
    'paypal.com', 'maya.ph', 'gcash.com', 'facebook.com', 'gmail.com',
    'amazon.com', 'bdo.com.ph', 'bpi.com.ph', 'netflix.com', 'apple.com',
    'google.com', 'instagram.com', 'twitter.com', 'unionbankph.com',
    'metrobank.com.ph'
]

# Common character substitutions used by phishers
CHAR_SUBSTITUTIONS = [
    ('0', 'o'),
    ('1', 'l'),
    ('@', 'a'),
    ('$', 's'),
    ('rn', 'm'),
    ('vv', 'w'),
    ('3', 'e'),
    ('4', 'a'),
    ('5', 's'),
]


def normalize_domain(domain):
    result = domain.lower()
    for old, new in CHAR_SUBSTITUTIONS:
        result = result.replace(old, new)
    return result


def levenshtein(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            insert_cost = curr[j - 1] + 1
            delete_cost = prev[j] + 1
            sub_cost = prev[j - 1] + (0 if ca == cb else 1)
            curr.append(min(insert_cost, delete_cost, sub_cost))
        prev = curr
    return prev[-1]


def extract_domain(url):
    try:
        without_scheme = re.sub(r'^[a-zA-Z]+://', '', url)
        domain = without_scheme.split('/')[0].split(':')[0].lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except Exception:
        return ''


def _base_name(domain):
    parts = domain.split('.')
    if len(parts) >= 3 and parts[-2] in ('com', 'co', 'org', 'net', 'gov'):
        return '.'.join(parts[:-2])
    if len(parts) >= 2:
        return '.'.join(parts[:-1])
    return domain


def analyze_url(url):
    score = 0
    reasons = []
    lookalike_detected = False

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
            break

    # Check 4: Too many hyphens in domain
    try:
        domain_full = url.split('/')[2]
        if domain_full.count('-') >= 3:
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
        domain_full = url.split('/')[2]
        if domain_full.count('.') >= 3:
            score += 10
            reasons.append("URL has multiple subdomains")
    except IndexError:
        pass

    # Check 8: Lookalike / character-substitution / typo-squatting detection
    domain = extract_domain(url)
    if domain and domain not in TRUSTED_DOMAINS:
        domain_base = _base_name(domain)
        normalized_full = normalize_domain(domain)
        normalized_base = _base_name(normalized_full)

        substitution_match = None
        lookalike_match = None
        typo_match = None
        typo_distance = None

        for trusted in TRUSTED_DOMAINS:
            trusted_base = _base_name(trusted)

            if normalized_full == trusted or normalized_base == trusted_base:
                substitution_match = trusted
                break

            dist = min(
                levenshtein(domain_base, trusted_base),
                levenshtein(domain, trusted),
            )

            if dist == 1 and lookalike_match is None:
                lookalike_match = trusted
            elif 2 <= dist <= 3:
                if typo_distance is None or dist < typo_distance:
                    typo_match = trusted
                    typo_distance = dist

        if substitution_match:
            score += 25
            reasons.append(
                f"Character substitution detected - imitates {substitution_match}"
            )
            lookalike_detected = True
        elif lookalike_match:
            score += 35
            reasons.append(
                f"Domain closely resembles trusted domain: {lookalike_match}"
            )
            lookalike_detected = True
        elif typo_match:
            score += 30
            reasons.append(
                f"Possible typo-squatting detected near: {typo_match}"
            )
            lookalike_detected = True

    # Minimum score rule: lookalike domains must never be Low Risk
    if lookalike_detected and score < 35:
        score = 35

    # Cap score at 100
    score = min(score, 100)

    # Determine risk level based on updated thresholds
    if score <= 25:
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

# features.py
suspicious_keywords = ['login', 'secure', 'update', 'verify', 'bank', 'confirm', 'account', 'free', 'webscr', 'signin']

def extract_features(url: str):
    url = url.lower().strip()
    features = []
    # 1. url length
    features.append(len(url))
    # 2. count of dots
    features.append(url.count('.'))
    # 3. https present (starts with https)
    features.append(1 if url.startswith('https') else 0)
    # 4. presence of @ symbol
    features.append(1 if '@' in url else 0)
    # 5. number of digits
    features.append(sum(c.isdigit() for c in url))
    # 6. suspicious keywords present
    features.append(1 if any(k in url for k in suspicious_keywords) else 0)

    return features

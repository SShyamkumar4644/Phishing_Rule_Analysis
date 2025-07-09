import pandas as pd
from urllib.parse import urlparse
import re
from collections import Counter
import math

# Load Majestic Million CSV (download and provide correct path)
df_majestic = pd.read_csv("majestic_million.csv")  # Replace with your actual path

# Take top 250 domains
top_domains = df_majestic['Domain'].head(250).tolist()

# Prepare URLs with https prefix
legit_urls = [f"https://{domain}" for domain in top_domains]

# Suspicious words, shorteners, known brands (same lists as phishing)
suspicious_words = ["login", "verify", "bank", "secure", "account", "update", "password"]
shorteners = ["bit.ly", "tinyurl", "goo.gl", "ow.ly", "t.co"]
known_brands = ["paypal", "facebook", "google", "amazon", "netflix", "microsoft", "instagram"]

def shannon_entropy(string):
    probabilities = [n_x / len(string) for x, n_x in Counter(string).items()]
    e_x = [-p * math.log2(p) for p in probabilities]
    return sum(e_x)

def extract_features(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc
        path = parsed.path
        query = parsed.query

        if not hostname:
            return None

        subdomain_parts = hostname.split(".")
        num_subdomains = len(subdomain_parts) - 2 if len(subdomain_parts) > 2 else 0

        return {
            "url": url,
            "url_length": len(url),
            "has_https": 1 if url.startswith("https") else 0,
            "has_at_symbol": 1 if "@" in url else 0,
            "num_dots": url.count("."),
            "has_ip_address": 1 if re.match(r"^(http|https)://\d{1,3}(\.\d{1,3}){3}", url) else 0,
            "has_hyphen": 1 if "-" in hostname else 0,
            "num_subdomains": num_subdomains,
            "url_shortener": 1 if any(s in url for s in shorteners) else 0,
            "has_suspicious_words": 1 if any(word in url.lower() for word in suspicious_words) else 0,
            "is_top_level_domain": 1 if hostname.endswith((".gov", ".edu")) else 0,
            "domain_age_days": 0,  # No info, set 0
            "url_has_port": 1 if ":" in hostname and hostname.split(":")[-1].isdigit() else 0,
            "path_length": len(path),
            "num_query_params": len(query.split("&")) if query else 0,
            "has_multiple_slashes": 1 if path.count("/") > 3 else 0,
            "ends_with_file_extension": 1 if re.search(r"\.(html|htm|php|exe|asp|jsp)$", path) else 0,
            "has_email_in_path": 1 if re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", url) else 0,
            "url_entropy": round(shannon_entropy(url), 3),
            "uses_known_brand": 1 if any(b in url.lower() for b in known_brands) else 0,
            "label": "legit"
        }
    except Exception:
        return None

# Extract features for legit URLs
feature_list = []
for url in legit_urls:
    features = extract_features(url)
    if features:
        feature_list.append(features)

df_legit_features = pd.DataFrame(feature_list)

# Save to CSV
df_legit_features.to_csv("legit_features_250.csv", index=False)

print(f"✅ Extracted features for {len(df_legit_features)} legit URLs")
print(df_legit_features.head())

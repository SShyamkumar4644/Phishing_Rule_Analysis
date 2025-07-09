import pandas as pd
from urllib.parse import urlparse
import re
from collections import Counter
import math

# Step 1: Load PhishTank CSV and take only 100 rows
url = "https://data.phishtank.com/data/online-valid.csv"
df_raw = pd.read_csv(url, usecols=["url"])
df_raw = df_raw.head(100)

# Suspicious words, shorteners, known brands
suspicious_words = ["login", "verify", "bank", "secure", "account", "update", "password"]
shorteners = ["bit.ly", "tinyurl", "goo.gl", "ow.ly", "t.co"]
known_brands = ["paypal", "facebook", "google", "amazon", "netflix", "microsoft", "instagram"]

# Function to calculate Shannon entropy
def shannon_entropy(string):
    probabilities = [n_x/len(string) for x, n_x in Counter(string).items()]
    e_x = [-p * math.log2(p) for p in probabilities]
    return sum(e_x)

# Feature extraction function
def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path
    query = parsed.query

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
        "domain_age_days": 0,  # Simulated value

        # Extra features
        "url_has_port": 1 if ":" in hostname and hostname.split(":")[-1].isdigit() else 0,
        "path_length": len(path),
        "num_query_params": len(query.split("&")) if query else 0,
        "has_multiple_slashes": 1 if path.count("/") > 3 else 0,
        "ends_with_file_extension": 1 if re.search(r"\.(html|htm|php|exe|asp|jsp)$", path) else 0,
        "has_email_in_path": 1 if re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", url) else 0,
        "url_entropy": round(shannon_entropy(url), 3),
        "uses_known_brand": 1 if any(b in url.lower() for b in known_brands) else 0,
        "label": "phishing"
    }

# Step 2: Extract features for each URL
feature_list = [extract_features(url) for url in df_raw["url"]]
df_features = pd.DataFrame(feature_list)

# Step 3: Save to CSV
df_features.to_csv("phishing_features_100_new.csv", index=False)

# Step 4: Preview the result
df_features.head()

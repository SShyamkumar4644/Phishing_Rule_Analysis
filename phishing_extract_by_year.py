import pandas as pd
from urllib.parse import urlparse
import re
from collections import Counter
import math

url = "https://data.phishtank.com/data/online-valid.csv"
df_raw = pd.read_csv(url, usecols=["url", "submission_time"])
df_raw["submission_time"] = pd.to_datetime(df_raw["submission_time"], errors='coerce')

years = [2020, 2021, 2022, 2023, 2024, 2025]
rows_per_year = 41  # 41 * 6 = 246 rows total

df_filtered = df_raw[df_raw["submission_time"].dt.year.isin(years)]

sampled_dfs = []
for year in years:
    df_year = df_filtered[df_filtered["submission_time"].dt.year == year]
    sampled = df_year.head(rows_per_year)
    sampled_dfs.append(sampled)

df_sampled = pd.concat(sampled_dfs, ignore_index=True)
df_sampled["submission_year"] = df_sampled["submission_time"].dt.year

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
            "domain_age_days": 0,
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
    except Exception:
        return None

feature_list = []
for _, row in df_sampled.iterrows():
    features = extract_features(row["url"])
    if features:
        features["submission_year"] = row["submission_year"]
        feature_list.append(features)

df_features = pd.DataFrame(feature_list)
df_features.to_csv("phishing_features_250_equal_dist.csv", index=False)

print(f"✅ Extracted features for {len(df_features)} URLs equally from 2020 to 2025 (~250 rows)")
print(df_features.head())

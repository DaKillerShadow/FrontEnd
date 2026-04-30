# =============================================================================
# train_model.py  —  ML Model Training Script (Real Dataset Version)
# =============================================================================

import os
import re
import math
import urllib.parse
import numpy as np
import pandas as pd
from sklearn.ensemble           import RandomForestClassifier
from sklearn.model_selection    import train_test_split
from sklearn.metrics            import classification_report, accuracy_score
import joblib

# ── Reproducibility ───────────────────────────────────────────────────────────
RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)

# ── Output path ───────────────────────────────────────────────────────────────
MODEL_DIR  = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")
os.makedirs(MODEL_DIR, exist_ok=True)


# =============================================================================
# 1. FEATURE EXTRACTION
# =============================================================================
def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log2(p_x)
    return entropy

def extract_features(url):
    """Extracts the 14 numerical features required by the Random Forest model."""
    # Ensure URL has a scheme for accurate parsing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""

        # Feature calculations
        url_length = len(url)
        hostname_length = len(hostname)
        path_length = len(path)
        num_dots = url.count('.')
        num_hyphens = url.count('-')
        num_underscores = url.count('_')
        num_slashes = url.count('/')
        num_query_params = len(urllib.parse.parse_qs(query)) if query else 0
        
        special_chars = set("!@#$%^&*()_+-=[]{};':\"\\|,.<>/?")
        num_special_chars = sum(1 for c in url if c in special_chars)
        
        has_ip_host = 1 if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", hostname) else 0
        has_https = 1 if parsed.scheme == "https" else 0
        has_at_sign = 1 if "@" in url else 0
        subdomain_count = max(0, len(hostname.split('.')) - 2) if hostname else 0
        url_entropy = calculate_entropy(url)

        return [
            url_length, hostname_length, path_length, num_dots, num_hyphens,
            num_underscores, num_slashes, num_query_params, num_special_chars,
            has_ip_host, has_https, has_at_sign, subdomain_count, url_entropy
        ]
    except Exception:
        # Fallback for completely malformed URLs
        return [0] * 14


print("─" * 60)
print("  Phishing URL Detector — Model Training")
print("─" * 60)

# =============================================================================
# 2. LOAD DATA & EXTRACT FEATURES
# =============================================================================
print("\n[1/5] Loading real dataset and extracting features …")
DATA_PATH = "data/training_data.csv"

if not os.path.exists(DATA_PATH):
    raise FileNotFoundError(f"Dataset not found at {DATA_PATH}. Run load_phishtank.py first.")

df = pd.read_csv(DATA_PATH)
urls = df["url"].tolist()
y = df["label"].values

# Apply feature extraction
X_list = [extract_features(url) for url in urls]
X = np.array(X_list)

print(f"    Total samples: {len(y):,}  |  Legitimate: {(y==0).sum():,}  |  Phishing: {(y==1).sum():,}")


# =============================================================================
# 3. TRAIN / TEST SPLIT
# =============================================================================
print("\n[2/5] Splitting into 80% train / 20% test …")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
)
print(f"    Train: {len(X_train):,}   Test: {len(X_test):,}")


# =============================================================================
# 4. MODEL TRAINING
# =============================================================================
print("\n[3/5] Training Random Forest classifier …")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    min_samples_leaf=5,
    random_state=RANDOM_SEED,
    n_jobs=-1,
)
model.fit(X_train, y_train)
print("    Training complete.")


# =============================================================================
# 5. EVALUATION
# =============================================================================
print("\n[4/5] Evaluating on held-out test set …")
y_pred = model.predict(X_test)
acc    = accuracy_score(y_test, y_pred)
print(f"\n    Accuracy: {acc*100:.2f}%\n")
print("    Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

feature_names = [
    "url_length", "hostname_length", "path_length",
    "num_dots", "num_hyphens", "num_underscores",
    "num_slashes", "num_query_params", "num_special_chars",
    "has_ip_host", "has_https", "has_at_sign",
    "subdomain_count", "url_entropy",
]
importances = sorted(
    zip(feature_names, model.feature_importances_),
    key=lambda x: x[1], reverse=True
)
print("    Top 5 most important features:")
for name, imp in importances[:5]:
    bar = "█" * int(imp * 100)
    print(f"      {name:<22} {imp:.4f}  {bar}")


# =============================================================================
# 6. SAVE MODEL
# =============================================================================
print(f"\n[5/5] Saving model to {MODEL_PATH} …")
joblib.dump(model, MODEL_PATH)
print(f"    ✔  Model saved successfully.\n")
print("─" * 60)
print("  You can now start the Flask app:  python app.py")
print("─" * 60)
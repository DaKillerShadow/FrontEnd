import pandas as pd
import os

def load_phishtank(csv_path: str) -> pd.DataFrame:
    """Load PhishTank CSV and return a clean DataFrame with url + label columns."""
    df = pd.read_csv(csv_path, usecols=["url"])
    df = df.dropna(subset=["url"])
    df["label"] = 1  # all PhishTank URLs are phishing
    return df

def load_tranco(tranco_path: str, limit: int = 50000) -> pd.DataFrame:
    """Load Tranco list as legitimate URLs."""
    df = pd.read_csv(tranco_path, header=None, names=["rank", "domain"])
    df = df.head(limit)
    df["url"] = "https://" + df["domain"]
    df["label"] = 0  # legitimate
    return df[["url", "label"]]

def build_dataset(phishtank_csv: str, tranco_csv: str) -> pd.DataFrame:
    phish = load_phishtank(phishtank_csv)
    legit = load_tranco(tranco_csv, limit=len(phish))  # balance the classes
    combined = pd.concat([phish, legit], ignore_index=True)
    return combined.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle

if __name__ == "__main__":
    # Ensure the 'data' directory exists to prevent save errors
    os.makedirs("data", exist_ok=True)
    
    try:
        df = build_dataset(
            phishtank_csv="data/verified_online.csv",
            tranco_csv="data/tranco.csv"
        )
        df.to_csv("data/training_data.csv", index=False)
        print(f"Dataset built: {len(df)} rows ({df['label'].sum()} phishing, {(df['label']==0).sum()} legit)")
    except FileNotFoundError as e:
        print(f"\n[!] File Error: {e}")
        print("[!] Please ensure you have created a 'data' folder in your backend directory.")
        print("[!] Make sure 'verified_online.csv' and 'tranco.csv' are placed inside that 'data' folder.")
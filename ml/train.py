import glob
from pathlib import Path
import numpy as np, pandas as pd, joblib
from lightgbm import LGBMClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from ml.config import FEATURES, FAMILIES, snake, to_family

ROOT = Path(__file__).resolve().parent.parent
CAP = 20000  # max rows per class (lower to 10000 if RAM is tight)

def load_cicids():
    files = glob.glob(str(ROOT / "data" / "raw" / "**" / "*.csv"), recursive=True)
    if not files:
        return None
    wanted = set(FEATURES) | {"label"}
    parts = []
    for f in files:
        d = pd.read_csv(f, encoding="latin1", low_memory=False,
                        usecols=lambda c: snake(c) in wanted)        # only the columns we need
        d.columns = [snake(c) for c in d.columns]
        d["family"] = d["label"].map(to_family)
        d = d.dropna(subset=["family"]).drop(columns="label")
        d = d.replace([np.inf, -np.inf], np.nan).dropna()
        d[FEATURES] = d[FEATURES].astype("float32")
        d = d.drop_duplicates()                                       # remove duplicate flows
        d = pd.concat([g.sample(min(len(g), CAP), random_state=0) for _, g in d.groupby("family")])
        print(f"{Path(f).name}: kept {len(d):,} rows")
        parts.append(d)
    return pd.concat(parts, ignore_index=True).drop_duplicates()

def synthetic(n=4000):
    """Demo data only (NOT real traffic): one random log-normal profile per class."""
    rng = np.random.default_rng(42)
    parts = []
    for i, name in enumerate(["Benign"] + FAMILIES):
        prof = np.random.default_rng(100 + i).normal(3, 1.6, len(FEATURES))
        d = pd.DataFrame(rng.lognormal(prof, 1.8, size=(n, len(FEATURES))), columns=FEATURES)
        d["family"] = name
        parts.append(d)
    return pd.concat(parts, ignore_index=True)

def main():
    df = load_cicids()
    if df is None:
        print("No CSVs in data/raw/ -> using SYNTHETIC demo data")
        df = synthetic()
    else:
        print("Loaded CICIDS2017. Class counts after cleaning:")
        print(df.family.value_counts().to_string())
    df = pd.concat([g.sample(min(len(g), CAP), random_state=0) for _, g in df.groupby("family")])
    train, test = train_test_split(df, test_size=0.2, stratify=df["family"], random_state=0)

    gate = LGBMClassifier(n_estimators=200, verbose=-1)
    gate.fit(train[FEATURES], (train.family != "Benign").astype(int))
    print("== Binary gate ==")
    print(classification_report((test.family != "Benign").astype(int), gate.predict(test[FEATURES]), target_names=["benign", "malicious"]))

    mal_tr, mal_te = train[train.family != "Benign"], test[test.family != "Benign"]
    fam = LGBMClassifier(n_estimators=200, class_weight="balanced", verbose=-1)
    fam.fit(mal_tr[FEATURES], mal_tr.family.map(FAMILIES.index))
    print("== 7-family classifier ==")
    print(classification_report(mal_te.family.map(FAMILIES.index), fam.predict(mal_te[FEATURES]), labels=list(range(len(FAMILIES))), target_names=FAMILIES, zero_division=0))

    (ROOT / "models").mkdir(exist_ok=True)
    joblib.dump({"binary": gate, "family": fam}, ROOT / "models" / "models.joblib")
    test.sample(min(len(test), 1000), random_state=1).to_csv(ROOT / "data" / "sample_flows.csv", index=False)
    print("Saved models/models.joblib and data/sample_flows.csv")

if __name__ == "__main__":
    main()
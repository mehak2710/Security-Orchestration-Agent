from pathlib import Path
import joblib, pandas as pd, shap
from ml.config import FEATURES, FAMILIES

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "models.joblib"

class Detector:
    def __init__(self):
        if not MODEL_PATH.exists():
            raise RuntimeError("models/models.joblib missing - run: python -m ml.train")
        m = joblib.load(MODEL_PATH)
        self.gate, self.fam = m["binary"], m["family"]
        self.explainer = shap.TreeExplainer(self.fam)

    def analyze(self, flow, threshold=0.5):
        X = pd.DataFrame([[float(flow.get(f, 0.0)) for f in FEATURES]], columns=FEATURES)
        p_mal = float(self.gate.predict_proba(X)[0, 1])
        if p_mal < threshold:
            return {"malicious": False, "p_malicious": p_mal}
        probs = self.fam.predict_proba(X)[0]
        k = int(probs.argmax())
        sv = self.explainer.shap_values(X)
        vals = sv[k][0] if isinstance(sv, list) else (sv[0, :, k] if sv.ndim == 3 else sv[0])
        top = sorted(range(len(FEATURES)), key=lambda i: -abs(vals[i]))[:5]
        return {
            "malicious": True, "p_malicious": p_mal,
            "family": FAMILIES[int(self.fam.classes_[k])], "confidence": float(probs[k]),
            "top_features": [{"feature": FEATURES[i], "value": float(X.iloc[0, i]), "shap": float(vals[i])} for i in top],
        }
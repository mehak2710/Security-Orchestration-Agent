import os, re, requests
from ml.config import FEATURES

def _prompt(family, conf, feats, strict):
    lines = "\n".join(f"- {f['feature']} = {f['value']:.4g} (SHAP {f['shap']:+.3f})" for f in feats)
    extra = ("\nSTRICT: mention ONLY the features listed above, copied exactly, each wrapped in backticks. "
             "Do not mention any other metric.") if strict else ""
    return (f"You are a SOC assistant. A network flow was classified as {family} with {conf:.0%} confidence. "
            f"Top SHAP features:\n{lines}\n\nWrite 2-3 sentences for an analyst explaining why. "
            f"Wrap every feature name in backticks and use only these features.{extra}")

def _call_llm(prompt):
    provider = os.getenv("LLM_PROVIDER", "none").lower()
    try:
        if provider == "groq" and os.getenv("GROQ_API_KEY"):
            r = requests.post("https://api.groq.com/openai/v1/chat/completions", timeout=20,
                headers={"Authorization": f"Bearer {os.environ['GROQ_API_KEY']}"},
                json={"model": os.getenv("GROQ_MODEL", "llama-3.1-8b-instant"), "temperature": 0.2, "max_tokens": 250,
                      "messages": [{"role": "user", "content": prompt}]})
            return r.json()["choices"][0]["message"]["content"].strip()
        if provider == "ollama":
            r = requests.post(os.getenv("OLLAMA_URL", "http://localhost:11434") + "/api/generate", timeout=60,
                json={"model": os.getenv("OLLAMA_MODEL", "llama3.1"), "prompt": prompt, "stream": False})
            return r.json()["response"].strip()
    except Exception:
        return None
    return None

def check_grounding(text, feats):
    """Rule-based: every feature name in the text must be in the SHAP output; at least one must be cited."""
    allowed = {f["feature"] for f in feats}
    bad = {t for t in re.findall(r"`([^`]+)`", text) if t not in allowed}
    bad |= {f for f in FEATURES if f not in allowed and re.search(rf"\b{re.escape(f)}\b", text)}
    if not any(a in text for a in allowed):
        bad.add("<no SHAP feature cited>")
    return (not bad), sorted(bad)

def template(family, conf, feats):
    parts = ", ".join(f"`{f['feature']}` ({'raises' if f['shap'] > 0 else 'lowers'} the {family} score)" for f in feats[:3])
    return f"Flow classified as {family} ({conf:.0%} confidence). Strongest drivers: {parts}."

def explain(family, conf, feats):
    """Returns (text, status). status: pass | regenerated | flagged (LLM output unsupported -> template used)."""
    if os.getenv("LLM_PROVIDER", "none").lower() == "none":
        return template(family, conf, feats), "pass"
    for attempt in range(3):
        text = _call_llm(_prompt(family, conf, feats, strict=attempt > 0))
        if text is None:
            return template(family, conf, feats), "pass"  # LLM unavailable -> grounded template
        ok, _ = check_grounding(text, feats)
        if ok:
            return text, "pass" if attempt == 0 else "regenerated"
    return template(family, conf, feats), "flagged"
from functools import lru_cache
from pathlib import Path
import joblib
from src.ml.feature_pipeline import feature_frame
MODEL_PATH=Path(__file__).resolve().parents[1]/'models'/'phishing_model.joblib'
@lru_cache(maxsize=1)
def _load(): return joblib.load(MODEL_PATH)
def predict_url(url):
    try:
        bundle=_load(); model=bundle['model']; probabilities=model.predict_proba(feature_frame([url]))[0]; classes=list(model.classes_); phishing=float(probabilities[classes.index(1)]); legit=float(probabilities[classes.index(0)])
        return {"available":True,"prediction":"PHISHING" if phishing>=.5 else "LEGITIMATE","phishing_probability":round(phishing,6),"legitimate_probability":round(legit,6),"error":None}
    except Exception:
        return {"available":False,"prediction":None,"phishing_probability":None,"legitimate_probability":None,"error":"Model unavailable"}

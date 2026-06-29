import time
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report

from src.scoring import get_features

DATA_PATH = "data/PhiUSIIL.csv"
MODEL_OUT = "src/models/decision_tree.pkl"


def load_training_data():
    df_raw = pd.read_csv(DATA_PATH)
    feature_rows = [get_features(url) for url in df_raw["URL"]]
    X = pd.DataFrame(feature_rows)
    y = 1 - df_raw["label"]  # flip: PhiUSIIL uses 1=legit, we use 0=legit
    return X, y


def train_and_evaluate():
    t0 = time.time()
    X, y = load_training_data()
    print(f"Loaded {len(X)} URLs in {time.time() - t0:.1f}s")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = DecisionTreeClassifier(random_state=42, max_depth=8)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n--- Evaluation on real PhiUSIIL data ---")
    print(classification_report(y_test, y_pred, target_names=["Legit", "Phishing"]))

    print("Feature importances:")
    for name, imp in sorted(zip(X.columns, model.feature_importances_), key=lambda x: -x[1]):
        print(f"  {name}: {imp:.3f}")

    joblib.dump(model, MODEL_OUT)
    print(f"\nSaved model to {MODEL_OUT}")
    return model


if __name__ == "__main__":
    train_and_evaluate()
import os
import joblib
from src.utils.nettoyage import nettoyer_code
from src.utils.dataset import collect_code_samples
from src.models.classifier import build_model

MODEL_PATH = "build/cwe_model.pkl"

def train_if_needed():
    if os.path.exists(MODEL_PATH):
        print("[INFO] Chargement du modèle existant...")
        model = joblib.load(MODEL_PATH)
    else:
        print("[INFO] Entraînement du modèle...")
        data = collect_code_samples("datasets/juliet/extracted")
        codes, labels = zip(*data)
        codes = [nettoyer_code(c) for c in codes]

        model = build_model()
        model.fit(codes, labels)

        os.makedirs("build", exist_ok=True)
        joblib.dump(model, MODEL_PATH)
        print("[INFO] Modèle entraîné et sauvegardé.")
    return model

def predict_file(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Fichier introuvable : {file_path}")

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        raw_code = f.read()

    cleaned_code = nettoyer_code(raw_code)
    model = train_if_needed()
    prediction = model.predict([cleaned_code])
    return prediction[0]

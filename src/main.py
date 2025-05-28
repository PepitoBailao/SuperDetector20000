from src.utils.dataset import collect_code_samples
from src.utils.nettoyage import nettoyer_code
from src.models.classifier import build_model
import joblib
import os

if __name__ == "__main__":
    dataset_root = "datasets/juliet/extracted"
    print("Chargement des données...")
    samples = collect_code_samples(dataset_root)
    codes, labels = [], []
    for code, cwe in samples:
        cleaned = nettoyer_code(code)
        codes.append(cleaned)
        labels.append(cwe)

    print("Entraînement du modèle...")
    model = build_model()
    model.fit(codes, labels)

    os.makedirs("build", exist_ok=True)
    joblib.dump(model, "build/cwe_model.pkl")
    print("Modèle sauvegardé dans build/cwe_model.pkl")
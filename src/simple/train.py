from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pandas as pd
import joblib
import os
import numpy as np
import re
import glob

class SimpleCWEClassifier:
    def __init__(self, max_features=100000, ngram_range=(1, 3), min_df=2, max_df=0.95):
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                token_pattern=r'\b\w+\b', 
                max_features=max_features,
                ngram_range=ngram_range,
                min_df=min_df,
                max_df=max_df,
                stop_words=None,
                lowercase=True,
                dtype=np.float32,
                use_idf=True,
                sublinear_tf=True
            )),
            ('clf', MultinomialNB(alpha=1.0)),
        ])
        self.is_trained = False
    
    def train_from_csv(self, csv_path, test_size=0.1):
        df = pd.read_csv(csv_path, usecols=['code', 'cwe'])
        X = df['code'].fillna('').astype(str)
        y = df['cwe'].fillna('Unknown').astype(str)
        
        valid_mask = (y != 'Unknown') & (y.str.strip() != '') & (X.str.strip() != '')
        X, y = X[valid_mask], y[valid_mask]
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42, stratify=y)
        self.pipeline.fit(X_train, y_train)
        self.is_trained = True
        
        accuracy = accuracy_score(y_test, self.pipeline.predict(X_test))
        print(f"Accuracy: {accuracy:.3f}")
        return self
    
    def predict(self, codes):
        if isinstance(codes, str):
            codes = [codes]
        return self.pipeline.predict(codes)
    
    def predict_proba(self, codes):
        if isinstance(codes, str):
            codes = [codes]
        return self.pipeline.predict_proba(codes)
    
    def save(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # Génère un nom de fichier avec numéro incrémental
        base_path = os.path.splitext(path)[0]  # Sans extension
        extension = os.path.splitext(path)[1]   # .pkl
        
        # Trouve le prochain numéro disponible
        counter = 1
        while True:
            numbered_path = f"{base_path}_{counter:03d}{extension}"
            if not os.path.exists(numbered_path):
                break
            counter += 1
        
        # Sauvegarde avec le numéro
        joblib.dump(self, numbered_path, compress=3)
        
        # Crée aussi un lien symbolique vers la dernière version
        latest_path = f"{base_path}_latest{extension}"
        if os.path.exists(latest_path):
            os.remove(latest_path)
        
        try:
            os.symlink(os.path.basename(numbered_path), latest_path)
        except OSError:
            # Fallback pour systèmes sans support symlink
            import shutil
            shutil.copy2(numbered_path, latest_path)
        
        print(f"Modèle sauvegardé: {numbered_path}")
        print(f"Lien vers dernière version: {latest_path}")
        
        return numbered_path

    @classmethod
    def load_model(cls, path):
        # Si on demande le modèle de base, charge la dernière version
        if not path.endswith('_latest.pkl') and not re.search(r'_\d{3}\.pkl$', path):
            base_path = os.path.splitext(path)[0]
            latest_path = f"{base_path}_latest.pkl"
            if os.path.exists(latest_path):
                path = latest_path
        
        return joblib.load(path)

def clean_code(code):
    code = re.sub(r'//.*?$|/\*.*?\*/', '', code, flags=re.MULTILINE | re.DOTALL)
    code = re.sub(r'\s+', ' ', code)
    return '\n'.join(line.strip() for line in code.splitlines() if line.strip())

def is_supported_file(file_path):
    return file_path.lower().endswith(('.c', '.cpp', '.cxx', '.cc', '.h', '.hpp', '.hxx'))

def read_file(file_path):
    if not is_supported_file(file_path):
        raise ValueError("Unsupported file type")
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

if __name__ == "__main__":
    print("Démarrage de l'entraînement...")
    
    csv_file = "datasets/juliet_cwe_dataset.csv"
    model_path = "build/simple/cwe_model.pkl"
    
    if not os.path.exists(csv_file):
        print(f"ERREUR: Dataset non trouvé à {csv_file}")
        exit(1)
    
    classifier = SimpleCWEClassifier()
    classifier.train_from_csv(csv_file)
    saved_path = classifier.save(model_path)
    
    print(f"Entraînement terminé. Modèle sauvé: {saved_path}")
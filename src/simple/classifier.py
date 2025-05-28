from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pandas as pd
import joblib
import os

class SimpleCWEClassifier:
    def __init__(self, max_features=5000):
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                token_pattern=r'\b\w+\b', 
                max_features=max_features,
                ngram_range=(1, 2),
                min_df=2,
                stop_words=None
            )),
            ('clf', MultinomialNB()),
        ])
    
    def train_from_csv(self, csv_path, test_size=0.2):
        """Train model from CSV file"""
        print(f"Loading data from {csv_path}...")
        df = pd.read_csv(csv_path)
        
        # Prepare data
        X = df['code'].fillna('')
        y = df['cwe'].fillna('Unknown')
        
        # Remove samples with unknown CWE
        valid_mask = y != 'Unknown'
        X = X[valid_mask]
        y = y[valid_mask]
        
        print(f"Training on {len(X)} samples with {y.nunique()} unique CWEs")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Train
        self.pipeline.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.pipeline.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Test accuracy: {accuracy:.4f}")
        
        return self
    
    def predict(self, codes):
        if isinstance(codes, str):
            codes = [codes]
        return self.pipeline.predict(codes)
    
    def predict_proba(self, codes):
        if isinstance(codes, str):
            codes = [codes]
        return self.pipeline.predict_proba(codes)
    
    def save(self, path="build/simple/cwe_model.pkl"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self.pipeline, path)
        print(f"Model saved to {path}")
    
    def load(self, path="build/simple/cwe_model.pkl"):
        self.pipeline = joblib.load(path)
        return self

def build_model():
    """Backward compatibility function"""
    return SimpleCWEClassifier()
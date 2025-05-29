from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pandas as pd
import joblib
import os
import numpy as np
from functools import lru_cache

class SimpleCWEClassifier:
    def __init__(self, max_features=5000):
        self.max_features = max_features
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                token_pattern=r'\b\w+\b', 
                max_features=max_features,
                ngram_range=(1, 2),
                min_df=2,
                stop_words=None,
                lowercase=True,
                strip_accents='unicode',
                dtype=np.float32
            )),
            ('clf', MultinomialNB(alpha=1.0, fit_prior=True)),
        ])
        self.is_trained = False
        self._cache = {}
    
    def train_from_csv(self, csv_path, test_size=0.2):
        df = pd.read_csv(csv_path, usecols=['code', 'cwe'], 
                        dtype={'code': 'string', 'cwe': 'category'})
        X = df['code'].fillna('').astype(str)
        y = df['cwe'].fillna('Unknown')
        valid_mask = y != 'Unknown'
        X, y = X[valid_mask], y[valid_mask]
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        self.pipeline.fit(X_train, y_train)
        self.is_trained = True
        accuracy = accuracy_score(y_test, self.pipeline.predict(X_test))
        print(f"Accuracy: {accuracy:.3f}")
        return self
    
    def predict(self, codes):
        if not self.is_trained:
            raise ValueError("Model not trained")
        if isinstance(codes, str):
            codes = [codes]
        
        results = []
        uncached = []
        indices = []
        
        for i, code in enumerate(codes):
            h = hash(code)
            if h in self._cache:
                results.append(self._cache[h])
            else:
                results.append(None)
                uncached.append(code)
                indices.append(i)
        
        if uncached:
            preds = self.pipeline.predict(uncached)
            for idx, pred in zip(indices, preds):
                self._cache[hash(codes[idx])] = pred
                results[idx] = pred
        
        return np.array(results)
    
    def predict_proba(self, codes):
        if not self.is_trained:
            raise ValueError("Model not trained")
        if isinstance(codes, str):
            codes = [codes]
        return self.pipeline.predict_proba(codes)
    
    @lru_cache(maxsize=128)
    def predict_single(self, code):
        if not self.is_trained:
            raise ValueError("Model not trained")
        return self.pipeline.predict([code])[0]
    
    def save(self, path="build/simple/cwe_model.pkl"):
        if not self.is_trained:
            raise ValueError("Cannot save untrained model")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._cache.clear()
        joblib.dump(self, path, compress=3)
    
    def load(self, path="build/simple/cwe_model.pkl"):
        model = joblib.load(path)
        self.pipeline = model.pipeline
        self.max_features = model.max_features
        self.is_trained = model.is_trained
        self._cache = {}
        return self
    
    @classmethod
    def load_model(cls, path="build/simple/cwe_model.pkl"):
        model = joblib.load(path)
        if hasattr(model, '_cache'):
            model._cache = {}
        return model
    
    def clear_cache(self):
        self._cache.clear()
        self.predict_single.cache_clear()

def build_model():
    return SimpleCWEClassifier()

def predict_batch(model, codes, batch_size=1000):
    results = []
    for i in range(0, len(codes), batch_size):
        batch = codes[i:i + batch_size]
        results.extend(model.predict(batch))
    return np.array(results)
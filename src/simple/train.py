import os
import re
import pickle
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

class SimpleCWEClassifier:
    def __init__(self, max_features=100000, ngram_range=(1, 3), min_df=2, max_df=0.95):
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                max_features=max_features,
                ngram_range=ngram_range,
                min_df=min_df,
                max_df=max_df,
                lowercase=True,
                dtype=np.float32
            )),
            ('clf', MultinomialNB()),
        ])
    
    def train_from_csv(self, csv_path, test_size=0.1):
        df = pd.read_csv(csv_path, usecols=['code', 'cwe'])
        X = df['code'].fillna('').astype(str)
        y = df['cwe'].fillna('Unknown').astype(str)
        
        valid_mask = (y != 'Unknown') & (y.str.strip() != '') & (X.str.strip() != '')
        X, y = X[valid_mask], y[valid_mask]
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        self.pipeline.fit(X_train, y_train)
        
        y_pred = self.pipeline.predict(X_test)
        self.accuracy_ = accuracy_score(y_test, y_pred)
        self.f1_score_ = f1_score(y_test, y_pred, average='weighted')
        self.precision_ = precision_score(y_test, y_pred, average='weighted')
        self.recall_ = recall_score(y_test, y_pred, average='weighted')
        
        return self
    
    def predict(self, codes):
        return self.pipeline.predict(codes)
    
    def predict_proba(self, codes):
        return self.pipeline.predict_proba(codes)
    
    def save(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        with open(path, 'wb') as f:
            pickle.dump(self, f)
        
        latest_path = path.replace('.pkl', '_latest.pkl')
        with open(latest_path, 'wb') as f:
            pickle.dump(self, f)
        
        return path

    @classmethod
    def load_model(cls, path):
        with open(path, 'rb') as f:
            return pickle.load(f)

def clean_code(code):
    code = re.sub(r'//.*?$|/\*.*?\*/', '', code, flags=re.MULTILINE | re.DOTALL)
    return re.sub(r'\s+', ' ', code).strip()

def read_file(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

if __name__ == "__main__":
    csv_file = "datasets/dataset.csv"
    model_path = "build/simple/cwe_model.pkl"
    
    if os.path.exists(csv_file):
        classifier = SimpleCWEClassifier()
        classifier.train_from_csv(csv_file)
        classifier.save(model_path)
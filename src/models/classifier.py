# src/models/classifier.py
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.naive_bayes import MultinomialNB

def build_model():
    model = Pipeline([
        ('tfidf', TfidfVectorizer(token_pattern=r'\b\w+\b', max_features=5000)),
        ('clf', MultinomialNB()),
    ])
    return model
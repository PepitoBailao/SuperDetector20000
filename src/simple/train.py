import numpy as np
import pickle
import pandas as pd
import os
import json
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, classification_report, confusion_matrix
from collections import Counter

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
        
        self.confidence_thresholds = {}
        
        self.cwe_patterns = {
            'CWE119': [r'buffer', r'overflow', r'bounds', r'memcpy', r'strcpy', r'strncpy', r'memset'],
            'CWE120': [r'strcpy', r'strcat', r'sprintf', r'gets', r'vsprintf'],
            'CWE121': [r'stack', r'buffer', r'overflow', r'alloca', r'variable.*length.*array'],
            'CWE122': [r'heap', r'malloc', r'calloc', r'realloc', r'free'],
            'CWE125': [r'read', r'bounds', r'array', r'index', r'out.*of.*bounds'],
            'CWE134': [r'printf', r'format', r'%s', r'%d', r'sprintf', r'snprintf'],
            'CWE190': [r'overflow', r'integer', r'wrap', r'MAX_INT', r'UINT_MAX'],
            'CWE191': [r'underflow', r'integer', r'wrap', r'MIN_INT'],
            'CWE242': [r'gets\s*\(', r'strcpy\s*\(', r'strcat\s*\(', r'sprintf\s*\('],
            'CWE369': [r'divide', r'/\s*0', r'division', r'modulo', r'%\s*0'],
            'CWE476': [r'null', r'NULL', r'nullptr', r'->', r'dereference'],
            'CWE20': [r'input', r'validation', r'sanitize', r'filter', r'validate'],
            'CWE22': [r'\.\./', r'path', r'directory', r'traversal', r'\.\.\\'],
            'CWE78': [r'system\s*\(', r'exec', r'popen', r'shell'],
            'CWE79': [r'<script', r'javascript:', r'xss', r'cross.*site'],
            'CWE89': [r'sql', r'query', r'select', r'insert', r'update', r'delete'],
            'CWE94': [r'eval\s*\(', r'exec\s*\(', r'system\s*\(', r'code.*injection'],
            'CWE131': [r'sizeof', r'malloc', r'buffer.*size', r'allocation'],
            'CWE170': [r'null.*termination', r'string.*length', r'strlen'],
            'CWE401': [r'memory.*leak', r'malloc', r'free', r'delete'],
            'CWE415': [r'double.*free', r'free.*free', r'delete.*delete'],
            'CWE416': [r'use.*after.*free', r'dangling.*pointer', r'freed.*memory'],
            'CWE787': [r'write', r'bounds', r'buffer', r'out.*of.*bounds']
        }
        
        self.cwe_stats = {}
        self.training_stats = {}
    
    def predict(self, X):
        """Predict CWE classes for input data"""
        return self.pipeline.predict(X)
    
    def predict_proba(self, X):
        """Predict class probabilities for input data"""
        return self.pipeline.predict_proba(X)
    
    def _calculate_confidence_thresholds(self, X_val, y_val):
        print("Calculating confidence thresholds...")
        
        y_pred_proba = self.pipeline.predict_proba(X_val)
        y_pred = self.pipeline.predict(X_val)
        classes = self.pipeline.classes_
        
        for i, cwe in enumerate(classes):
            true_indices = np.where(y_val == cwe)[0]
            
            if len(true_indices) == 0:
                self.confidence_thresholds[cwe] = 0.5
                continue
                
            cwe_probas = y_pred_proba[:, i]
            
            thresholds = np.arange(0.1, 1.0, 0.05)
            best_f1 = 0
            best_threshold = 0.5
            
            for threshold in thresholds:
                high_conf_pred = (cwe_probas >= threshold) & (y_pred == cwe)
                
                if np.sum(high_conf_pred) == 0:
                    continue
                    
                tp = np.sum(high_conf_pred & (y_val == cwe))
                fp = np.sum(high_conf_pred & (y_val != cwe))
                fn = np.sum((y_val == cwe) & ~high_conf_pred)
                
                if tp + fp > 0 and tp + fn > 0:
                    precision = tp / (tp + fp)
                    recall = tp / (tp + fn)
                    if precision + recall > 0:
                        f1 = 2 * (precision * recall) / (precision + recall)
                        if f1 > best_f1:
                            best_f1 = f1
                            best_threshold = threshold
            
            self.confidence_thresholds[cwe] = best_threshold
    
    def _validate_with_patterns(self, code, predicted_cwe, confidence):
        if predicted_cwe not in self.cwe_patterns:
            return confidence
        
        patterns = self.cwe_patterns[predicted_cwe]
        code_lower = code.lower()
        
        pattern_matches = 0
        total_patterns = len(patterns)
        
        for pattern in patterns:
            if re.search(pattern, code_lower):
                pattern_matches += 1
        
        if pattern_matches > 0:
            pattern_ratio = pattern_matches / total_patterns
            pattern_boost = min(pattern_ratio * 0.2, 0.2)
            adjusted_confidence = confidence + pattern_boost
        else:
            specific_cwes = ['CWE134', 'CWE242', 'CWE369', 'CWE415', 'CWE416']
            if predicted_cwe in specific_cwes:
                adjusted_confidence = confidence * 0.8
            else:
                adjusted_confidence = confidence
        
        return min(adjusted_confidence, 1.0)
    
    def predict_with_postprocessing(self, codes):
        if isinstance(codes, str):
            codes = [codes]
        
        y_pred = self.pipeline.predict(codes)
        y_pred_proba = self.pipeline.predict_proba(codes)
        
        final_predictions = []
        confidences = []
        
        for i, code in enumerate(codes):
            predicted_cwe = y_pred[i]
            cwe_index = np.where(self.pipeline.classes_ == predicted_cwe)[0][0]
            base_confidence = y_pred_proba[i][cwe_index]
            
            adjusted_confidence = self._validate_with_patterns(code, predicted_cwe, base_confidence)
            
            threshold = self.confidence_thresholds.get(predicted_cwe, 0.5)
            
            if adjusted_confidence >= threshold:
                final_predictions.append(predicted_cwe)
                confidences.append(adjusted_confidence)
            else:
                sorted_indices = np.argsort(y_pred_proba[i])[::-1]
                
                found_alternative = False
                for idx in sorted_indices[1:3]:
                    alt_cwe = self.pipeline.classes_[idx]
                    alt_confidence = y_pred_proba[i][idx]
                    alt_adjusted = self._validate_with_patterns(code, alt_cwe, alt_confidence)
                    alt_threshold = self.confidence_thresholds.get(alt_cwe, 0.5)
                    
                    if alt_adjusted >= alt_threshold:
                        final_predictions.append(alt_cwe)
                        confidences.append(alt_adjusted)
                        found_alternative = True
                        break
                
                if not found_alternative:
                    final_predictions.append("Unknown")
                    confidences.append(0.0)
        
        return final_predictions, confidences
    
    def train_from_csv(self, csv_path, test_size=0.15):
        """Train model from CSV dataset"""
        print(f"Training model from CSV: {csv_path}")
        
        df = pd.read_csv(csv_path, usecols=['code', 'cwe'])
        X = df['code'].fillna('').astype(str)
        y = df['cwe'].fillna('Unknown').astype(str)
        
        valid_mask = (y != 'Unknown') & (y.str.strip() != '') & (X.str.strip() != '')
        X, y = X[valid_mask], y[valid_mask]
        
        print(f"Clean samples: {len(X)}")
        
        cwe_counts = Counter(y)
        min_samples_per_cwe = max(8, int(2 / test_size) + 2)
        valid_cwes = [cwe for cwe, count in cwe_counts.items() if count >= min_samples_per_cwe]
        
        print(f"Usable CWEs: {len(valid_cwes)}")
        
        cwe_mask = y.isin(valid_cwes)
        X, y = X[cwe_mask], y[cwe_mask]
        
        print(f"Final dataset: {len(X)} samples across {len(valid_cwes)} CWEs")
        
        if len(X) == 0:
            raise ValueError("No samples remaining after filtering")
        
        self.training_stats = {
            'total_original_samples': len(df),
            'total_clean_samples': len(X),
            'total_cwes_original': len(cwe_counts),
            'total_cwes_used': len(valid_cwes),
            'min_samples_threshold': min_samples_per_cwe,
            'test_size': test_size
        }
        
        try:
            X_train, X_temp, y_train, y_temp = train_test_split(
                X, y, test_size=test_size*2, random_state=42, stratify=y
            )
            
            X_val, X_test, y_val, y_test = train_test_split(
                X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
            )
            
        except ValueError:
            print("Falling back to non-stratified split")
            
            X_train, X_temp, y_train, y_temp = train_test_split(
                X, y, test_size=test_size*2, random_state=42
            )
            
            X_val, X_test, y_val, y_test = train_test_split(
                X_temp, y_temp, test_size=0.5, random_state=42
            )
        
        print(f"Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")
        
        print("Training model...")
        self.pipeline.fit(X_train, y_train)
        
        self._calculate_confidence_thresholds(X_val, y_val)
        
        y_pred = self.pipeline.predict(X_test)
        self.accuracy_ = accuracy_score(y_test, y_pred)
        self.f1_score_ = f1_score(y_test, y_pred, average='weighted')
        self.precision_ = precision_score(y_test, y_pred, average='weighted')
        self.recall_ = recall_score(y_test, y_pred, average='weighted')
        
        print(f"Training completed: Accuracy={self.accuracy_:.1%}, F1={self.f1_score_:.1%}")
        
        return self
    
    def save(self, path):
        """Save trained model"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        with open(path, 'wb') as f:
            pickle.dump(self, f)
        
        latest_path = path.replace('.pkl', '_latest.pkl')
        with open(latest_path, 'wb') as f:
            pickle.dump(self, f)
        
        print(f"Model saved: {path}")
        return path

    @classmethod
    def load_model(cls, path):
        """Load trained model"""
        with open(path, 'rb') as f:
            return pickle.load(f)

def train_model_from_csv(csv_path="datasets/dataset.csv", model_path="build/simple/cwe_model.pkl"):
    """Main training function"""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found: {csv_path}")
    
    print("Training CWE classifier...")
    
    classifier = SimpleCWEClassifier()
    classifier.train_from_csv(csv_path)
    classifier.save(model_path)
    
    print(f"Training completed successfully")
    print(f"Model saved: {model_path}")
    print(f"Final accuracy: {classifier.accuracy_:.1%}")
    print(f"Final F1-score: {classifier.f1_score_:.1%}")
    print(f"Final precision: {classifier.precision_:.1%}")
    print(f"Final recall: {classifier.recall_:.1%}")
    
    return classifier

if __name__ == "__main__":
    csv_file = "datasets/dataset.csv"
    model_path = "build/simple/cwe_model.pkl"
    
    if os.path.exists(csv_file):
        train_model_from_csv(csv_file, model_path)
    else:
        print(f"Dataset not found: {csv_file}")
        print("Generate dataset first")
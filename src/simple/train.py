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
    
    def analyze_dataset(self, csv_path):
        print("Analyzing dataset...")
        
        df = pd.read_csv(csv_path, usecols=['code', 'cwe'])
        X = df['code'].fillna('').astype(str)
        y = df['cwe'].fillna('Unknown').astype(str)
        
        print(f"Raw dataset: {len(df)} samples")
        
        valid_mask = (y != 'Unknown') & (y.str.strip() != '') & (X.str.strip() != '')
        X_clean, y_clean = X[valid_mask], y[valid_mask]
        
        print(f"After cleaning: {len(X_clean)} samples")
        
        cwe_counts = Counter(y_clean)
        print(f"Total unique CWEs: {len(cwe_counts)}")
        
        count_distribution = Counter(cwe_counts.values())
        print(f"Sample count distribution:")
        for count, num_cwes in sorted(count_distribution.items()):
            print(f"  {num_cwes} CWEs have {count} samples")
        
        most_common = cwe_counts.most_common(5)
        print(f"Top 5 CWEs by sample count:")
        for cwe, count in most_common:
            print(f"  {cwe}: {count} samples")
        
        min_recommended = 10
        usable_cwes = [cwe for cwe, count in cwe_counts.items() if count >= min_recommended]
        
        print(f"CWEs with >= {min_recommended} samples: {len(usable_cwes)}")
        
        return cwe_counts
    
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
            
            # Check if the primary prediction meets the threshold
            if adjusted_confidence >= threshold:
                final_predictions.append(predicted_cwe)
                confidences.append(adjusted_confidence)
            else:
                # Look for alternatives if primary prediction doesn't meet threshold
                sorted_indices = np.argsort(y_pred_proba[i])[::-1]
                
                found_alternative = False
                for idx in sorted_indices[1:3]:  # Check top 2 alternatives
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
    
    def analyze_cwe_performance(self, X_test, y_test):
        print("Analyzing CWE performance...")
        
        y_pred_normal = self.pipeline.predict(X_test)
        y_pred_postproc, confidences = self.predict_with_postprocessing(X_test)
        
        print("Classification report (normal):")
        print(classification_report(y_test, y_pred_normal, zero_division=0))
        
        mask_known = np.array(y_pred_postproc) != "Unknown"
        if np.sum(mask_known) > 0:
            print("Classification report (post-processed):")
            print(classification_report(
                np.array(y_test)[mask_known], 
                np.array(y_pred_postproc)[mask_known], 
                zero_division=0
            ))
        
        unique_cwes = sorted(set(y_test))
        
        print("CWE performance analysis:")
        print(f"{'CWE':<10} {'Samples':<8} {'Precision':<10} {'Recall':<8} {'F1':<8} {'Issues'}")
        print("-" * 80)
        
        cwe_analysis = {}
        
        for cwe in unique_cwes:
            true_mask = y_test == cwe
            pred_mask_postproc = np.array(y_pred_postproc) == cwe
            
            n_samples = np.sum(true_mask)
            
            if n_samples == 0:
                continue
            
            tp = np.sum(true_mask & pred_mask_postproc)
            fp = np.sum(~true_mask & pred_mask_postproc)
            fn = np.sum(true_mask & ~pred_mask_postproc)
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            
            cwe_confidences = [conf for i, conf in enumerate(confidences) 
                             if y_pred_postproc[i] == cwe]
            avg_confidence = np.mean(cwe_confidences) if cwe_confidences else 0
            
            issues = []
            if precision < 0.7:
                issues.append("Low_Prec")
            if recall < 0.7:
                issues.append("Low_Rec")
            if avg_confidence < 0.6:
                issues.append("Low_Conf")
            
            issue_str = ",".join(issues) if issues else "OK"
            
            print(f"{cwe:<10} {n_samples:<8} {precision:<10.3f} {recall:<8.3f} {f1:<8.3f} {issue_str}")
            
            cwe_analysis[cwe] = {
                'samples': n_samples,
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'false_positives': fp,
                'false_negatives': fn,
                'avg_confidence': avg_confidence,
                'threshold': self.confidence_thresholds.get(cwe, 0.5),
                'issues': issues
            }
        
        problematic_cwes = []
        for cwe, stats in cwe_analysis.items():
            if stats['f1'] < 0.6 or len(stats['issues']) > 1:
                problematic_cwes.append((cwe, stats['f1'], stats['issues']))
        
        problematic_cwes.sort(key=lambda x: x[1])
        
        if problematic_cwes:
            print("Most problematic CWEs:")
            for cwe, f1, issues in problematic_cwes[:10]:
                print(f"  {cwe}: F1={f1:.3f}, Issues: {', '.join(issues)}")
        
        acc_normal = accuracy_score(y_test, y_pred_normal)
        acc_postproc = accuracy_score(
            np.array(y_test)[mask_known], 
            np.array(y_pred_postproc)[mask_known]
        ) if np.sum(mask_known) > 0 else 0
        
        unknown_rate = np.sum(np.array(y_pred_postproc) == "Unknown") / len(y_pred_postproc)
        
        print(f"Accuracy normal: {acc_normal:.3f}")
        print(f"Accuracy post-processed: {acc_postproc:.3f}")
        print(f"Unknown rate: {unknown_rate:.3f}")
        print(f"Improvement: {acc_postproc - acc_normal:+.3f}")
        
        self.cwe_stats = cwe_analysis
        return cwe_analysis
    
    def save_analysis_report(self, analysis, output_path="stats/cwe_analysis.json"):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        try:
            json_data = {
                'confidence_thresholds': {k: float(v) for k, v in self.confidence_thresholds.items()},
                'training_stats': {
                    'total_original_samples': int(self.training_stats.get('total_original_samples', 0)),
                    'total_clean_samples': int(self.training_stats.get('total_clean_samples', 0)),
                    'total_cwes_original': int(self.training_stats.get('total_cwes_original', 0)),
                    'total_cwes_used': int(self.training_stats.get('total_cwes_used', 0)),
                    'min_samples_threshold': int(self.training_stats.get('min_samples_threshold', 0)),
                    'test_size': float(self.training_stats.get('test_size', 0.15))
                },
                'cwe_analysis': {},
                'summary': {}
            }
            
            for cwe, stats in analysis.items():
                json_data['cwe_analysis'][cwe] = {
                    'samples': int(stats['samples']),
                    'precision': float(stats['precision']),
                    'recall': float(stats['recall']),
                    'f1': float(stats['f1']),
                    'false_positives': int(stats['false_positives']),
                    'false_negatives': int(stats['false_negatives']),
                    'avg_confidence': float(stats['avg_confidence']),
                    'threshold': float(stats['threshold']),
                    'issues': list(stats['issues'])
                }
            
            f1_scores = [float(stats['f1']) for stats in analysis.values()]
            precision_scores = [float(stats['precision']) for stats in analysis.values()]
            recall_scores = [float(stats['recall']) for stats in analysis.values()]
            confidence_scores = [float(stats['avg_confidence']) for stats in analysis.values()]
            
            json_data['summary'] = {
                'total_cwes': len(analysis),
                'problematic_cwes': len([cwe for cwe, stats in analysis.items() if stats['f1'] < 0.6]),
                'high_performing_cwes': len([cwe for cwe, stats in analysis.items() if stats['f1'] > 0.8]),
                'average_f1': float(sum(f1_scores) / len(f1_scores)) if f1_scores else 0.0,
                'average_precision': float(sum(precision_scores) / len(precision_scores)) if precision_scores else 0.0,
                'average_recall': float(sum(recall_scores) / len(recall_scores)) if recall_scores else 0.0,
                'average_confidence': float(sum(confidence_scores) / len(confidence_scores)) if confidence_scores else 0.0
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            
            print(f"Analysis report saved: {output_path}")
            
        except Exception as e:
            print(f"Failed to save JSON report: {e}")
            
            try:
                text_path = output_path.replace('.json', '.txt')
                with open(text_path, 'w', encoding='utf-8') as f:
                    f.write("CWE ANALYSIS REPORT\n")
                    f.write("=" * 50 + "\n\n")
                    
                    f.write("SUMMARY:\n")
                    f.write(f"Total CWEs: {len(analysis)}\n")
                    f.write(f"Problematic CWEs: {len([cwe for cwe, stats in analysis.items() if stats['f1'] < 0.6])}\n")
                    f.write(f"High performing CWEs: {len([cwe for cwe, stats in analysis.items() if stats['f1'] > 0.8])}\n\n")
                    
                    f.write("DETAILS BY CWE:\n")
                    f.write("-" * 50 + "\n")
                    for cwe, stats in sorted(analysis.items(), key=lambda x: x[1]['f1'], reverse=True):
                        f.write(f"{cwe}: F1={stats['f1']:.3f}, Precision={stats['precision']:.3f}, Recall={stats['recall']:.3f}\n")
                
                print(f"Text report saved: {text_path}")
                
            except Exception as e2:
                print(f"Failed to save text report: {e2}")
    
    def train_from_csv(self, csv_path, test_size=0.15):
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
        
        print(f"Basic metrics: Accuracy={self.accuracy_:.3f}, F1={self.f1_score_:.3f}")
        
        analysis = self.analyze_cwe_performance(X_test, y_test)
        self.save_analysis_report(analysis)
        
        return self
    
    def predict(self, codes):
        predictions, _ = self.predict_with_postprocessing(codes)
        return predictions
    
    def predict_proba(self, codes):
        return self.pipeline.predict_proba(codes)
    
    def save(self, path):
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
        with open(path, 'rb') as f:
            return pickle.load(f)

def clean_code(code):
    code = re.sub(r'//.*?$|/\*.*?\*/', '', code, flags=re.MULTILINE | re.DOTALL)
    return re.sub(r'\s+', ' ', code).strip()

def read_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()

if __name__ == "__main__":
    csv_file = "datasets/dataset.csv"
    model_path = "build/simple/cwe_model.pkl"
    
    if os.path.exists(csv_file):
        print("Training CWE classifier with post-processing...")
        
        classifier = SimpleCWEClassifier()
        
        dataset_stats = classifier.analyze_dataset(csv_file)
        
        classifier.train_from_csv(csv_file)
        classifier.save(model_path)
        
        print("Training completed")
        print(f"Model saved: {model_path}")
        print(f"Final accuracy: {classifier.accuracy_:.3f}")
        print(f"Final F1-score: {classifier.f1_score_:.3f}")
        
    else:
        print(f"Dataset not found: {csv_file}")
        print("Generate dataset first with: python src/utils/dataset.py")
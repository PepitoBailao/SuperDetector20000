class CWEAnalyzer:
    def __init__(self):
        self.data = None
        self.model = None

    def load_data(self, file_path):
        import pandas as pd
        self.data = pd.read_csv(file_path)

    def preprocess_data(self):
        # Implement preprocessing steps such as cleaning and feature extraction
        from utils.helpers import clean_code, extract_features
        
        self.data['cleaned_code'] = self.data['code'].apply(clean_code)
        self.data['features'] = self.data['cleaned_code'].apply(extract_features)

    def train_model(self):
        from models.classifier import Classifier
        
        features = self.data['features'].tolist()
        labels = self.data['cwe_labels'].tolist()
        
        self.model = Classifier()
        self.model.train(features, labels)

    def detect_cwe(self, code_input):
        features = extract_features(clean_code(code_input))
        return self.model.predict(features)
    
#testssss
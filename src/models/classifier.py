class Classifier:
    def __init__(self, model=None):
        self.model = model

    def train(self, X, y):
        from sklearn.ensemble import RandomForestClassifier
        self.model = RandomForestClassifier()
        self.model.fit(X, y)

    def predict(self, X):
        if self.model is None:
            raise ValueError("Model has not been trained yet.")
        return self.model.predict(X)
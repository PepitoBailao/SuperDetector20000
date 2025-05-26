import pandas as pd
from detecteur import CWEAnalyzer

def main():
    # Initialize the CWE Analyzer
    analyzer = CWEAnalyzer()

    # Load the dataset
    data = analyzer.load_data()

    # Preprocess the data
    processed_data = analyzer.preprocess_data(data)

    # Train the model
    analyzer.train_model(processed_data)

    # Example code input for CWE detection
    code_input = "def example_function():\n    return 1 / 0"  # Example of a potential weakness
    detected_cwe = analyzer.detect_cwe(code_input)

    # Output the detected CWE
    print(f"Detected CWE: {detected_cwe}")

if __name__ == "__main__":
    main()
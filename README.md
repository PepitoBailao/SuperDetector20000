# AI CWE Detector

## Overview
The AI CWE Detector is a Python-based project designed to analyze code inputs and detect Common Weakness Enumerations (CWE) using machine learning techniques. The project leverages scikit-learn for model training and prediction, providing a robust framework for identifying potential vulnerabilities in code.

## Project Structure
```
ai-cwe-detector
├── src
│   ├── main.py            # Entry point of the application
│   ├── cwe_detector.py    # Contains the CWEAnalyzer class for detecting CWEs
│   ├── models
│   │   └── classifier.py   # Classifier for training and predicting CWEs
│   └── utils
│       └── helpers.py      # Utility functions for data processing
├── requirements.txt        # Project dependencies
├── .gitignore              # Files and directories to ignore in version control
└── README.md               # Project documentation
```

## Setup Instructions
1. **Clone the repository**:
   ```
   git clone <repository-url>
   cd ai-cwe-detector
   ```

2. **Install dependencies**:
   It is recommended to use a virtual environment. You can create one using:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```
   Then install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Usage Guidelines
1. **Run the application**:
   Execute the main script to start the analysis:
   ```
   python src/main.py
   ```

2. **Input Data**:
   Ensure that the code input is formatted correctly as per the requirements of the `CWEAnalyzer` class.

3. **Output**:
   The application will output detected CWEs based on the provided code input.

## Dataset
The project requires a dataset containing examples of code with known CWEs for training the model. Ensure that the dataset is accessible and properly formatted for use with the `CWEAnalyzer`.

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.
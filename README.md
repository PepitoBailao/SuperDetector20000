# SuperDetector20000

Automatic CWE vulnerability detection for C/C++ code.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

1. **Run the main program:**
```bash
python main.py
```

2. **Follow the automatic pipeline** (dataset download, training, validation)

3. **Choose an option:**
   - `1` : Detection menu (test files or code snippets)
   - `2` : Exit

## Detection Menu

Once in the detection menu:
- `1` : Test a C/C++ file
- `2` : Test a code snippet (paste code then type `END`)
- `3` : Archive current model
- `4` : Exit

## Statistics and Performance

View model metrics: https://pepitobailao.github.io/SuperDetector20000/

## Project Structure

```
SuperDetector20000/
├── main.py              # Main entry point
├── src/simple/          # Training and detection code
├── datasets/            # Vulnerability datasets
├── build/simple/        # Trained models (.pkl)
└── stats/               # Statistics and metrics
```

## Features

- **Automatic training** from Juliet Test Suite dataset
- **Real-time detection** of CWE vulnerabilities
- **Model archiving** with performance tracking
- **Web dashboard** for statistics visualization
- **Command-line interface** for easy testing

## Model Performance

Current model achieves:
- **87.3%** accuracy on test set
- **118** different CWE types supported
- **100K+** training samples processed

## Quick Start

```bash
# Clone and setup
git clone https://github.com/pepitobailao/SuperDetector20000.git
cd SuperDetector20000
pip install -r requirements.txt

# Run setup and training
python main.py

# Test a file
# Choose option 1 in menu, then option 1 to test file
```
import re

def clean_code(code: str) -> str:
    # Function to clean the input code by removing unnecessary whitespace and comments
    cleaned_code = '\n'.join(line.strip() for line in code.splitlines() if line.strip() and not line.strip().startswith('#'))
    return cleaned_code

def extract_features(code: str) -> dict:
    """Extract C/C++ specific features"""
    features = {
        'num_lines': len(code.splitlines()),
        'num_functions': len(re.findall(r'\w+\s*\([^)]*\)\s*\{', code)),
        'num_includes': code.count('#include'),
        'num_pointers': code.count('*'),
        'num_malloc': code.count('malloc'),
        'num_strcpy': code.count('strcpy'),
        'has_gets': 'gets(' in code,           # CWE-120
        'has_scanf': 'scanf(' in code,         # Potential overflow
        'has_buffer_ops': any(func in code for func in ['strcpy', 'strcat', 'sprintf'])
    }
    return features
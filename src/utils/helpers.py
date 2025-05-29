import re

def clean_code(code):
    return '\n'.join(line.strip() for line in code.splitlines() if line.strip() and not line.strip().startswith('#'))

def extract_features(code):
    return {
        'num_lines': len(code.splitlines()),
        'num_functions': len(re.findall(r'\w+\s*\([^)]*\)\s*\{', code)),
        'num_includes': code.count('#include'),
        'num_pointers': code.count('*'),
        'num_malloc': code.count('malloc'),
        'num_strcpy': code.count('strcpy'),
        'has_gets': 'gets(' in code,
        'has_scanf': 'scanf(' in code,
        'has_buffer_ops': any(func in code for func in ['strcpy', 'strcat', 'sprintf'])
    }
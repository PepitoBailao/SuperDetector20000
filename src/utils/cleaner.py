import re

def nettoyer_code(code):
    code = re.sub(r'//.*?$|/\*.*?\*/', '', code, flags=re.MULTILINE | re.DOTALL)
    code = re.sub(r'\s+', ' ', code)
    return '\n'.join(line.strip() for line in code.splitlines() if line.strip())
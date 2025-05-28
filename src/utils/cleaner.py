import re

def nettoyer_code(code: str) -> str:
    """Clean C/C++ code for analysis"""
    # Remove comments
    code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    
    # Remove extra whitespace
    code = re.sub(r'\s+', ' ', code)
    code = '\n'.join(line.strip() for line in code.splitlines() if line.strip())
    
    return code

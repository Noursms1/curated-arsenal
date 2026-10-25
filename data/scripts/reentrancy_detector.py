import sys, json, re

def load_source():
    """يقرأ كود العقد إما من ملف يُمرّر كوسيط أو من stdin"""
    if len(sys.argv) > 1:
        try:
            with open(sys.argv[1], 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            sys.stderr.write(f'خطأ في قراءة الملف: {e}\n')
            sys.exit(1)
    else:
        return sys.stdin.read()

def find_functions(source):
    """يستخرج تعريفات الدوال من الكود"""
    pattern = re.compile(r'function\s+(\w+)\s*\([^)]*\)\s*(public|external|internal|private)?[^{]*{', re.MULTILINE)
    return [m.group(1) for m in pattern.finditer(source)]

def detect_reentrancy(source):
    """يكشف الحالات التي يحدث فيها استدعاء خارجي يليه تعديل حالة"""
    warnings = []
    # تقسيم الكود إلى دوال
    func_pattern = re.compile(r'(function\s+\w+\s*\([^)]*\)\s*(public|external|internal|private)?[^{]*{)(.*?)}', re.DOTALL)
    for func_match in func_pattern.finditer(source):
        header, _, body = func_match.groups()
        func_name_match = re.search(r'function\s+(\w+)', header)
        func_name = func_name_match.group(1) if func_name_match else 'unknown'
        # البحث عن استدعاءات خارجية
        external_calls = re.search(r'(\.call\s*\(|\.call{[^}]*}\s*\(|\.transfer\s*\(|\.send\s*\()', body)
        if external_calls:
            # بعد الاستدعاء، هل هناك تعديل لحالة (مثال: تعديل متغير تخزين أو mapping)
            post_call = body[external_calls.end():]
            state_change = re.search(r'(\b(?:balances?|_?balances?)\s*\[|\bstate\b|\buint\s+\w+\s*=)', post_call)
            if state_change:
                warnings.append({
                    'function': func_name,
                    'issue': 'Potential reentrancy: external call followed by state change',
                    'snippet': body[external_calls.start():external_calls.end()+30].replace('\n', ' ')[:120]
                })
    return warnings

def main():
    source = load_source()
    results = detect_reentrancy(source)
    output = {
        'contract_analysis': {
            'reentrancy_warnings': results,
            'total_warnings': len(results)
        }
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()

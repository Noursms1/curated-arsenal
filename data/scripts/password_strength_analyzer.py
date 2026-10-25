'''Password strength analyzer.

Evaluates a password's strength based on length, character variety,
and common patterns. Reads the password from the first command line
argument or from stdin if no argument is given. Prints a JSON object
with the score (0-100) and feedback.
'''

import sys
import json
import re
import string

def load_password():
    if len(sys.argv) > 1:
        return sys.argv[1]
    return sys.stdin.read().strip()

def has_sequence(pw):
    # detect sequential letters or digits of length >=3
    seq = 'abcdefghijklmnopqrstuvwxyz'
    seq += seq.upper()
    seq += '0123456789'
    for i in range(len(seq) - 2):
        if seq[i:i+3] in pw:
            return True
    return False

def evaluate(pw):
    score = 0
    feedback = []

    length = len(pw)
    if length >= 12:
        score += 30
    elif length >= 8:
        score += 15
    else:
        feedback.append('الطول قصير')

    categories = 0
    if any(c.islower() for c in pw):
        categories += 1
    if any(c.isupper() for c in pw):
        categories += 1
    if any(c.isdigit() for c in pw):
        categories += 1
    if any(c in string.punctuation for c in pw):
        categories += 1

    score += categories * 15
    if categories < 3:
        feedback.append('استخدم أنواع مختلفة من الأحرف')

    if re.search(r'(.)\1{2,}', pw):
        feedback.append('تكرار أحرف متتالية')
        score -= 10

    if has_sequence(pw):
        feedback.append('وجود تسلسل أحرف أو أرقام')
        score -= 10

    score = max(0, min(100, score))
    return {"score": score, "feedback": feedback}

def main():
    pw = load_password()
    result = evaluate(pw)
    json.dump(result, sys.stdout, ensure_ascii=False)

if __name__ == "__main__":
    main()
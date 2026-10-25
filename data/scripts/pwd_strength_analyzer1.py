#!/usr/bin/env python3
"""Advanced password strength analyzer with pattern detection.

Usage:
    echo 'MyP@ssw0rd' | python analyzer.py
    python analyzer.py --password 'secret'
    python analyzer.py --generate 24 --symbols
    python analyzer.py --password 'x' --pretty
"""

import sys
import json
import math
import string
import secrets
import argparse


# ============================================================
# Pattern dictionaries
# ============================================================

COMMON_PASSWORDS = [
    "password", "123456", "12345678", "123456789", "12345", "1234",
    "qwerty", "letmein", "admin", "welcome", "monkey", "dragon",
    "master", "abc123", "password1", "iloveyou", "trustno1",
    "sunshine", "princess", "football", "baseball", "shadow",
    "superman", "batman", "mustang", "michael", "jennifer",
    "jordan", "hunter", "thomas", "robert", "daniel", "matthew",
    "joshua", "andrew", "charles", "jessica", "ashley", "amanda",
    "nicole", "michelle", "stephanie", "orange", "purple", "yellow",
    "qwerty123", "1q2w3e4r", "qazwsx", "123qwe", "666666", "654321",
    "123123", "121212", "111111", "000000", "123abc", "zaq12wsx",
    "asdfgh", "zxcvbn", "q1w2e3r4", "1qaz2wsx", "aaaaaa", "qwertyuiop",
    "asdfghjkl", "zxcvbnm", "changeme", "secret", "letmein123",
]
_DICT_RANK = {p: i + 1 for i, p in enumerate(COMMON_PASSWORDS)}

_SEQ_PATTERNS = [
    "abcdefghijklmnopqrstuvwxyz", "zyxwvutsrqponmlkjihgfedcba",
    "0123456789", "9876543210",
    "qwertyuiop", "poiuytrewq",
    "asdfghjkl", "lkjhgfdsa",
    "zxcvbnm", "mnbvcxz",
]

# Leet substitutions → normal letter
_NORM_MAP = str.maketrans({
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i',
    '+': 't', '|': 'l',
})
_LEET_CHARS = set("0134578@$!+|")


# ============================================================
# Pattern matchers
# ============================================================

def find_dictionary(pwd):
    """Match words from the common-password list, both forward and reversed."""
    matches = []
    n = len(pwd)
    lower = pwd.lower()
    for i in range(n):
        for j in range(i + 3, n + 1):
            sub = lower[i:j]
            token = pwd[i:j]
            hit = None
            reverse = False
            if sub in _DICT_RANK:
                hit = sub
            elif sub[::-1] in _DICT_RANK:
                hit = sub[::-1]
                reverse = True
            if hit is None:
                continue
            rank = _DICT_RANK[hit]
            # Case-variation multiplier (zxcvbn-style)
            if token.islower():
                mult = 1
            elif token.isupper():
                mult = 2
            elif token[0].isupper() and token[1:].islower():
                mult = 2
            else:
                mult = 3
            if reverse:
                mult *= 2
            matches.append({
                'pattern': 'dictionary',
                'start': i, 'end': j - 1, 'token': token,
                'guesses': max(rank, 1) * mult,
            })
    return matches


def find_l33t(pwd):
    """Detect dictionary words disguised with leet substitutions."""
    matches = []
    n = len(pwd)
    for i in range(n):
        for j in range(i + 3, n + 1):
            sub = pwd[i:j]
            if not any(c in _LEET_CHARS for c in sub):
                continue
            norm = sub.lower().translate(_NORM_MAP)
            if norm in _DICT_RANK:
                subs = sum(1 for c in sub if c in _LEET_CHARS)
                rank = _DICT_RANK[norm]
                matches.append({
                    'pattern': 'l33t',
                    'start': i, 'end': j - 1, 'token': sub,
                    'base': norm,
                    'guesses': max(rank, 1) * (2 ** subs),
                })
    return matches


def find_repeat(pwd):
    """Detect character runs ('aaaa') and substring repeats ('abcabc')."""
    matches = []
    n = len(pwd)

    # Single-character runs
    i = 0
    while i < n:
        j = i + 1
        while j < n and pwd[j] == pwd[i]:
            j += 1
        length = j - i
        if length >= 3:
            matches.append({
                'pattern': 'repeat',
                'start': i, 'end': j - 1, 'token': pwd[i:j],
                'guesses': _char_pool_for_char(pwd[i]) * length,
            })
        i = j

    # Substring repeats
    for unit_len in range(2, n // 2 + 1):
        for start in range(n - 2 * unit_len + 1):
            unit = pwd[start:start + unit_len]
            end = start + unit_len
            count = 1
            while end + unit_len <= n and pwd[end:end + unit_len] == unit:
                count += 1
                end += unit_len
            if count >= 2:
                matches.append({
                    'pattern': 'repeat',
                    'start': start, 'end': end - 1,
                    'token': pwd[start:end],
                    'guesses': 26 * unit_len * count * 2,
                })
    return matches


def find_sequential(pwd):
    """Detect runs that appear in known sequences (abc, 123, qwerty, ...)."""
    matches = []
    lower = pwd.lower()
    for pat in _SEQ_PATTERNS:
        for start in range(len(pat)):
            for length in range(3, len(pat) - start + 1):
                seq = pat[start:start + length]
                idx = 0
                while True:
                    pos = lower.find(seq, idx)
                    if pos < 0:
                        break
                    base = 10 if seq[0].isdigit() else 26
                    matches.append({
                        'pattern': 'sequence',
                        'start': pos, 'end': pos + length - 1,
                        'token': pwd[pos:pos + length],
                        'guesses': base * length * 2,
                    })
                    idx = pos + 1
    return matches


def find_date(pwd):
    """Detect plausible years (1900-2099)."""
    import re
    matches = []
    for m in re.finditer(r'(19|20)\d{2}', pwd):
        matches.append({
            'pattern': 'date',
            'start': m.start(), 'end': m.end() - 1,
            'token': m.group(),
            'guesses': 100 * 2,  # 100-year range, two positions
        })
    return matches


def _char_pool_for_char(c):
    if c.islower(): return 26
    if c.isupper(): return 26
    if c.isdigit(): return 10
    if c in string.punctuation: return len(string.punctuation)
    if c.isspace(): return 6
    return 100  # Non-ASCII — rough estimate


def _all_matches(pwd):
    return (find_dictionary(pwd)
            + find_l33t(pwd)
            + find_repeat(pwd)
            + find_sequential(pwd)
            + find_date(pwd))


# ============================================================
# Entropy estimation via DP over the match graph
# ============================================================

def _char_pool(pwd):
    pool = 0
    if any(c.islower() for c in pwd): pool += 26
    if any(c.isupper() for c in pwd): pool += 26
    if any(c.isdigit() for c in pwd): pool += 10
    if any(c in string.punctuation for c in pwd): pool += len(string.punctuation)
    if any(c.isspace() for c in pwd): pool += 6
    non_ascii = {c for c in pwd if not c.isascii()}
    if non_ascii:
        pool += max(32, len(non_ascii))
    return pool


def _estimate_entropy_bits(pwd):
    """Find the cheapest "guess path" through the password.

    Works in log2 space so long passwords don't overflow. Each position
    can be covered either by a pattern match or by a brute-force char,
    and we take the minimum-cost path.
    """
    n = len(pwd)
    if n == 0:
        return 0.0

    pool = _char_pool(pwd)
    log_pool = math.log2(pool) if pool > 0 else 0.0

    by_start = {}
    for m in _all_matches(pwd):
        by_start.setdefault(m['start'], []).append(m)

    INF = float('inf')
    best = [INF] * (n + 1)
    best[0] = 0.0

    for i in range(n):
        if best[i] == INF:
            continue
        # Option 1: brute-force one character
        cand = best[i] + log_pool
        if cand < best[i + 1]:
            best[i + 1] = cand
        # Option 2: apply a pattern starting here
        for m in by_start.get(i, []):
            end = m['end'] + 1
            cand = best[i] + math.log2(max(m['guesses'], 1))
            if cand < best[end]:
                best[end] = cand

    return best[n]


# ============================================================
# Crack-time estimates
# ============================================================

_CRACK_SCENARIOS = {
    # name: guesses per second
    'online_throttled':   10,               # 10/s rate-limited login
    'online_unthrottled': 10_000,           # 10^4/s unrestricted
    'offline_slow_hash':  10_000,           # bcrypt / argon2, 10^4/s
    'offline_fast_hash':  10_000_000_000,   # GPU on MD5/SHA1, 10^10/s
}


def crack_times(entropy_bits):
    # Average attacker finds it after ~half the keyspace
    avg_guesses = 2 ** (entropy_bits - 1)
    return {name: avg_guesses / rate for name, rate in _CRACK_SCENARIOS.items()}


def human_time(seconds):
    if seconds < 1:
        return "instant"
    units = [
        ('century', 100 * 365.25 * 86400),
        ('year', 365.25 * 86400),
        ('month', 30.44 * 86400),
        ('day', 86400),
        ('hour', 3600),
        ('minute', 60),
        ('second', 1),
    ]
    for name, size in units:
        if seconds >= size:
            n = seconds / size
            plural = '' if n < 2 else 's'
            if n >= 1000:
                return f"{n:.2e} {name}{plural}"
            elif n < 10:
                return f"{n:.1f} {name}{plural}"
            else:
                return f"{int(n)} {name}{plural}"
    return "instant"


# ============================================================
# Public analysis
# ============================================================

def _strength_label(entropy):
    if entropy < 28:  return "very weak"
    if entropy < 36:  return "weak"
    if entropy < 60:  return "reasonable"
    if entropy < 80:  return "strong"
    return "very strong"


def _suggestions(pwd, entropy):
    s = []
    if len(pwd) < 8:
        s.append("اجعل كلمة السر 8 أحرف على الأقل")
    elif len(pwd) < 12:
        s.append("فكّر في كلمة سر أطول (12 حرفاً أو أكثر)")
    if not any(c.islower() for c in pwd):
        s.append("أضف أحرفاً صغيرة")
    if not any(c.isupper() for c in pwd):
        s.append("أضف أحرفاً كبيرة")
    if not any(c.isdigit() for c in pwd):
        s.append("أضف أرقاماً")
    if not any(c in string.punctuation for c in pwd):
        s.append("أضف رموزاً خاصة")
    if entropy < 36:
        s.append("تجنّب الكلمات الشائعة والأنماط المتوقعة")
    return s


def analyze(pwd):
    if not pwd:
        return {
            "length": 0,
            "unique_chars": 0,
            "entropy_bits": 0.0,
            "guesses_log10": 0.0,
            "score": 0,
            "score_0_4": 0,
            "strength": "empty",
            "crack_times": {},
            "patterns": [],
            "suggestions": ["كلمة السر فارغة"],
        }

    entropy = _estimate_entropy_bits(pwd)
    times = crack_times(entropy)

    # Surface the detected patterns (deduped, ordered by position)
    seen = set()
    patterns = []
    for m in sorted(_all_matches(pwd), key=lambda x: (x['start'], -x['end'])):
        key = (m['pattern'], m['token'])
        if key in seen:
            continue
        seen.add(key)
        patterns.append({'pattern': m['pattern'], 'token': m['token']})

    score_100 = int(min(100, round(entropy * 100 / 128)))
    score_4 = (
        0 if entropy < 28 else
        1 if entropy < 36 else
        2 if entropy < 60 else
        3 if entropy < 128 else 4
    )

    return {
        "length": len(pwd),
        "unique_chars": len(set(pwd)),
        "entropy_bits": round(entropy, 2),
        "guesses_log10": round(entropy / math.log2(10), 2),
        "score": score_100,
        "score_0_4": score_4,
        "strength": _strength_label(entropy),
        "crack_times": {k: human_time(v) for k, v in times.items()},
        "patterns": patterns,
        "suggestions": _suggestions(pwd, entropy),
    }


# ============================================================
# Generator
# ============================================================

def generate_password(length=20, symbols=True):
    alphabet = string.ascii_letters + string.digits
    if symbols:
        alphabet += string.punctuation
    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        ok = (any(c.islower() for c in pwd)
              and any(c.isupper() for c in pwd)
              and any(c.isdigit() for c in pwd)
              and (not symbols or any(c in string.punctuation for c in pwd)))
        if ok:
            return pwd


# ============================================================
# CLI
# ============================================================

def _read_stdin():
    pwd = sys.stdin.read()
    # Drop exactly one trailing newline; leave everything else intact.
    if pwd.endswith("\r\n"):
        pwd = pwd[:-2]
    elif pwd.endswith("\n") or pwd.endswith("\r"):
        pwd = pwd[:-1]
    return pwd


def _emit(obj, pretty):
    if pretty:
        json.dump(obj, sys.stdout, ensure_ascii=False, indent=2)
    else:
        json.dump(obj, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")


def main():
    parser = argparse.ArgumentParser(description="Advanced password strength analyzer")
    parser.add_argument("--password", help="Analyze this password. Prefer stdin.")
    parser.add_argument("--generate", type=int, metavar="LEN",
                        help="Generate a random password of the given length.")
    parser.add_argument("--symbols", action="store_true",
                        help="Include symbols when generating.")
    parser.add_argument("--pretty", action="store_true",
                        help="Pretty-print JSON output.")
    args = parser.parse_args()

    if args.generate:
        if args.generate < 4:
            parser.error("--generate length must be >= 4")
        pwd = generate_password(args.generate, args.symbols)
        result = analyze(pwd)
        result = {"password": pwd, **result}
        _emit(result, args.pretty)
        return

    pwd = args.password if args.password is not None else _read_stdin()
    _emit(analyze(pwd), args.pretty)


if __name__ == "__main__":
    main()
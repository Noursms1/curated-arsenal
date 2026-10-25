# Review: Jwt Tester

## Overview
Auto-generated review for `jwt_tester`.

## Metadata
- Category: Security - JWT Analysis Tool
- Techniques: N/A
- Functions: 6
- Self-test: Yes
- Standardized JSON: Yes

## Description
CATEGORY: Security - JWT Analysis Tool

This production‑grade script provides three core capabilities for assessing JSON Web Tokens (JWT):
1. **Weakness Detection** – identifies usage of the insecure "none" algorithm.
2. **Algorithm Confusion Check** – attempts to verify a token under mismatched alg## Usage
```
python jwt_tester.py <target>
python jwt_tester.py --self-test
```

## Quality
- [x] Multi-functional
- [x] Self-test
- [x] JSON output

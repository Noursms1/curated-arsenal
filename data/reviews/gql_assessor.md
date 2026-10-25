# Review: Gql Assessor

## Overview
Auto-generated review for `gql_assessor`.

## Metadata
- Category: Security Tool - GraphQL Assessment
- Techniques: N/A
- Functions: 8
- Self-test: Yes
- Standardized JSON: Yes

## Description
CATEGORY: Security Tool - GraphQL Assessment

This tool performs three main capabilities against a target host:
1. GraphQL endpoint discovery (common paths probing).
2. GraphQL introspection query execution to retrieve the schema.
3. Basic IDOR testing on discovered mutations that accept an `id` arg## Usage
```
python gql_assessor.py <target>
python gql_assessor.py --self-test
```

## Quality
- [x] Multi-functional
- [x] Self-test
- [x] JSON output

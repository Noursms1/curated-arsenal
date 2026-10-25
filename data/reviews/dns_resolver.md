# Review: Fast DNS Resolver

## Overview
This tool was initially generated as a micro-script, then refined for production use.

## Features
- Fast IPv4 resolution.
- Clean JSON output for easy parsing.
- Error handling for non-existent domains.

## When to use it?
Use this tool in the **Passive Reconnaissance** phase to map out the target's infrastructure before active scanning.

## Test Results
- Tested on `example.com`: PASS
- Tested on `non-existent-domain-xyz.com`: PASS (Graceful error)
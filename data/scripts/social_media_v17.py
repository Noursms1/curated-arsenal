# CATEGORY: OSINT
# PREMORTEM:
# failure_mode: Rate limiting leads to HTTP 429 responses, causing the tool to stop collecting data.
# failure_mode: Changes in target site HTML structure break parsing logic, resulting in empty findings.
# failure_mode: Network instability causes unhandled exceptions, crashing the tool.
# early_warning: Consecutive HTTP 429 responses exceed 3.
# early_warning: Parsing error count exceeds 5.
# early_warning: Uncaught exception count exceeds 2.

import argparse
import json
import sys
import time
import logging
from collections import Counter

import requests
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

TOOL_NAME = "SocialMediaOSINT"
VERSION = "1.0.0"

# Global counters for early warning detection
counters = Counter()


def safe_request(url, headers=None, params=None):
    """Wrapper for requests.get with timeout, error handling and rate‑limit detection."""
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 429:
            counters["http_429"] += 1
            logger.warning("Rate limited (429) on %s", url)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        counters["request_exceptions"] += 1
        logger.error("Request error for %s: %s", url, e)
        return None


def parse_twitter(username):
    """Scrape public Twitter profile page for basic info and recent tweets."""
    base_url = f"https://twitter.com/{username}"
    resp = safe_request(base_url, headers={"User-Agent": "Mozilla/5.0"})
    if not resp:
        return {}

    soup = BeautifulSoup(resp.text, "html.parser")
    # Basic profile info
    name_tag = soup.find("title")
    display_name = name_tag.text.strip() if name_tag else ""

    # Recent tweets (publicly visible)
    tweets = []
    tweet_tags = soup.select('article div[lang]')
    for tag in tweet_tags[:5]:  # limit to 5 recent tweets
        tweets.append(tag.get_text(strip=True))
        time.sleep(0.5)

    if not display_name and not tweets:
        counters["parsing_errors"] += 1
        logger.warning("Twitter parsing yielded no data for %s", username)

    return {
        "platform": "twitter",
        "display_name": display_name,
        "recent_tweets": tweets,
    }


def parse_instagram(username):
    """Scrape public Instagram profile page for bio and recent posts."""
    base_url = f"https://www.instagram.com/{username}/?__a=1"
    resp = safe_request(base_url, headers={"User-Agent": "Mozilla/5.0"})
    if not resp:
        return {}

    try:
        data = resp.json()
        user = data.get("graphql", {}).get("user", {})
        bio = user.get("biography", "")
        recent_posts = [
            edge["node"]["edge_media_to_caption"]["edges"][0]["node"]["text"]
            for edge in user.get("edge_owner_to_timeline_media", {}).get("edges", [])[:5]
        ]
        return {
            "platform": "instagram",
            "bio": bio,
            "recent_posts": recent_posts,
        }
    except (ValueError, KeyError, IndexError) as e:
        counters["parsing_errors"] += 1
        logger.error("Instagram JSON parsing error for %s: %s", username, e)
        return {}


def parse_reddit(username):
    """Use Reddit's public JSON endpoint to fetch user overview."""
    base_url = f"https://www.reddit.com/user/{username}/about.json"
    resp = safe_request(base_url, headers={"User-Agent": "Mozilla/5.0"})
    if not resp:
        return {}

    try:
        data = resp.json()
        user = data.get("data", {})
        comment_karma = user.get("comment_karma", 0)
        link_karma = user.get("link_karma", 0)
        created_utc = user.get("created_utc", 0)

        # Recent submissions
        submissions_url = f"https://www.reddit.com/user/{username}/submitted.json"
        sub_resp = safe_request(submissions_url, headers={"User-Agent": "Mozilla/5.0"})
        recent_titles = []
        if sub_resp:
            sub_data = sub_resp.json()
            for child in sub_data.get("data", {}).get("children", [])[:5]:
                recent_titles.append(child["data"].get("title", ""))
                time.sleep(0.5)

        return {
            "platform": "reddit",
            "comment_karma": comment_karma,
            "link_karma": link_karma,
            "account_created_utc": created_utc,
            "recent_submissions": recent_titles,
        }
    except (ValueError, KeyError) as e:
        counters["parsing_errors"] += 1
        logger.error("Reddit parsing error for %s: %s", username, e)
        return {}


def run_checks(target):
    findings = []
    results = {}

    # Twitter
    tw = parse_twitter(target)
    if tw:
        findings.append("twitter")
        results["twitter"] = tw

    # Instagram
    ig = parse_instagram(target)
    if ig:
        findings.append("instagram")
        results["instagram"] = ig

    # Reddit
    rd = parse_reddit(target)
    if rd:
        findings.append("reddit")
        results["reddit"] = rd

    status = "success" if findings else "no_data"
    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": target,
        "status": status,
        "findings": findings,
        "results": results,
    }


def early_warning_check():
    warnings = []
    if counters["http_429"] > 3:
        warnings.append("High rate‑limit (429) count")
    if counters["parsing_errors"] > 5:
        warnings.append("Frequent parsing errors")
    if counters["request_exceptions"] > 2:
        warnings.append("Multiple request exceptions")
    return warnings


def self_test():
    test_user = "spez"  # Reddit co‑founder, public profile on all platforms
    logger.info("Running self‑test with target: %s", test_user)
    output = run_checks(test_user)
    warnings = early_warning_check()
    output["self_test_warnings"] = warnings
    print(json.dumps(output, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Social Media OSINT tool")
    parser.add_argument("target", nargs="?", help="Username to investigate")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.target:
        logger.error("Target username is required unless --self-test is used.")
        sys.exit(1)

    result = run_checks(args.target)
    warnings = early_warning_check()
    if warnings:
        result["early_warnings"] = warnings

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
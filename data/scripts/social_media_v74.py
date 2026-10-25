# CATEGORY: OSINT - Social Media Enumeration Tool
import argparse
import json
import sys
import time
import requests

TOOL_NAME = "SocialMediaOSINT"
VERSION = "1.0.0"
USER_AGENT = "SocialMediaOSINT/1.0 (+https://github.com/example)"


def fetch_twitter_info(username):
    """Fetch basic Twitter user info via public endpoint."""
    url = f"https://cdn.syndication.twimg.com/widgets/followbutton/info.json?screen_names={username}"
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        time.sleep(0.5)
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list) and data:
            user = data[0]
            return {
                "id": user.get("id_str"),
                "name": user.get("name"),
                "screen_name": user.get("screen_name"),
                "description": user.get("description"),
                "followers_count": user.get("followers_count"),
                "following_count": user.get("friends_count"),
                "profile_image_url": user.get("profile_image_url_https"),
            }
        else:
            return {"error": "User not found or empty response"}
    except Exception as e:
        return {"error": str(e)}


def fetch_instagram_info(username):
    """Fetch public Instagram profile info."""
    url = f"https://www.instagram.com/{username}/?__a=1&__d=dis"
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        time.sleep(0.5)
        resp.raise_for_status()
        data = resp.json()
        user = data.get("graphql", {}).get("user", {})
        if not user:
            return {"error": "User not found or unexpected response"}
        return {
            "id": user.get("id"),
            "username": user.get("username"),
            "full_name": user.get("full_name"),
            "biography": user.get("biography"),
            "followers": user.get("edge_followed_by", {}).get("count"),
            "following": user.get("edge_follow", {}).get("count"),
            "profile_pic_url": user.get("profile_pic_url_hd") or user.get("profile_pic_url"),
        }
    except Exception as e:
        return {"error": str(e)}


def fetch_reddit_info(username):
    """Fetch Reddit user public profile."""
    url = f"https://www.reddit.com/user/{username}/about.json"
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        time.sleep(0.5)
        resp.raise_for_status()
        data = resp.json()
        user = data.get("data", {})
        if not user:
            return {"error": "User not found or unexpected response"}
        return {
            "id": user.get("id"),
            "name": user.get("name"),
            "created_utc": user.get("created_utc"),
            "link_karma": user.get("link_karma"),
            "comment_karma": user.get("comment_karma"),
            "total_karma": user.get("total_karma"),
            "is_gold": user.get("is_gold"),
            "has_verified_email": user.get("has_verified_email"),
        }
    except Exception as e:
        return {"error": str(e)}


def run_self_test():
    """Execute basic self‑tests for each capability."""
    test_cases = {
        "twitter": ("TwitterDev", fetch_twitter_info),
        "instagram": ("instagram", fetch_instagram_info),
        "reddit": ("spez", fetch_reddit_info),
    }
    results = {}
    overall_status = "success"
    for platform, (user, func) in test_cases.items():
        out = func(user)
        if out.get("error"):
            overall_status = "error"
            results[platform] = {"status": "fail", "detail": out["error"]}
        else:
            results[platform] = {"status": "pass", "detail": f"Fetched {len(out)} fields"}
    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": "self-test",
        "status": overall_status,
        "findings": ["Self‑test completed"],
        "results": results,
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description="OSINT tool for public social media profiles.")
    parser.add_argument("-t", "--target", help="Username or handle to query", required=False)
    parser.add_argument("-p", "--platform", choices=["twitter", "instagram", "reddit", "all"], default="all",
                        help="Platform to query")
    parser.add_argument("--self-test", action="store_true", help="Run internal self‑tests and exit")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        sys.exit(0)

    if not args.target:
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": VERSION,
            "target": None,
            "status": "error",
            "findings": ["No target specified"],
            "results": {}
        }, indent=2, ensure_ascii=False))
        sys.exit(1)

    findings = []
    results = {}
    status = "success"

    platforms = [args.platform] if args.platform != "all" else ["twitter", "instagram", "reddit"]

    for platform in platforms:
        if platform == "twitter":
            data = fetch_twitter_info(args.target)
        elif platform == "instagram":
            data = fetch_instagram_info(args.target)
        elif platform == "reddit":
            data = fetch_reddit_info(args.target)
        else:
            continue

        if data.get("error"):
            findings.append(f"{platform.capitalize()} error: {data['error']}")
            status = "partial" if status == "success" else status
            results[platform] = {"error": data["error"]}
        else:
            findings.append(f"{platform.capitalize()} data retrieved")
            results[platform] = data

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": args.target,
        "status": status,
        "findings": findings,
        "results": results,
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
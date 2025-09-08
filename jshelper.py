#!/usr/bin/env python3
import argparse
import requests
import re
import sys

# Secret regex patterns
_regex = {
    'google_api': r'AIza[0-9A-Za-z-_]{35}',
    'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id': r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke': r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url': r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2': r"([a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com"
                       r"|s3://[a-zA-Z0-9-\.\_]+"
                       r"|s3-[a-zA-Z0-9-\.\_/]+"
                       r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+"
                       r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    'facebook_access_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic': r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer': r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'authorization_api': r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key': r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid': r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid': r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret': r'sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token': r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api': r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api': r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token': r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key': r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key': r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key': r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token': r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey': r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'possible_Creds': r"(?i)("
                      r"password\s*[`=:\"]+\s*[^\s]+|"
                      r"password is\s*[`=:\"]*\s*[^\s]+|"
                      r"pwd\s*[`=:\"]*\s*[^\s]+|"
                      r"passwd\s*[`=:\"]+\s*[^\s]+)",
}


def fetch_js(url):
    """Fetch JavaScript file from given URL."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response else ""
        print(f"[ + ] URL: {url} {status}")
        return None
    except requests.exceptions.RequestException as e:
        status = e.response.status_code if hasattr(e, "response") and e.response else ""
        print(f"[ + ] URL: {url} {status}")
        return None


def normalize_links(links):
    """Convert protocol-relative URLs into HTTPS full URLs."""
    normalized = []
    for link in links:
        if link.startswith("//"):
            normalized.append("https:" + link)
        else:
            normalized.append(link)
    return sorted(set(normalized))


def extract_links(js_content):
    """Extract links, normalize protocol-relative URLs."""
    if not js_content:
        return {"full_urls": [], "endpoints": []}

    full_urls = re.findall(r"https?://[^\s\"'<>]+", js_content)
    relative_urls = re.findall(r"//[a-zA-Z0-9./?=_-]+", js_content)
    endpoints = re.findall(r"/[a-zA-Z0-9/_-]+(?:\.[a-zA-Z0-9]+)?", js_content)

    all_full_urls = normalize_links(full_urls + relative_urls)

    return {
        "full_urls": all_full_urls,
        "endpoints": sorted(set(endpoints)),
    }


def extract_secrets(js_content):
    """Extract secrets based on predefined regex patterns."""
    found = {}
    for name, pattern in _regex.items():
        matches = re.findall(pattern, js_content, re.IGNORECASE | re.MULTILINE)
        if matches:
            found[name] = sorted(set(matches))
    return found


def save_output(filename, all_results):
    """Save extracted data into file in prefixed format."""
    try:
        with open(filename, "w") as f:
            for url, results in all_results.items():
                f.write(f"[ + ] URL: {url}\n")
                if "full_urls" in results:
                    for u in results["full_urls"]:
                        f.write(f"    [Full URL] {u}\n")
                if "endpoints" in results:
                    for ep in results["endpoints"]:
                        f.write(f"    [Endpoint] {ep}\n")
                if "secrets" in results:
                    for key, values in results["secrets"].items():
                        for v in values:
                            f.write(f"    {key}\t->\t{v}\n")
                f.write("\n")

        print(f"[*] Results saved to {filename}")
    except Exception as e:
        print(f"[!] Error writing to file: {e}", file=sys.stderr)


def process_url(url, extract_flag, secrets_flag):
    """Fetch and process a single URL."""
    js_content = fetch_js(url)
    if not js_content:
        return None

    results = {}
    if extract_flag:
        results.update(extract_links(js_content))
    if secrets_flag:
        results["secrets"] = extract_secrets(js_content)

    return results if results else None


def main():
    parser = argparse.ArgumentParser(
        description="Extract links, paths, endpoints, and secrets from JavaScript files"
    )
    parser.add_argument("-u", "--url", help="Target JavaScript file URL")
    parser.add_argument("-f", "--file", help="File containing multiple JS URLs")
    parser.add_argument("-o", "--output", help="Output file (plain text)", required=False)
    parser.add_argument("-links", action="store_true", help="Extract links from JS")
    parser.add_argument("-secrets", action="store_true", help="Extract secrets from JS")

    args = parser.parse_args()

    urls = []

    if args.url:
        urls.append(args.url.strip())
    elif args.file:
        try:
            with open(args.file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        urls.append(line)
        except Exception as e:
            print(f"[!] Error reading file {args.file}: {e}", file=sys.stderr)
            sys.exit(1)
    elif not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line:
                urls.append(line)

    if not urls:
        print("[!] No URL provided. Use -u, -f, or pipe via stdin.", file=sys.stderr)
        sys.exit(1)

    all_results = {}

    for url in urls:
        results = process_url(url, args.links, args.secrets)
        if not results or not any(results.values()):
            continue

        print(f"[ + ] URL: {url}")
        all_results[url] = results

        if args.links and "full_urls" in results:
            for u in results["full_urls"]:
                print(f"    [Full URL] {u}")
            for ep in results["endpoints"]:
                print(f"    [Endpoint] {ep}")

        if args.secrets and "secrets" in results:
            for key, values in results["secrets"].items():
                for v in values:
                    print(f"    {key}\t->\t{v}")

    if args.output and all_results:
        save_output(args.output, all_results)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
import argparse
import requests
import re
import sys


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
        # Covers timeouts, SSL errors, connection issues
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

    # Extract patterns
    full_urls = re.findall(r"https?://[^\s\"'<>]+", js_content)
    relative_urls = re.findall(r"//[a-zA-Z0-9./?=_-]+", js_content)
    endpoints = re.findall(r"/[a-zA-Z0-9/_-]+(?:\.[a-zA-Z0-9]+)?", js_content)

    # Normalize relative URLs to full HTTPS
    all_full_urls = normalize_links(full_urls + relative_urls)

    return {
        "full_urls": all_full_urls,
        "endpoints": sorted(set(endpoints)),
    }


def save_output(filename, all_results):
    """Save extracted data into file in prefixed format."""
    try:
        with open(filename, "w") as f:
            for url, results in all_results.items():
                f.write(f"[ + ] URL: {url}\n")
                for u in results["full_urls"]:
                    f.write(f"    [Full URL] {u}\n")
                for ep in results["endpoints"]:
                    f.write(f"    [Endpoint] {ep}\n")
                f.write("\n")

        print(f"[*] Results saved to {filename}")
    except Exception as e:
        print(f"[!] Error writing to file: {e}", file=sys.stderr)


def process_url(url, extract_flag):
    """Fetch and process a single URL."""
    js_content = fetch_js(url)
    if not js_content:
        return None

    if extract_flag:
        return extract_links(js_content)
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Extract links, paths, and endpoints from JavaScript files"
    )
    parser.add_argument("-u", "--url", help="Target JavaScript file URL")
    parser.add_argument("-f", "--file", help="File containing multiple JS URLs")
    parser.add_argument("-o", "--output", help="Output file (plain text)", required=False)
    parser.add_argument("-links", action="store_true", help="Extract links from JS")

    args = parser.parse_args()

    urls = []

    # Case 1: URL passed via -u
    if args.url:
        urls.append(args.url.strip())

    # Case 2: File input via -f
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

    # Case 3: Read multiple URLs from stdin
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
        results = process_url(url, args.links)
        if not results or not any(results.values()):
            continue  # skip empty results

        # Print URL in the requested format
        print(f"[ + ] URL: {url}")

        all_results[url] = results

        # Optional: print extracted links/endpoints under each URL
        if args.links:
            for u in results["full_urls"]:
                print(f"    [Full URL] {u}")
            for ep in results["endpoints"]:
                print(f"    [Endpoint] {ep}")

    if args.output and all_results:
        save_output(args.output, all_results)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""Audit static site files or a published origin; this does not test Google indexing."""

import argparse
from collections import Counter
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urldefrag, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import xml.etree.ElementTree as ET


class Document(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.h1_count = 0
        self.ids = []
        self.canonicals = []
        self.robots = []
        self.resources = set()
        self.links = []
        self.json_ld = []
        self.base = None
        self._json_parts = None
        self.feed(source)
        self.close()

    def handle_starttag(self, tag, attributes):
        attrs = {key: value or "" for key, value in attributes}
        if attrs.get("id"):
            self.ids.append(attrs["id"])
        if tag == "h1":
            self.h1_count += 1
        if tag == "base" and self.base is None:
            self.base = attrs.get("href")
        if tag == "link":
            rel = attrs.get("rel", "").lower().split()
            if "canonical" in rel:
                self.canonicals.append(attrs.get("href", ""))
            if set(rel) & {"stylesheet", "icon", "preload", "modulepreload", "apple-touch-icon"}:
                self.resources.add(attrs.get("href", ""))
        if tag == "meta":
            name = attrs.get("name", "").lower()
            if name in {"robots", "googlebot"}:
                self.robots.append(attrs.get("content", ""))
            if attrs.get("property", "").lower() == "og:image" or name == "twitter:image":
                self.resources.add(attrs.get("content", ""))
        if tag in {"script", "img", "source", "video", "audio", "iframe", "input"}:
            if attrs.get("src"):
                self.resources.add(attrs["src"])
            if attrs.get("poster"):
                self.resources.add(attrs["poster"])
            # Data URLs need no HTTP/file check and contain their own commas.
            srcset = attrs.get("srcset", "")
            if srcset and "data:" not in srcset:
                self.resources.update(item.strip().split()[0] for item in srcset.split(",") if item.strip())
        if tag == "a" and attrs.get("href") is not None:
            self.links.append(attrs["href"])
        if tag == "script" and attrs.get("type", "").lower() == "application/ld+json":
            self._json_parts = []

    def handle_data(self, data):
        if self._json_parts is not None:
            self._json_parts.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._json_parts is not None:
            self.json_ld.append("".join(self._json_parts))
            self._json_parts = None


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def googlebot_can_fetch(source, url):
    """Match Google's groups, wildcards, longest rule and allow-on-tie policy."""
    groups, agents, rules = [], [], []
    saw_rule = False
    for line in source.splitlines():
        field, separator, value = line.split("#", 1)[0].partition(":")
        if not separator:
            continue
        field, value = field.strip().lower(), value.strip()
        if field == "user-agent":
            if saw_rule:
                groups.append((agents, rules))
                agents, rules, saw_rule = [], [], False
            agents.append(value.lower())
        elif field in {"allow", "disallow"} and agents:
            saw_rule = True
            if value:
                rules.append((field == "allow", value))
    groups.append((agents, rules))
    specific = [rules for agents, rules in groups
                if any(re.match(r"^googlebot(?:[^a-z_-]|$)", agent) for agent in agents)]
    applicable = specific or [rules for agents, rules in groups if "*" in agents]
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    safe = "/?&=:+,;%@!$'()*~-"
    path = quote(path, safe=safe)
    matches = []
    for rules in applicable:
        for allowed, rule in rules:
            rule = quote(rule, safe=safe).rstrip("*")
            end = "$" if rule.endswith("$") else ""
            pattern = rule[:-1] if end else rule
            pattern = "^" + re.escape(pattern).replace(r"\*", ".*") + end
            if re.search(pattern, path):
                matches.append((len(rule), allowed))
    return max(matches, default=(0, True))[1]


class Audit:
    def __init__(self, directory, live_url=None):
        self.directory = directory
        self.live = live_url is not None
        self.origin = live_url
        self.failures = 0
        self.cache = {}
        self.opener = build_opener(NoRedirect)

    def check(self, condition, message):
        print(f"{'OK' if condition else 'FAIL'}: {message}")
        self.failures += not condition
        return condition

    def read(self, url):
        url = urldefrag(url)[0]
        if url in self.cache:
            return self.cache[url]
        try:
            if self.live:
                request = Request(url, headers={"User-Agent": "MonolitSiteAudit/1.0"})
                with self.opener.open(request, timeout=15) as response:
                    if response.status != 200:
                        raise ValueError(f"HTTP {response.status}, expected 200")
                    result = (response.read(), response.headers)
            else:
                path = self.directory / unquote(urlsplit(url).path).lstrip("/")
                if path.is_dir():
                    path /= "index.html"
                path = path.resolve()
                if not path.is_relative_to(self.directory):
                    raise ValueError("path escapes the site directory")
                result = (path.read_bytes(), {})
        except (OSError, URLError, ValueError) as error:
            detail = f"HTTP {error.code}" if isinstance(error, HTTPError) else str(error)
            self.check(False, f"Cannot read {url}: {detail}")
            result = None
        self.cache[url] = result
        return result

    def internal(self, reference, base=None):
        absolute = urljoin(base or self.origin, reference)
        parsed = urlsplit(absolute)
        if parsed.scheme not in {"http", "https"}:
            return None
        if parsed.netloc.lower() != urlsplit(self.origin).netloc.lower():
            return None
        return absolute

    def run(self):
        if self.live:
            homepage = self.read(self.origin)
        else:
            try:
                homepage = ((self.directory / "index.html").read_bytes(), {})
            except OSError as error:
                self.check(False, f"Cannot read index.html: {error}")
                return
        if homepage is None:
            return
        self.check(True, "Homepage is readable" + (" with HTTP 200" if self.live else " on disk"))
        try:
            document = Document(homepage[0].decode("utf-8-sig"))
        except (UnicodeError, ValueError) as error:
            self.check(False, f"Cannot parse homepage HTML: {error}")
            return

        self.check(document.h1_count == 1, f"Exactly one H1 (found {document.h1_count})")
        duplicates = sorted(key for key, count in Counter(document.ids).items() if count > 1)
        self.check(not duplicates, "Unique HTML IDs" + (f": duplicates {duplicates}" if duplicates else ""))
        has_canonical = self.check(len(document.canonicals) == 1, "Exactly one canonical URL")
        canonical = document.canonicals[0] if has_canonical else ""
        parsed = urlsplit(canonical)
        valid_canonical = (parsed.scheme in {"http", "https"} and bool(parsed.netloc)
                           and parsed.path == "/" and not parsed.query and not parsed.fragment)
        self.check(valid_canonical, "Canonical is an absolute site root URL ending in /")
        if not self.live:
            self.origin = canonical if valid_canonical else "https://local.invalid/"
        self.cache[self.origin] = homepage
        self.check(canonical == self.origin, f"Canonical matches the audited root: {self.origin}")
        directives = list(document.robots)
        headers = homepage[1]
        header_values = headers.get_all("X-Robots-Tag", []) if self.live else []
        # Ignore crawler-specific header rules for bots other than Googlebot.
        for value in header_values:
            scope = None
            for part in value.split(","):
                if ":" in part:
                    agent, rule = part.split(":", 1)
                    if agent.strip().lower() != "unavailable_after":
                        scope = agent.strip().lower()
                        part = rule
                if scope in {None, "googlebot", "*"}:
                    directives.append(part)
        forbidden = any(re.search(r"\b(noindex|none)\b", value, re.I) for value in directives)
        checked_sources = "HTML or HTTP headers" if self.live else "HTML (HTTP headers require --url)"
        self.check(not forbidden, f"No Google noindex/none directive in {checked_sources}")

        self.check(bool(document.json_ld), "At least one JSON-LD block")
        for number, block in enumerate(document.json_ld, 1):
            try:
                data = json.loads(block)
                self.check(isinstance(data, (dict, list)), f"JSON-LD block {number} is an object or array")
            except json.JSONDecodeError as error:
                self.check(False, f"JSON-LD block {number} is invalid: {error}")

        robots_url = urljoin(self.origin, "robots.txt")
        sitemap_url = urljoin(self.origin, "sitemap.xml")
        robots = self.read(robots_url)
        robot_text = None
        if robots:
            robot_text = robots[0].decode("utf-8-sig")
            self.check(googlebot_can_fetch(robot_text, self.origin), "robots.txt allows Googlebot to crawl the root")
            declared = re.findall(r"^\s*sitemap\s*:\s*(\S+)", robot_text, re.I | re.M)
            self.check(sitemap_url in declared, f"robots.txt declares {sitemap_url}")
        sitemap = self.read(sitemap_url)
        if sitemap:
            try:
                root = ET.fromstring(sitemap[0])
                namespace = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
                self.check(root.tag == namespace + "urlset", "sitemap.xml has a sitemap urlset root")
                locations = [item.text for item in root.findall(f"{namespace}url/{namespace}loc")]
                self.check(self.origin in locations, "sitemap.xml includes the canonical root")
                self.check(len(locations) == len(set(locations)), "Sitemap URLs are unique")
            except ET.ParseError as error:
                self.check(False, f"Invalid sitemap XML: {error}")

        base = urljoin(self.origin, document.base) if document.base else self.origin
        targets = {self.internal(reference, base) for reference in document.resources if reference}
        targets.discard(None)
        resource_failures = self.failures
        checked = set()
        while targets:
            target = urldefrag(targets.pop())[0]
            if target in checked:
                continue
            checked.add(target)
            resource = self.read(target)
            if robot_text is not None and not googlebot_can_fetch(robot_text, target):
                self.check(False, f"robots.txt blocks resource: {target}")
            if resource and urlsplit(target).path.lower().endswith(".css"):
                css = resource[0].decode("utf-8-sig")
                references = re.findall(r"url\(\s*['\"]?([^)'\"]+)['\"]?\s*\)", css)
                references += re.findall(r"@import\s+['\"]([^'\"]+)['\"]", css)
                for reference in references:
                    child = self.internal(reference.strip(), target)
                    if child:
                        targets.add(child)
        self.check(self.failures == resource_failures, f"All {len(checked)} same-host assets are readable and crawlable")

        link_failures = self.failures
        parsed_pages = {self.origin: document}
        for reference in sorted(set(document.links)):
            target = self.internal(reference, base)
            if target is None:
                continue
            page_url, fragment = urldefrag(target)
            if not fragment and page_url == self.origin:
                continue
            if page_url not in parsed_pages:
                page = self.read(page_url)
                if page is None:
                    continue
                parsed_pages[page_url] = Document(page[0].decode("utf-8-sig"))
            # Text fragments are browser navigation instructions, not HTML IDs.
            anchor = unquote(fragment.split(":~:text=", 1)[0])
            if anchor and anchor not in parsed_pages[page_url].ids:
                self.check(False, f"Missing anchor #{anchor} in {page_url}")
        self.check(self.failures == link_failures, "Internal links and HTML anchors resolve")

        tokens = sorted(path.name for path in self.directory.glob("google*.html")
                        if re.fullmatch(r"google[0-9a-f]+\.html", path.name))
        self.check(bool(tokens), "A Google HTML verification file exists locally")
        for filename in tokens:
            verification = self.read(urljoin(self.origin, filename))
            if verification:
                expected = f"google-site-verification: {filename}".encode("ascii")
                self.check(verification[0].rstrip(b"\r\n") == expected,
                           f"{filename} serves the exact verification token without a redirect")


def main():
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("--url", help="Audit a published root URL instead of local files")
    args = argument_parser.parse_args()
    live_url = None
    if args.url:
        parsed = urlsplit(args.url)
        if (parsed.scheme not in {"http", "https"} or not parsed.netloc
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or parsed.username or parsed.password):
            argument_parser.error("--url must be an HTTP(S) origin, for example https://monolitwork.vercel.app/")
        live_url = args.url.rstrip("/") + "/"
    audit = Audit(Path(__file__).resolve().parent.parent, live_url)
    print("Mode: " + (live_url or "local files"))
    try:
        audit.run()
    except (OSError, UnicodeError, ValueError) as error:
        audit.check(False, f"Audit could not finish: {error}")
    print(f"Result: {'FAIL' if audit.failures else 'PASS'} ({audit.failures} failed checks)")
    print("External hosts are skipped. This audit does not establish Google indexing or rankings.")
    return 1 if audit.failures else 0


if __name__ == "__main__":
    sys.exit(main())

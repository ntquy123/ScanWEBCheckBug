#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import sys
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

MAX_BODY_BYTES = 512 * 1024
USER_AGENT = "ScanWEBCheckBug/1.0 passive-fingerprint"
SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "20"))
ALLOW_PRIVATE_TARGETS = os.getenv("ALLOW_PRIVATE_TARGETS", "0").lower() in {
    "1",
    "true",
    "yes",
    "on",
}


@dataclass
class FetchResult:
    input_url: str
    final_url: str
    status_code: int
    headers: object
    body: bytes


@dataclass
class Candidate:
    name: str
    category: str
    confidence: float = 0.0
    evidence: List[Dict[str, str]] = field(default_factory=list)

    def add_evidence(
        self,
        weight: float,
        source: str,
        detail: str,
        value: Optional[str] = None,
    ) -> None:
        self.confidence = 1 - ((1 - self.confidence) * (1 - weight))
        if len(self.evidence) >= 6:
            return

        item = {
            "source": source,
            "detail": detail,
        }
        if value:
            item["value"] = value[:300]
        self.evidence.append(item)


class SignalParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.title_parts: List[str] = []
        self.generators: List[str] = []
        self.scripts: List[str] = []
        self.links: List[str] = []
        self.input_names: List[str] = []
        self.comments: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attrs_map = {name.lower(): value or "" for name, value in attrs}
        tag = tag.lower()

        if tag == "title":
            self.in_title = True
            return

        if tag == "meta":
            name = attrs_map.get("name", "").lower()
            if name == "generator" and attrs_map.get("content"):
                self.generators.append(attrs_map["content"])
            return

        if tag == "script" and attrs_map.get("src"):
            self.scripts.append(attrs_map["src"])
            return

        if tag == "link" and attrs_map.get("href"):
            self.links.append(attrs_map["href"])
            return

        if tag == "input" and attrs_map.get("name"):
            self.input_names.append(attrs_map["name"])

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data.strip())

    def handle_comment(self, data: str) -> None:
        if len(self.comments) < 20:
            self.comments.append(data.strip())

    @property
    def title(self) -> str:
        return " ".join(part for part in self.title_parts if part).strip()


def emit_progress(percent: int, stage: str, message: str, status: str = "running") -> None:
    event = {
        "type": "progress",
        "progress": {
            "status": status,
            "stage": stage,
            "percent": percent,
            "message": message,
        },
    }
    print(json.dumps(event), flush=True)


def emit_result(result: Dict[str, object]) -> None:
    print(json.dumps({"type": "result", "result": result}), flush=True)


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: scanner.py <url>", file=sys.stderr)
        return 2

    start = time.time()
    input_url = sys.argv[1]

    try:
        emit_progress(10, "validate", "Validating target URL")
        assert_target_allowed(input_url)

        emit_progress(25, "fetch", "Fetching public response")
        fetch = fetch_url(input_url)

        emit_progress(60, "fingerprint", "Analyzing public fingerprints")
        result = analyze(fetch, start)

        emit_progress(100, "completed", "Fingerprint complete", "completed")
        emit_result(result)
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


def assert_target_allowed(raw_url: str) -> None:
    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https targets are supported")

    if not parsed.hostname:
        raise ValueError("Target URL must include a hostname")

    if ALLOW_PRIVATE_TARGETS:
        return

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve target hostname: {parsed.hostname}") from exc

    for info in infos:
        address = info[4][0]
        ip = ipaddress.ip_address(address)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ValueError(
                "Private, loopback, link-local and reserved targets are blocked. "
                "Set ALLOW_PRIVATE_TARGETS=1 only for authorized local lab targets."
            )


def fetch_url(input_url: str) -> FetchResult:
    request = Request(
        input_url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.8",
        },
        method="GET",
    )

    try:
        with urlopen(request, timeout=SCAN_TIMEOUT_SECONDS) as response:
            body = response.read(MAX_BODY_BYTES)
            return FetchResult(
                input_url=input_url,
                final_url=response.geturl(),
                status_code=response.getcode(),
                headers=response.headers,
                body=body,
            )
    except HTTPError as response:
        body = response.read(MAX_BODY_BYTES)
        return FetchResult(
            input_url=input_url,
            final_url=response.geturl(),
            status_code=response.code,
            headers=response.headers,
            body=body,
        )
    except URLError as exc:
        raise ValueError(f"Cannot fetch target: {exc.reason}") from exc


def analyze(fetch: FetchResult, start: float) -> Dict[str, object]:
    headers = normalize_headers(fetch.headers)
    set_cookies = get_all_headers(fetch.headers, "Set-Cookie")
    content_type = headers.get("content-type", "")
    html = decode_body(fetch.body, content_type)

    parser = SignalParser()
    parser.feed(html[:MAX_BODY_BYTES])

    candidates: Dict[Tuple[str, str], Candidate] = {}

    analyze_headers(headers, candidates)
    analyze_cookies(set_cookies, candidates)
    analyze_html(html, parser, candidates)
    analyze_database_leaks(html, headers, candidates)

    backend_languages = serialize_candidates(candidates, "backend_language")
    frameworks = serialize_candidates(candidates, "framework")
    databases = serialize_candidates(candidates, "database")

    top_backend = backend_languages[0] if backend_languages else None
    top_database = databases[0] if databases else None

    notes = [
        "Backend language and database are inferred from public fingerprints, not guaranteed facts.",
        "Database engines are usually hidden behind the backend; no database result means no public evidence was found.",
        "This scanner uses passive HTTP fingerprinting only.",
    ]

    http_info = {
        "inputUrl": fetch.input_url,
        "finalUrl": fetch.final_url,
        "statusCode": fetch.status_code,
        "contentType": content_type or None,
        "server": headers.get("server"),
        "poweredBy": headers.get("x-powered-by"),
        "title": parser.title or None,
    }

    return {
        "scannedAt": current_iso_timestamp(),
        "durationMs": int((time.time() - start) * 1000),
        "http": {key: value for key, value in http_info.items() if value is not None},
        "backendLanguages": backend_languages,
        "frameworks": frameworks,
        "databases": databases,
        "summary": {
            "backendLanguage": top_backend["name"] if top_backend else "Unknown",
            "backendConfidence": top_backend["confidence"] if top_backend else 0,
            "database": top_database["name"] if top_database else "Unknown",
            "databaseConfidence": top_database["confidence"] if top_database else 0,
        },
        "notes": notes,
    }


def normalize_headers(headers: object) -> Dict[str, str]:
    return {key.lower(): value for key, value in headers.items()}


def get_all_headers(headers: object, name: str) -> List[str]:
    getter = getattr(headers, "get_all", None)
    if callable(getter):
        return getter(name) or []

    value = getattr(headers, "get", lambda _name: None)(name)
    return [value] if value else []


def decode_body(body: bytes, content_type: str) -> str:
    charset_match = re.search(r"charset=([^;\s]+)", content_type, flags=re.I)
    charset = charset_match.group(1) if charset_match else "utf-8"
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def analyze_headers(headers: Dict[str, str], candidates: Dict[Tuple[str, str], Candidate]) -> None:
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    generator = headers.get("x-generator", "")
    combined = " ".join([server, powered_by, generator]).lower()

    if "php" in powered_by.lower():
        add_candidate(candidates, "backend_language", "PHP", 0.88, "header:x-powered-by", "PHP exposed by X-Powered-By", powered_by)
    if "express" in powered_by.lower():
        add_candidate(candidates, "backend_language", "Node.js", 0.82, "header:x-powered-by", "Express commonly runs on Node.js", powered_by)
        add_candidate(candidates, "framework", "Express", 0.9, "header:x-powered-by", "Express exposed by X-Powered-By", powered_by)
    if "next.js" in powered_by.lower() or "nextjs" in powered_by.lower():
        add_candidate(candidates, "backend_language", "Node.js", 0.75, "header:x-powered-by", "Next.js commonly runs on Node.js", powered_by)
        add_candidate(candidates, "framework", "Next.js", 0.9, "header:x-powered-by", "Next.js exposed by X-Powered-By", powered_by)
    if "asp.net" in powered_by.lower() or "x-aspnet-version" in headers or "x-aspnetmvc-version" in headers:
        add_candidate(candidates, "backend_language", "C# / ASP.NET", 0.9, "header:aspnet", "ASP.NET header exposed", powered_by or headers.get("x-aspnet-version"))
        add_candidate(candidates, "framework", "ASP.NET", 0.92, "header:aspnet", "ASP.NET header exposed", powered_by or headers.get("x-aspnet-version"))

    server_patterns = [
        ("gunicorn", "Python", "Gunicorn", 0.82),
        ("uvicorn", "Python", "FastAPI / ASGI", 0.78),
        ("daphne", "Python", "Django Channels / ASGI", 0.75),
        ("waitress", "Python", "Waitress", 0.75),
        ("werkzeug", "Python", "Flask / Werkzeug", 0.8),
        ("puma", "Ruby", "Ruby on Rails / Rack", 0.78),
        ("passenger", "Ruby", "Ruby on Rails / Rack", 0.72),
        ("webrick", "Ruby", "WEBrick", 0.8),
        ("tomcat", "Java", "Apache Tomcat", 0.82),
        ("jetty", "Java", "Jetty", 0.82),
        ("jboss", "Java", "JBoss", 0.82),
        ("weblogic", "Java", "Oracle WebLogic", 0.82),
        ("kestrel", "C# / ASP.NET", "ASP.NET Core", 0.82),
    ]
    for needle, language, framework, weight in server_patterns:
        if needle in combined:
            add_candidate(candidates, "backend_language", language, weight, "header:server", f"{framework} server fingerprint", server or powered_by)
            add_candidate(candidates, "framework", framework, weight, "header:server", f"{framework} server fingerprint", server or powered_by)


def analyze_cookies(cookies: Iterable[str], candidates: Dict[Tuple[str, str], Candidate]) -> None:
    cookie_text = "\n".join(cookies)
    lower = cookie_text.lower()

    cookie_patterns = [
        ("phpsessid", "backend_language", "PHP", 0.82, "PHP session cookie"),
        ("laravel_session", "framework", "Laravel", 0.85, "Laravel session cookie"),
        ("laravel_session", "backend_language", "PHP", 0.72, "Laravel is a PHP framework"),
        ("asp.net_sessionid", "backend_language", "C# / ASP.NET", 0.86, "ASP.NET session cookie"),
        (".aspnetcore", "framework", "ASP.NET Core", 0.86, "ASP.NET Core cookie"),
        (".aspnetcore", "backend_language", "C# / ASP.NET", 0.8, "ASP.NET Core cookie"),
        ("jsessionid", "backend_language", "Java", 0.84, "Java session cookie"),
        ("connect.sid", "backend_language", "Node.js", 0.78, "Express session cookie"),
        ("connect.sid", "framework", "Express", 0.72, "Express session cookie"),
        ("_rails_session", "backend_language", "Ruby", 0.84, "Rails session cookie"),
        ("_rails_session", "framework", "Ruby on Rails", 0.88, "Rails session cookie"),
        ("csrftoken", "backend_language", "Python", 0.5, "Django-style CSRF cookie"),
        ("csrftoken", "framework", "Django", 0.52, "Django-style CSRF cookie"),
        ("play_session", "backend_language", "Java / Scala", 0.72, "Play Framework session cookie"),
        ("play_session", "framework", "Play Framework", 0.78, "Play Framework session cookie"),
    ]

    for needle, category, name, weight, detail in cookie_patterns:
        if needle in lower:
            add_candidate(candidates, category, name, weight, "cookie", detail, first_matching_cookie(cookie_text, needle))


def analyze_html(html: str, parser: SignalParser, candidates: Dict[Tuple[str, str], Candidate]) -> None:
    lower = html.lower()
    assets = " ".join(parser.scripts + parser.links).lower()
    generators = " ".join(parser.generators).lower()
    inputs = " ".join(parser.input_names).lower()

    if "wordpress" in generators or "wp-content" in assets or "wp-includes" in assets:
        add_candidate(candidates, "framework", "WordPress", 0.92, "html", "WordPress generator or asset path", evidence_value(generators, assets, "wordpress"))
        add_candidate(candidates, "backend_language", "PHP", 0.78, "html", "WordPress commonly runs on PHP", evidence_value(generators, assets, "wordpress"))
        add_candidate(candidates, "database", "MySQL / MariaDB", 0.62, "html", "WordPress commonly uses MySQL or MariaDB", evidence_value(generators, assets, "wordpress"))

    if "joomla" in generators or "/media/jui/" in assets or "/components/com_" in assets:
        add_candidate(candidates, "framework", "Joomla", 0.86, "html", "Joomla generator or asset path", evidence_value(generators, assets, "joomla"))
        add_candidate(candidates, "backend_language", "PHP", 0.72, "html", "Joomla commonly runs on PHP", evidence_value(generators, assets, "joomla"))
        add_candidate(candidates, "database", "MySQL / MariaDB", 0.52, "html", "Joomla commonly uses MySQL or MariaDB", evidence_value(generators, assets, "joomla"))

    if "drupal" in generators or "/sites/default/" in assets or "drupal-settings-json" in lower:
        add_candidate(candidates, "framework", "Drupal", 0.86, "html", "Drupal generator or asset path", evidence_value(generators, assets, "drupal"))
        add_candidate(candidates, "backend_language", "PHP", 0.72, "html", "Drupal commonly runs on PHP", evidence_value(generators, assets, "drupal"))

    if "/_next/" in assets or "__next_data__" in lower:
        add_candidate(candidates, "framework", "Next.js", 0.9, "html", "Next.js asset/data marker", evidence_value("", assets + " " + lower[:2000], "_next"))
        add_candidate(candidates, "backend_language", "Node.js", 0.62, "html", "Next.js is commonly served by Node.js", evidence_value("", assets, "_next"))

    if "/_nuxt/" in assets or "__nuxt" in lower:
        add_candidate(candidates, "framework", "Nuxt", 0.88, "html", "Nuxt asset/data marker", evidence_value("", assets + " " + lower[:2000], "nuxt"))
        add_candidate(candidates, "backend_language", "Node.js", 0.48, "html", "Nuxt can be served by Node.js", evidence_value("", assets, "nuxt"))

    if "csrfmiddlewaretoken" in inputs or "csrfmiddlewaretoken" in lower:
        add_candidate(candidates, "framework", "Django", 0.76, "html", "Django CSRF input marker", "csrfmiddlewaretoken")
        add_candidate(candidates, "backend_language", "Python", 0.72, "html", "Django is a Python framework", "csrfmiddlewaretoken")

    if "csrf-param" in lower and "csrf-token" in lower:
        add_candidate(candidates, "framework", "Ruby on Rails", 0.78, "html", "Rails CSRF meta tags", "csrf-param csrf-token")
        add_candidate(candidates, "backend_language", "Ruby", 0.72, "html", "Rails is a Ruby framework", "csrf-param csrf-token")

    if "__viewstate" in lower or "__eventvalidation" in lower:
        add_candidate(candidates, "framework", "ASP.NET Web Forms", 0.88, "html", "ASP.NET Web Forms hidden fields", "__VIEWSTATE")
        add_candidate(candidates, "backend_language", "C# / ASP.NET", 0.82, "html", "ASP.NET Web Forms hidden fields", "__VIEWSTATE")

    if "blazor.server.js" in assets or "_framework/blazor" in assets:
        add_candidate(candidates, "framework", "Blazor / ASP.NET Core", 0.86, "html", "Blazor asset marker", "blazor")
        add_candidate(candidates, "backend_language", "C# / ASP.NET", 0.78, "html", "Blazor is an ASP.NET technology", "blazor")

    if ".php" in assets:
        add_candidate(candidates, "backend_language", "PHP", 0.35, "html", "PHP file path exposed in page assets", evidence_value("", assets, ".php"))


def analyze_database_leaks(
    html: str,
    headers: Dict[str, str],
    candidates: Dict[Tuple[str, str], Candidate],
) -> None:
    text = "\n".join([html[:MAX_BODY_BYTES], " ".join(headers.values())])
    patterns = [
        ("MySQL / MariaDB", 0.94, r"(you have an error in your sql syntax|mysql_fetch|mysqli_|mariadb server version|mysql server version)", "Public MySQL/MariaDB error text"),
        ("PostgreSQL", 0.94, r"(postgresql|pg_query|org\.postgresql|npgsql|psycopg2|pq: syntax error)", "Public PostgreSQL error text"),
        ("Microsoft SQL Server", 0.94, r"(microsoft sql server|system\.data\.sqlclient|sqlexception|sql server native client|odbc sql server driver)", "Public SQL Server error text"),
        ("Oracle Database", 0.94, r"(ora-\d{5}|oracle database|oracle.jdbc)", "Public Oracle error text"),
        ("SQLite", 0.92, r"(sqlite_error|sqlite3\.operationalerror|sqlite/jdbcdriver|no such table:)", "Public SQLite error text"),
        ("MongoDB", 0.9, r"(mongoerror|mongoservererror|mongooseerror|bson\.objectid|mongodb)", "Public MongoDB error text"),
        ("Redis", 0.78, r"(redisconnectionexception|redis command timed out|ioredis)", "Public Redis error text"),
    ]

    for name, weight, pattern, detail in patterns:
        match = re.search(pattern, text, flags=re.I)
        if match:
            add_candidate(candidates, "database", name, weight, "body/header", detail, surrounding_text(text, match.start(), match.end()))

    if candidate_exists(candidates, "framework", "ASP.NET") or candidate_exists(candidates, "framework", "ASP.NET Core"):
        add_candidate(candidates, "database", "Microsoft SQL Server", 0.35, "framework", "ASP.NET apps often use SQL Server, but this is weak evidence")

    if candidate_exists(candidates, "framework", "Laravel"):
        add_candidate(candidates, "database", "MySQL / MariaDB", 0.35, "framework", "Laravel apps often use MySQL/MariaDB, but this is weak evidence")


def add_candidate(
    candidates: Dict[Tuple[str, str], Candidate],
    category: str,
    name: str,
    weight: float,
    source: str,
    detail: str,
    value: Optional[str] = None,
) -> None:
    key = (category, name)
    if key not in candidates:
        candidates[key] = Candidate(name=name, category=category)
    candidates[key].add_evidence(weight, source, detail, value)


def candidate_exists(candidates: Dict[Tuple[str, str], Candidate], category: str, name: str) -> bool:
    return (category, name) in candidates


def serialize_candidates(candidates: Dict[Tuple[str, str], Candidate], category: str) -> List[Dict[str, object]]:
    values = [candidate for candidate in candidates.values() if candidate.category == category]
    values.sort(key=lambda candidate: candidate.confidence, reverse=True)
    return [
        {
            "name": candidate.name,
            "category": candidate.category,
            "confidence": round(candidate.confidence, 2),
            "evidence": candidate.evidence,
        }
        for candidate in values
    ]


def first_matching_cookie(cookie_text: str, needle: str) -> Optional[str]:
    for line in cookie_text.splitlines():
        if needle.lower() in line.lower():
            return line.split(";", 1)[0]
    return None


def evidence_value(primary: str, secondary: str, needle: str) -> Optional[str]:
    combined = "\n".join([primary, secondary])
    index = combined.lower().find(needle.lower())
    if index < 0:
        return None
    return surrounding_text(combined, index, index + len(needle))


def surrounding_text(text: str, start: int, end: int) -> str:
    left = max(0, start - 80)
    right = min(len(text), end + 80)
    return re.sub(r"\s+", " ", text[left:right]).strip()


def current_iso_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


if __name__ == "__main__":
    sys.exit(main())

"""Crawling and discovery: pull endpoints, parameters, and object refs."""

from __future__ import annotations

from collections import deque
from urllib.parse import parse_qsl, urljoin, urlparse

from bs4 import BeautifulSoup

from .identifiers import build_reference, looks_like_object_param
from .models import ObjectReference
from .scope import ScopeGuard, host_of
from .session import Principal, RateLimiter


def extract_query_refs(url: str) -> list[ObjectReference]:
    refs = []
    for name, value in parse_qsl(urlparse(url).query):
        if looks_like_object_param(name, value):
            refs.append(build_reference(value, f"query:{name}", url))
    return refs


def extract_path_refs(url: str) -> list[ObjectReference]:
    refs = []
    parts = [p for p in urlparse(url).path.split("/") if p]
    for i, seg in enumerate(parts):
        if looks_like_object_param("", seg):
            collection = parts[i - 1] if i > 0 else "path"
            refs.append(build_reference(seg, f"path:{collection}", url))
    return refs


def all_param_names(url: str) -> list[str]:
    return [n for n, _ in parse_qsl(urlparse(url).query)]


def extract_links(html: str, base_url: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    out = []
    for tag, attr in (("a", "href"), ("form", "action"), ("link", "href")):
        for el in soup.find_all(tag):
            v = el.get(attr)
            if v:
                out.append(urljoin(base_url, v))
    return out


class CrawlOutput:
    def __init__(self) -> None:
        self.object_urls: dict[str, list[ObjectReference]] = {}   # url -> refs
        self.object_refs: list[ObjectReference] = []
        self.param_names: set[str] = set()
        self.visited: set[str] = set()


def crawl(principal: Principal, guard: ScopeGuard, limiter: RateLimiter,
          seed: str, max_pages: int, max_depth: int) -> CrawlOutput:
    out = CrawlOutput()
    root_host = host_of(seed)
    queue: deque[tuple[str, int]] = deque([(seed, 0)])

    def record(url: str) -> None:
        refs = extract_query_refs(url) + extract_path_refs(url)
        out.param_names.update(all_param_names(url))
        if refs:
            out.object_refs.extend(refs)
            out.object_urls.setdefault(url, refs)

    while queue and len(out.visited) < max_pages:
        url, depth = queue.popleft()
        if url in out.visited or depth > max_depth or host_of(url) != root_host:
            continue
        out.visited.add(url)
        record(url)
        limiter.wait()
        res = principal.get(url, guard)
        if res.error or res.status_code >= 400 or not res.text:
            continue
        for link in extract_links(res.text, url):
            record(link)
            if link not in out.visited and host_of(link) == root_host:
                queue.append((link, depth + 1))
    return out

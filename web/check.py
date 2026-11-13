#!/usr/bin/env python3
"""check.py — lint the static site.

Three things go wrong with hand-written HTML and a navigation bar duplicated on
every page:

  * a link to a page or an anchor that does not exist
  * a page that no longer appears in the navigation
  * a tag that was never closed

None of them are visible by looking at rendered output, and all of them are
cheap to check. Deliberately dependency-free: this is a repository whose static
site should be checkable on a machine with only Python.

    python3 web/check.py            # exit 0 when everything is fine
"""

from __future__ import annotations

import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

WEB = Path(__file__).resolve().parent

VOID = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
    "param", "source", "track", "wbr",
}
SKIP_TEXT = {"script", "style"}


class Page(HTMLParser):
    """Collects ids, local links, tag structure and a little trivia."""

    def __init__(self, path: Path) -> None:
        super().__init__(convert_charrefs=True)
        self.path = path
        self.ids: set[str] = set()
        self.links: list[tuple[str, int]] = []      # (href, line)
        self.anchors: list[tuple[str, int]] = []     # href="#x" only
        self.stack: list[tuple[str, int]] = []
        self.problems: list[str] = []
        self.h1s: list[str] = []
        self._in: str | None = None
        self._text: list[str] = []

    # -- tags
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a and a["id"]:
            if a["id"] in self.ids:
                self.problems.append(f"{self.path.name}:{self.getpos()[0]}: duplicate id {a['id']!r}")
            self.ids.add(a["id"])
        if tag == "a" and "href" in a:
            href = a["href"]
            line = self.getpos()[0]
            self.links.append((href, line))
            if href.startswith("#"):
                self.anchors.append((href[1:], line))
        if tag == "h1":
            self._in = "h1"
            self._text = []
        if tag not in VOID:
            self.stack.append((tag, self.getpos()[0]))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID and self.stack and self.stack[-1][0] == tag:
            self.stack.pop()

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        if tag == "h1" and self._in == "h1":
            self.h1s.append("".join(self._text).strip())
            self._in = None
        if not self.stack:
            self.problems.append(f"{self.path.name}:{self.getpos()[0]}: </{tag}> with nothing open")
            return
        if self.stack[-1][0] == tag:
            self.stack.pop()
            return
        # tolerate an unclosed <p>, which browsers close implicitly
        while self.stack and self.stack[-1][0] == "p":
            self.stack.pop()
            if self.stack and self.stack[-1][0] == tag:
                self.stack.pop()
                return
        self.problems.append(
            f"{self.path.name}:{self.getpos()[0]}: </{tag}> but <{self.stack[-1][0]}> "
            f"from line {self.stack[-1][1]} is still open"
        )

    def handle_data(self, data):
        if self._in == "h1":
            self._text.append(data)

    def close(self):
        super().close()
        for tag, line in self.stack:
            self.problems.append(f"{self.path.name}: <{tag}> from line {line} never closed")


def main() -> int:
    pages = sorted(WEB.glob("*.html"))
    if not pages:
        print("no HTML files found; run this from the repository root", file=sys.stderr)
        return 2

    parsed: dict[str, Page] = {}
    problems: list[str] = []

    for path in pages:
        page = Page(path)
        page.feed(path.read_text(encoding="utf-8"))
        page.close()
        parsed[path.name] = page
        problems.extend(page.problems)
        if len(page.h1s) != 1:
            problems.append(f"{path.name}: expected exactly one <h1>, found {len(page.h1s)}")
        if not page.h1s or not page.h1s[0].strip():
            problems.append(f"{path.name}: empty <h1>")
        if "style.css" not in path.read_text(encoding="utf-8"):
            problems.append(f"{path.name}: does not link style.css")

    # navigation must appear on every page and point at every page
    nav_pages = {p.name for p in pages}
    for name, page in parsed.items():
        internal = {href.split("#")[0] for href, _ in page.links if href.endswith(".html")}
        internal.discard("")
        missing = nav_pages - internal - {name}
        if missing:
            problems.append(f"{name}: nav does not reach {', '.join(sorted(missing))}")

    # every local href resolves, and every fragment exists
    for name, page in parsed.items():
        for href, line in page.links:
            parts = urlsplit(href)
            if parts.scheme in {"http", "https", "mailto"}:
                continue
            if not parts.path and not parts.fragment:
                problems.append(f"{name}:{line}: empty href")
                continue
            target_name = unquote(parts.path) or name
            if parts.path:
                target = WEB / target_name
                if not target.exists():
                    problems.append(f"{name}:{line}: {href} -> no such file {target_name}")
                    continue
                if target.suffix != ".html":
                    continue
            else:
                target = WEB / name
            if parts.fragment:
                dest = parsed.get(Path(target_name).name)
                if dest is not None and unquote(parts.fragment) not in dest.ids:
                    problems.append(
                        f"{name}:{line}: {href} -> {target_name} has no id "
                        f"{unquote(parts.fragment)!r}"
                    )
        for anchor, line in page.anchors:
            if unquote(anchor) not in page.ids:
                problems.append(f"{name}:{line}: #{anchor} -> no such id on this page")

    # nothing may pull a subresource from the network: the site is offline-first
    for name in parsed:
        for line_no, line in enumerate((WEB / name).read_text(encoding="utf-8").splitlines(), 1):
            for tag, attr in (("<link", "href"), ("<img", "src"), ("<script", "src")):
                if tag in line and "http" in line and attr in line:
                    problems.append(f"{name}:{line_no}: remote subresource ({tag})")

    if problems:
        print(f"{len(problems)} problem(s):")
        for p in problems:
            print("  " + p)
        return 1

    print(f"ok: {len(pages)} pages, {sum(len(p.links) for p in parsed.values())} links, "
          f"all local targets and fragments resolve")
    for name in sorted(parsed):
        print(f"  {name:<20} {len(parsed[name].links):>3} links  {len(parsed[name].ids):>3} ids")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

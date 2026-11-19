"""Detect broken local Markdown links so docs don't silently drift."""
from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import unquote, urlsplit
import unittest

ROOT = Path(__file__).resolve().parent.parent
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")


def local_broken_links() -> list[str]:
    broken: list[str] = []
    for doc in [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]:
        content = doc.read_text(encoding="utf-8")
        for line_no, line in enumerate(content.splitlines(), start=1):
            # No attempt to parse fenced code blocks; fake code URLs are allowed.
            for raw in MARKDOWN_LINK.findall(line):
                value = raw.strip().split(" \"", 1)[0].strip("<>")
                parsed = urlsplit(value)
                if parsed.scheme or value.startswith(("#", "//", "mailto:")):
                    continue
                path = unquote(parsed.path)
                if not path:
                    continue
                target = (doc.parent / path).resolve()
                if not target.is_relative_to(ROOT) or not target.exists():
                    broken.append(f"{doc.relative_to(ROOT)}:{line_no}: {raw}")
    return broken


class MarkdownLinksTests(unittest.TestCase):
    def test_local_markdown_links_exist(self) -> None:
        self.assertEqual(local_broken_links(), [])


if __name__ == "__main__":
    unittest.main()

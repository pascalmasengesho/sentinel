"""Opt-in, rate-limited content discovery using a user-controlled wordlist."""

from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import quote, urljoin

from sentinel.models import ModuleResult
from sentinel.modules.base import ScanContext, ScanModule


class WordlistModule(ScanModule):
    """Request a limited set of wordlist paths only after explicit opt-in."""

    name = "content_discovery"

    async def run(self, context: ScanContext) -> ModuleResult:
        if not context.config.enable_content_discovery:
            return ModuleResult(
                module=self.name,
                data={
                    "enabled": False,
                    "reason": "Use --content-discovery with a scoped wordlist to enable.",
                },
            )
        if not context.config.wordlist_path:
            return ModuleResult(
                module=self.name,
                errors=["Content discovery enabled but no wordlist_path was supplied."],
            )
        wordlist = Path(context.config.wordlist_path)
        if not await asyncio.to_thread(wordlist.is_file):
            return ModuleResult(module=self.name, errors=[f"Wordlist not found: {wordlist}"])
        words = await asyncio.to_thread(
            self._read_words, wordlist, context.config.max_directory_requests
        )
        semaphore = asyncio.Semaphore(context.config.concurrency)
        results = await asyncio.gather(*(self._probe(context, word, semaphore) for word in words))
        found = [result for result in results if result is not None]
        return ModuleResult(
            module=self.name,
            data={"enabled": True, "words_checked": len(words), "discovered_paths": found},
        )

    @staticmethod
    def _read_words(path: Path, maximum: int) -> list[str]:
        words: list[str] = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            word = line.strip().lstrip("/")
            if word and not word.startswith("#") and ".." not in word:
                words.append(word)
            if len(words) >= maximum:
                break
        return list(dict.fromkeys(words))

    @staticmethod
    async def _probe(
        context: ScanContext, word: str, semaphore: asyncio.Semaphore
    ) -> dict[str, str | int] | None:
        async with semaphore:
            url = urljoin(context.target.origin + "/", quote(word, safe="/"))
            try:
                response = await context.http.get(url)
            except Exception:
                return None
            if response.status_code not in {200, 204, 301, 302, 307, 308, 401, 403}:
                return None
            return {"path": word, "url": response.url, "status_code": response.status_code}

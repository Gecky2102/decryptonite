"""Ranking of decoded candidates.

Two layers work together:

* A cheap local heuristic (``heuristic_score``) that estimates how
  "human meaningful" a string looks based on character mix, entropy and word
  shape. It runs on every candidate and needs no dependencies.
* An optional Ollama judge (``OllamaJudge``) that asks a local LLM to rate how
  much a candidate resembles a real password or meaningful secret. It refines
  the ranking of the top heuristic candidates.
"""

from __future__ import annotations

import json
import math
import re
import string
import urllib.error
import urllib.request
from dataclasses import dataclass

from .decoders import Candidate

_WORDISH = re.compile(r"[A-Za-z]{3,}")
_VOWELS = set("aeiouAEIOU")

# Common English bigrams; presence signals pronounceable, human text and is the
# main lever separating real words from mostly-printable byte soup.
_COMMON_BIGRAMS = {
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es",
    "or", "te", "of", "ed", "is", "it", "al", "ar", "st", "to", "nt", "ng",
    "se", "ha", "as", "ou", "io", "le", "ve", "co", "me", "de", "hi", "ri",
    "ro", "ic", "ne", "ea", "ra", "ce", "li", "ch", "ll", "be", "ma", "si",
    "om", "ur", "ss", "wo", "rd", "pa", "sw", "us", "ho", "el", "ol",
}
# A small set of tokens that strongly imply a real secret / word when present.
_SECRET_WORDS = {
    "password", "passwd", "secret", "admin", "login", "root", "user", "pass",
    "key", "token", "flag", "welcome", "letmein", "hunter", "dragon", "master",
    "qwerty", "hello", "money", "love",
}


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: "dict[str, int]" = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def heuristic_score(text: str) -> float:
    """Return a 0-100 estimate of how password/word-like ``text`` is.

    The score rewards printable ASCII, a healthy vowel/consonant balance and
    the presence of word-shaped runs, while penalising byte soup and extreme
    lengths.
    """
    if not text:
        return 0.0

    if any(ord(c) < 9 or (13 < ord(c) < 32) for c in text):
        return 0.0  # control bytes: almost never a chosen secret

    printable = sum(c in string.printable for c in text) / len(text)
    if printable < 0.95:
        return 0.0

    score = 15.0 * printable

    lower = text.lower()
    letters = [c for c in lower if c.isalpha()]
    if letters:
        vowels = sum(c in _VOWELS for c in letters)
        ratio = vowels / len(letters)
        # natural language sits roughly between 30% and 60% vowels
        score += 15.0 * (1.0 - min(abs(ratio - 0.4) / 0.4, 1.0))

    # Pronounceability: fraction of adjacent letter pairs that are common
    # English bigrams. This is the dominant signal against byte soup.
    letter_run = re.sub(r"[^a-z]", "", lower)
    if len(letter_run) >= 2:
        pairs = [letter_run[i:i + 2] for i in range(len(letter_run) - 1)]
        hits = sum(p in _COMMON_BIGRAMS for p in pairs)
        score += 45.0 * (hits / len(pairs))

    words = _WORDISH.findall(lower)
    if words:
        score += min(len(words) * 4.0, 12.0)
    if any(w in _SECRET_WORDS for w in words) or any(
        sw in lower for sw in _SECRET_WORDS
    ):
        score += 25.0

    classes = sum(
        bool(re.search(pat, text))
        for pat in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
    )
    score += classes * 2.0  # password-like character diversity

    ent = shannon_entropy(text)
    if ent > 5.5:
        score -= 15.0

    length = len(text)
    if length < 3 or length > 64:
        score -= 20.0

    return max(0.0, min(100.0, score))


@dataclass
class ScoredCandidate:
    candidate: Candidate
    heuristic: float
    llm: "float | None" = None
    reason: str = ""

    @property
    def final(self) -> float:
        if self.llm is None:
            return self.heuristic
        return 0.35 * self.heuristic + 0.65 * self.llm


class OllamaJudge:
    """Thin client over the Ollama HTTP API (``/api/generate``)."""

    def __init__(
        self,
        model: str = "llama3.2",
        host: str = "http://localhost:11434",
        timeout: float = 30.0,
    ) -> None:
        self.model = model
        self.host = host.rstrip("/")
        self.timeout = timeout

    def available(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.host}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError):
            return False

    def _prompt(self, text: str) -> str:
        return (
            "You are a security analyst triaging strings recovered from a "
            "decryption sweep. Rate, from 0 to 100, how likely the following "
            "string is a meaningful human secret: a real password, passphrase, "
            "PIN, key, or readable words a person chose. Byte soup, random "
            "high-entropy garbage, or gibberish should score low. Reply with a "
            "single minified JSON object and nothing else, of the form "
            '{"score": <int 0-100>, "reason": "<max 8 words>"}.\n\n'
            f"String: {text!r}"
        )

    def score(self, text: str) -> "tuple[float, str] | None":
        payload = json.dumps(
            {
                "model": self.model,
                "prompt": self._prompt(text),
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.0},
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
            return None

        raw = body.get("response", "")
        try:
            parsed = json.loads(raw)
            score = float(parsed.get("score", 0))
            reason = str(parsed.get("reason", "")).strip()
        except (json.JSONDecodeError, ValueError, TypeError):
            return None
        return max(0.0, min(100.0, score)), reason


def rank(
    candidates: "list[Candidate]",
    judge: "OllamaJudge | None" = None,
    llm_top_k: int = 20,
) -> "list[ScoredCandidate]":
    """Score and sort ``candidates`` best-first.

    All candidates get a heuristic score. When ``judge`` is provided and
    reachable, the top ``llm_top_k`` by heuristic are additionally scored by the
    LLM and re-ranked on the blended score.
    """
    scored = [ScoredCandidate(c, heuristic_score(c.text)) for c in candidates]
    scored.sort(key=lambda s: s.heuristic, reverse=True)

    if judge is not None:
        for sc in scored[:llm_top_k]:
            result = judge.score(sc.candidate.text)
            if result is not None:
                sc.llm, sc.reason = result

    scored.sort(key=lambda s: s.final, reverse=True)
    return scored

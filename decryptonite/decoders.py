"""Reversible transforms used to expand an input string into candidate plaintexts.

Each decoder is a pure function ``str -> str | None``. It returns the decoded
string on success or ``None`` when the transform does not apply to the input.
Decoders are applied recursively up to a configurable depth so that layered
encodings (e.g. base64 of a hex string) are also uncovered.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import string
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Iterable

Decoder = Callable[[str], "str | None"]

_PRINTABLE = set(string.printable)
MORSE_TABLE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(c in _PRINTABLE for c in text) / len(text)


def _clean_str(raw: bytes) -> "str | None":
    """Decode bytes to str, rejecting output that is mostly non-printable."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except UnicodeDecodeError:
            return None
    if not text or _printable_ratio(text) < 0.85:
        return None
    return text


def d_base64(text: str) -> "str | None":
    stripped = text.strip()
    if len(stripped) < 4 or len(stripped) % 4 != 0:
        return None
    if any(c not in (string.ascii_letters + string.digits + "+/=") for c in stripped):
        return None
    try:
        return _clean_str(base64.b64decode(stripped, validate=True))
    except (binascii.Error, ValueError):
        return None


def d_base64url(text: str) -> "str | None":
    stripped = text.strip()
    if len(stripped) < 4:
        return None
    if any(c not in (string.ascii_letters + string.digits + "-_=") for c in stripped):
        return None
    padded = stripped + "=" * (-len(stripped) % 4)
    try:
        return _clean_str(base64.urlsafe_b64decode(padded))
    except (binascii.Error, ValueError):
        return None


def d_base32(text: str) -> "str | None":
    stripped = text.strip().upper()
    if len(stripped) < 8 or len(stripped) % 8 != 0:
        return None
    try:
        return _clean_str(base64.b32decode(stripped))
    except (binascii.Error, ValueError):
        return None


def d_base85(text: str) -> "str | None":
    stripped = text.strip()
    if len(stripped) < 5:
        return None
    try:
        return _clean_str(base64.b85decode(stripped))
    except (ValueError, binascii.Error):
        return None


def d_ascii85(text: str) -> "str | None":
    stripped = text.strip()
    if len(stripped) < 5:
        return None
    try:
        return _clean_str(base64.a85decode(stripped))
    except (ValueError, binascii.Error):
        return None


def d_hex(text: str) -> "str | None":
    stripped = "".join(text.split())
    if len(stripped) < 2 or len(stripped) % 2 != 0:
        return None
    if any(c not in string.hexdigits for c in stripped):
        return None
    try:
        return _clean_str(bytes.fromhex(stripped))
    except ValueError:
        return None


def d_url(text: str) -> "str | None":
    if "%" not in text and "+" not in text:
        return None
    decoded = urllib.parse.unquote_plus(text)
    if decoded == text:
        return None
    return decoded


def d_html(text: str) -> "str | None":
    if "&" not in text or ";" not in text:
        return None
    decoded = html.unescape(text)
    if decoded == text:
        return None
    return decoded


def d_rot13(text: str) -> "str | None":
    if not any(c.isalpha() for c in text):
        return None
    return codecs.encode(text, "rot_13")


def d_rot47(text: str) -> "str | None":
    out = []
    changed = False
    for ch in text:
        o = ord(ch)
        if 33 <= o <= 126:
            out.append(chr(33 + ((o - 33 + 47) % 94)))
            changed = True
        else:
            out.append(ch)
    return "".join(out) if changed else None


def d_atbash(text: str) -> "str | None":
    if not any(c.isalpha() for c in text):
        return None
    out = []
    for ch in text:
        if ch.isupper():
            out.append(chr(ord("Z") - (ord(ch) - ord("A"))))
        elif ch.islower():
            out.append(chr(ord("z") - (ord(ch) - ord("a"))))
        else:
            out.append(ch)
    return "".join(out)


def d_reverse(text: str) -> "str | None":
    if len(text) < 2:
        return None
    return text[::-1]


def d_morse(text: str) -> "str | None":
    tokens = text.replace("/", " ").split()
    if not tokens or any(t not in MORSE_TABLE for t in tokens):
        return None
    return "".join(MORSE_TABLE[t] for t in tokens)


def d_binary(text: str) -> "str | None":
    bits = "".join(text.split())
    if len(bits) < 8 or len(bits) % 8 != 0 or set(bits) - {"0", "1"}:
        return None
    try:
        chars = [chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8)]
    except ValueError:
        return None
    out = "".join(chars)
    return out if _printable_ratio(out) >= 0.85 else None


def d_decimal(text: str) -> "str | None":
    parts = text.replace(",", " ").split()
    if len(parts) < 2 or any(not p.isdigit() for p in parts):
        return None
    try:
        vals = [int(p) for p in parts]
    except ValueError:
        return None
    if any(v > 0x10FFFF for v in vals):
        return None
    try:
        out = "".join(chr(v) for v in vals)
    except ValueError:
        return None
    return out if _printable_ratio(out) >= 0.85 else None


def caesar_shifts(text: str) -> "Iterable[tuple[str, str]]":
    """Yield ``(label, decoded)`` for all 25 Caesar shifts (letters only)."""
    if not any(c.isalpha() for c in text):
        return
    for shift in range(1, 26):
        out = []
        for ch in text:
            if ch.isupper():
                out.append(chr((ord(ch) - ord("A") - shift) % 26 + ord("A")))
            elif ch.islower():
                out.append(chr((ord(ch) - ord("a") - shift) % 26 + ord("a")))
            else:
                out.append(ch)
        yield f"caesar-{shift}", "".join(out)


def xor_single_byte(text: str) -> "Iterable[tuple[str, str]]":
    """Yield ``(label, decoded)`` for every single-byte XOR key that yields
    a mostly printable result."""
    raw = text.encode("latin-1", errors="ignore")
    if not raw:
        return
    for key in range(1, 256):
        out = bytes(b ^ key for b in raw)
        decoded = _clean_str(out)
        if decoded is not None and decoded != text:
            yield f"xor-{key:02x}", decoded


# Simple 1:1 decoders applied during recursive expansion.
SIMPLE_DECODERS: "dict[str, Decoder]" = {
    "base64": d_base64,
    "base64url": d_base64url,
    "base32": d_base32,
    "base85": d_base85,
    "ascii85": d_ascii85,
    "hex": d_hex,
    "url": d_url,
    "html": d_html,
    "rot13": d_rot13,
    "rot47": d_rot47,
    "atbash": d_atbash,
    "reverse": d_reverse,
    "morse": d_morse,
    "binary": d_binary,
    "decimal": d_decimal,
}


@dataclass
class Candidate:
    """A decoded plaintext plus the chain of transforms that produced it."""

    text: str
    chain: "list[str]" = field(default_factory=list)

    @property
    def method(self) -> str:
        return " > ".join(self.chain) if self.chain else "identity"


def expand(
    text: str,
    max_depth: int = 2,
    include_bruteforce: bool = True,
) -> "list[Candidate]":
    """Return every distinct candidate reachable from ``text`` within
    ``max_depth`` layers of transforms.

    ``include_bruteforce`` toggles the high-fan-out families (Caesar shifts and
    single-byte XOR) which are only applied at the first layer to keep the
    search space bounded.
    """
    results: "dict[str, Candidate]" = {}

    def add(cand: Candidate) -> bool:
        key = cand.text
        if key in results or key == text:
            return False
        results[key] = cand
        return True

    def recurse(current: str, chain: "list[str]", depth: int) -> None:
        if depth > max_depth:
            return
        for name, fn in SIMPLE_DECODERS.items():
            try:
                decoded = fn(current)
            except Exception:
                decoded = None
            if not decoded or decoded == current:
                continue
            new_chain = chain + [name]
            cand = Candidate(decoded, new_chain)
            if add(cand):
                recurse(decoded, new_chain, depth + 1)

    recurse(text, [], 1)

    if include_bruteforce:
        for label, decoded in caesar_shifts(text):
            add(Candidate(decoded, [label]))
        for label, decoded in xor_single_byte(text):
            add(Candidate(decoded, [label]))

    return list(results.values())

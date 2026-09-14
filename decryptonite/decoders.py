"""Reversible transforms used to expand an input string into candidate plaintexts.

Each *simple* decoder is a pure function ``str -> str | None``. It returns the
decoded string on success or ``None`` when the transform does not apply. Simple
decoders are applied recursively up to a configurable depth so layered
encodings (e.g. gzip of base64 of a hex string) are also uncovered.

*Brute-force families* return many ``(label, decoded)`` pairs (Caesar, affine,
XOR, Vigenere, rail fence) and are only expanded at the first layer to keep the
search space bounded.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import codecs
import gzip
import html
import lzma
import quopri
import string
import urllib.parse
import zlib
from dataclasses import dataclass, field
from typing import Callable, Iterable

Decoder = Callable[[str], "str | None"]

_PRINTABLE = set(string.printable)
_MAX_OUT = 4096  # ignore absurdly large decompressed outputs

MORSE_TABLE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}
BACON_TABLE = {
    "AAAAA": "A", "AAAAB": "B", "AAABA": "C", "AAABB": "D", "AABAA": "E",
    "AABAB": "F", "AABBA": "G", "AABBB": "H", "ABAAA": "I", "ABAAB": "J",
    "ABABA": "K", "ABABB": "L", "ABBAA": "M", "ABBAB": "N", "ABBBA": "O",
    "ABBBB": "P", "BAAAA": "Q", "BAAAB": "R", "BAABA": "S", "BAABB": "T",
    "BABAA": "U", "BABAB": "V", "BABBA": "W", "BABBB": "X", "BBAAA": "Y",
    "BBAAB": "Z",
}
LEET_MAP = {"4": "a", "@": "a", "8": "b", "3": "e", "1": "i", "0": "o",
            "5": "s", "$": "s", "7": "t", "9": "g", "2": "z"}
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B62_ALPHABET = string.digits + string.ascii_uppercase + string.ascii_lowercase
_B45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
# A small keyword list used to brute-force keyed ciphers (Vigenere / XOR).
COMMON_KEYS = [
    "key", "secret", "password", "pass", "cipher", "flag", "admin", "login",
    "crypto", "hello", "world", "test", "python", "ctf", "vigenere", "love",
    "god", "money", "root", "user", "qwerty", "letmein", "master", "dragon",
]


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(c in _PRINTABLE for c in text) / len(text)


def _clean_str(raw: bytes) -> "str | None":
    """Decode bytes to str, rejecting output that is mostly non-printable."""
    if not raw or len(raw) > _MAX_OUT:
        return None
    for enc in ("utf-8", "latin-1"):
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if text and _printable_ratio(text) >= 0.85:
            return text
        return None
    return None


# --------------------------------------------------------------------------- #
# Base-N encodings
# --------------------------------------------------------------------------- #
def d_base64(text: str) -> "str | None":
    s = text.strip()
    if len(s) < 4 or len(s) % 4 != 0:
        return None
    if any(c not in (string.ascii_letters + string.digits + "+/=") for c in s):
        return None
    try:
        return _clean_str(base64.b64decode(s, validate=True))
    except (binascii.Error, ValueError):
        return None


def d_base64url(text: str) -> "str | None":
    s = text.strip()
    if len(s) < 4:
        return None
    if any(c not in (string.ascii_letters + string.digits + "-_=") for c in s):
        return None
    try:
        return _clean_str(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
    except (binascii.Error, ValueError):
        return None


def d_base32(text: str) -> "str | None":
    s = text.strip().upper()
    if len(s) < 8 or len(s) % 8 != 0:
        return None
    try:
        return _clean_str(base64.b32decode(s))
    except (binascii.Error, ValueError):
        return None


def d_base85(text: str) -> "str | None":
    s = text.strip()
    if len(s) < 5:
        return None
    try:
        return _clean_str(base64.b85decode(s))
    except (ValueError, binascii.Error):
        return None


def d_ascii85(text: str) -> "str | None":
    s = text.strip()
    if len(s) < 5:
        return None
    try:
        return _clean_str(base64.a85decode(s))
    except (ValueError, binascii.Error):
        return None


def d_base16(text: str) -> "str | None":
    return d_hex(text)


def d_base58(text: str) -> "str | None":
    s = text.strip()
    if len(s) < 4 or any(c not in _B58_ALPHABET for c in s):
        return None
    num = 0
    for c in s:
        num = num * 58 + _B58_ALPHABET.index(c)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))
    return _clean_str(b"\x00" * pad + raw)


def d_base62(text: str) -> "str | None":
    s = text.strip()
    if len(s) < 4 or any(c not in _B62_ALPHABET for c in s):
        return None
    num = 0
    for c in s:
        num = num * 62 + _B62_ALPHABET.index(c)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return _clean_str(raw)


def d_base45(text: str) -> "str | None":
    s = text.strip().upper()
    if len(s) < 2 or len(s) % 3 == 1 or any(c not in _B45_ALPHABET for c in s):
        return None
    out = bytearray()
    try:
        for i in range(0, len(s), 3):
            chunk = s[i:i + 3]
            n = sum(_B45_ALPHABET.index(c) * (45 ** j) for j, c in enumerate(chunk))
            if len(chunk) == 3:
                if n > 0xFFFF:
                    return None
                out.append(n // 256)
                out.append(n % 256)
            else:
                if n > 0xFF:
                    return None
                out.append(n)
    except ValueError:
        return None
    return _clean_str(bytes(out))


def d_z85(text: str) -> "str | None":
    s = text.strip()
    if len(s) < 5 or len(s) % 5 != 0:
        return None
    try:
        return _clean_str(base64.z85decode(s))  # type: ignore[attr-defined]
    except (ValueError, binascii.Error, AttributeError):
        return None


def d_hex(text: str) -> "str | None":
    s = "".join(text.split())
    if s[:2].lower() == "0x":
        s = s[2:]
    if len(s) < 2 or len(s) % 2 != 0 or any(c not in string.hexdigits for c in s):
        return None
    try:
        return _clean_str(bytes.fromhex(s))
    except ValueError:
        return None


def d_uu(text: str) -> "str | None":
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("begin")]
    out = bytearray()
    try:
        for ln in lines:
            out += binascii.a2b_uu(ln)
    except (binascii.Error, ValueError):
        return None
    return _clean_str(bytes(out))


# --------------------------------------------------------------------------- #
# Text / web encodings
# --------------------------------------------------------------------------- #
def d_url(text: str) -> "str | None":
    if "%" not in text and "+" not in text:
        return None
    decoded = urllib.parse.unquote_plus(text)
    return decoded if decoded != text else None


def d_html(text: str) -> "str | None":
    if "&" not in text or ";" not in text:
        return None
    decoded = html.unescape(text)
    return decoded if decoded != text else None


def d_quopri(text: str) -> "str | None":
    if "=" not in text:
        return None
    try:
        decoded = quopri.decodestring(text.encode("latin-1"))
    except (ValueError, binascii.Error):
        return None
    out = _clean_str(decoded)
    return out if out and out != text else None


def d_punycode(text: str) -> "str | None":
    s = text.strip()
    if s.startswith("xn--"):
        s = s[4:]
    if not s or any(ord(c) > 127 for c in s):
        return None
    try:
        decoded = s.encode("ascii").decode("punycode")
    except (UnicodeError, ValueError):
        return None
    return decoded if decoded != text else None


def d_hex_escape(text: str) -> "str | None":
    if "\\x" not in text:
        return None
    try:
        decoded = codecs.decode(text, "unicode_escape")
    except (UnicodeDecodeError, ValueError):
        return None
    return decoded if decoded != text and _printable_ratio(decoded) >= 0.85 else None


def d_unicode_escape(text: str) -> "str | None":
    if "\\u" not in text:
        return None
    try:
        decoded = text.encode("latin-1", "ignore").decode("unicode_escape")
    except (UnicodeDecodeError, ValueError):
        return None
    return decoded if decoded != text and _printable_ratio(decoded) >= 0.85 else None


# --------------------------------------------------------------------------- #
# Classical / substitution
# --------------------------------------------------------------------------- #
def d_rot13(text: str) -> "str | None":
    return codecs.encode(text, "rot_13") if any(c.isalpha() for c in text) else None


def d_rot47(text: str) -> "str | None":
    out, changed = [], False
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
    return text[::-1] if len(text) >= 2 else None


def d_leet(text: str) -> "str | None":
    if not any(c in LEET_MAP for c in text):
        return None
    out = "".join(LEET_MAP.get(c, c) for c in text)
    return out if out != text else None


def d_baconian(text: str) -> "str | None":
    s = "".join(text.upper().split())
    s = s.replace("0", "A").replace("1", "B")
    if len(s) < 5 or len(s) % 5 != 0 or set(s) - {"A", "B"}:
        return None
    try:
        return "".join(BACON_TABLE[s[i:i + 5]] for i in range(0, len(s), 5))
    except KeyError:
        return None


# --------------------------------------------------------------------------- #
# Numeric representations
# --------------------------------------------------------------------------- #
def d_morse(text: str) -> "str | None":
    tokens = text.replace("/", " ").split()
    if not tokens or any(t not in MORSE_TABLE for t in tokens):
        return None
    return "".join(MORSE_TABLE[t] for t in tokens)


def d_binary(text: str) -> "str | None":
    bits = "".join(text.split())
    if len(bits) < 8 or len(bits) % 8 != 0 or set(bits) - {"0", "1"}:
        return None
    out = "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8))
    return out if _printable_ratio(out) >= 0.85 else None


def d_octal(text: str) -> "str | None":
    parts = text.replace(",", " ").split()
    if len(parts) < 2 or any(not p or set(p) - set("01234567") for p in parts):
        return None
    try:
        vals = [int(p, 8) for p in parts]
    except ValueError:
        return None
    if any(v > 0x10FFFF for v in vals):
        return None
    out = "".join(chr(v) for v in vals)
    return out if _printable_ratio(out) >= 0.85 else None


def d_decimal(text: str) -> "str | None":
    parts = text.replace(",", " ").split()
    if len(parts) < 2 or any(not p.isdigit() for p in parts):
        return None
    vals = [int(p) for p in parts]
    if any(v > 0x10FFFF for v in vals):
        return None
    out = "".join(chr(v) for v in vals)
    return out if _printable_ratio(out) >= 0.85 else None


def d_a1z26(text: str) -> "str | None":
    parts = text.replace("-", " ").replace(",", " ").split()
    if len(parts) < 2 or any(not p.isdigit() for p in parts):
        return None
    vals = [int(p) for p in parts]
    if any(v < 1 or v > 26 for v in vals):
        return None
    return "".join(chr(v - 1 + ord("a")) for v in vals)


# --------------------------------------------------------------------------- #
# Compression (often layered under base64)
# --------------------------------------------------------------------------- #
def _decompress(fn: "Callable[[bytes], bytes]", text: str) -> "str | None":
    raw = text.encode("latin-1", errors="ignore")
    try:
        return _clean_str(fn(raw))
    except Exception:
        return None


def d_gzip(text: str) -> "str | None":
    return _decompress(gzip.decompress, text)


def d_zlib(text: str) -> "str | None":
    return _decompress(zlib.decompress, text)


def d_bz2(text: str) -> "str | None":
    return _decompress(bz2.decompress, text)


def d_lzma(text: str) -> "str | None":
    return _decompress(lzma.decompress, text)


# --------------------------------------------------------------------------- #
# Brute-force families (many outputs, first layer only)
# --------------------------------------------------------------------------- #
def caesar_shifts(text: str) -> "Iterable[tuple[str, str]]":
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


def affine_shifts(text: str) -> "Iterable[tuple[str, str]]":
    if not any(c.isalpha() for c in text):
        return
    coprimes = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    for a in coprimes:
        a_inv = pow(a, -1, 26)
        for b in range(26):
            if a == 1 and b == 0:
                continue
            out = []
            for ch in text:
                if ch.isupper():
                    out.append(chr(a_inv * (ord(ch) - ord("A") - b) % 26 + ord("A")))
                elif ch.islower():
                    out.append(chr(a_inv * (ord(ch) - ord("a") - b) % 26 + ord("a")))
                else:
                    out.append(ch)
            yield f"affine-a{a}b{b}", "".join(out)


def xor_single_byte(text: str) -> "Iterable[tuple[str, str]]":
    raw = text.encode("latin-1", errors="ignore")
    if not raw:
        return
    for key in range(1, 256):
        decoded = _clean_str(bytes(b ^ key for b in raw))
        if decoded is not None and decoded != text:
            yield f"xor-{key:02x}", decoded


def xor_keyword(text: str) -> "Iterable[tuple[str, str]]":
    raw = text.encode("latin-1", errors="ignore")
    if not raw:
        return
    for key in COMMON_KEYS:
        kb = key.encode()
        decoded = _clean_str(bytes(b ^ kb[i % len(kb)] for i, b in enumerate(raw)))
        if decoded is not None and decoded != text:
            yield f"xor-key:{key}", decoded


def vigenere_keyword(text: str) -> "Iterable[tuple[str, str]]":
    if not any(c.isalpha() for c in text):
        return
    for key in COMMON_KEYS:
        kl = [ord(k) - ord("a") for k in key.lower() if k.isalpha()]
        if not kl:
            continue
        out, ki = [], 0
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                out.append(chr((ord(ch) - base - kl[ki % len(kl)]) % 26 + base))
                ki += 1
            else:
                out.append(ch)
        result = "".join(out)
        if result != text:
            yield f"vigenere:{key}", result


def railfence(text: str) -> "Iterable[tuple[str, str]]":
    n = len(text)
    if n < 4:
        return
    for rails in range(2, min(12, n)):
        pattern, r, step = [], 0, 1
        for _ in range(n):
            pattern.append(r)
            if r == 0:
                step = 1
            elif r == rails - 1:
                step = -1
            r += step
        counts = [pattern.count(i) for i in range(rails)]
        chunks, idx = [], 0
        for c in counts:
            chunks.append(list(text[idx:idx + c]))
            idx += c
        out, pos = [], [0] * rails
        for r in pattern:
            out.append(chunks[r][pos[r]])
            pos[r] += 1
        result = "".join(out)
        if result != text:
            yield f"railfence-{rails}", result


# --------------------------------------------------------------------------- #
# Registries
# --------------------------------------------------------------------------- #
SIMPLE_DECODERS: "dict[str, Decoder]" = {
    "base64": d_base64, "base64url": d_base64url, "base32": d_base32,
    "base58": d_base58, "base62": d_base62, "base45": d_base45,
    "base85": d_base85, "ascii85": d_ascii85, "z85": d_z85, "hex": d_hex,
    "uudecode": d_uu, "url": d_url, "html": d_html, "quoted-printable": d_quopri,
    "punycode": d_punycode, "hex-escape": d_hex_escape,
    "unicode-escape": d_unicode_escape, "rot13": d_rot13, "rot47": d_rot47,
    "atbash": d_atbash, "reverse": d_reverse, "leet": d_leet,
    "baconian": d_baconian, "morse": d_morse, "binary": d_binary,
    "octal": d_octal, "decimal": d_decimal, "a1z26": d_a1z26,
    "gzip": d_gzip, "zlib": d_zlib, "bz2": d_bz2, "lzma": d_lzma,
}

BRUTE_FAMILIES: "dict[str, Callable[[str], Iterable[tuple[str, str]]]]" = {
    "caesar": caesar_shifts,
    "affine": affine_shifts,
    "xor-single-byte": xor_single_byte,
    "xor-keyword": xor_keyword,
    "vigenere": vigenere_keyword,
    "railfence": railfence,
}


def technology_count() -> "tuple[int, int]":
    """Return ``(simple_decoders, brute_families)`` counts."""
    return len(SIMPLE_DECODERS), len(BRUTE_FAMILIES)


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
    ``max_depth`` layers of simple decoders, plus one layer of brute-force
    families when ``include_bruteforce`` is set.
    """
    results: "dict[str, Candidate]" = {}

    def add(cand: Candidate) -> bool:
        if cand.text in results or cand.text == text:
            return False
        results[cand.text] = cand
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
            if add(Candidate(decoded, new_chain)):
                recurse(decoded, new_chain, depth + 1)

    recurse(text, [], 1)

    if include_bruteforce:
        for family in BRUTE_FAMILIES.values():
            try:
                for label, decoded in family(text):
                    add(Candidate(decoded, [label]))
            except Exception:
                continue

    return list(results.values())

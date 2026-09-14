import base64

from decryptonite.decoders import expand
from decryptonite.scorer import heuristic_score, rank


def _texts(cands):
    return {c.text for c in cands}


def test_base64_roundtrip():
    secret = "hunter2"
    encoded = base64.b64encode(secret.encode()).decode()
    cands = expand(encoded, max_depth=1, include_bruteforce=False)
    assert secret in _texts(cands)


def test_hex_roundtrip():
    secret = "correcthorse"
    encoded = secret.encode().hex()
    cands = expand(encoded, max_depth=1, include_bruteforce=False)
    assert secret in _texts(cands)


def test_layered_base64_of_hex():
    secret = "layered!"
    hexed = secret.encode().hex()
    encoded = base64.b64encode(hexed.encode()).decode()
    cands = expand(encoded, max_depth=2, include_bruteforce=False)
    assert secret in _texts(cands)


def test_rot13_and_reverse():
    cands = _texts(expand("uryyb", max_depth=1, include_bruteforce=False))
    assert "hello" in cands
    cands = _texts(expand("drowssap", max_depth=1, include_bruteforce=False))
    assert "password" in cands


def test_caesar_bruteforce():
    # "khoor" is "hello" shifted by +3
    cands = _texts(expand("khoor", max_depth=1, include_bruteforce=True))
    assert "hello" in cands


def test_heuristic_prefers_words_over_soup():
    assert heuristic_score("Password123!") > heuristic_score("\x01\x02\x9f\xaa")
    assert heuristic_score("hello") > heuristic_score("qxzjkv")


def test_rank_orders_by_score_without_llm():
    cands = expand(base64.b64encode(b"MyS3cret!").decode(), include_bruteforce=False)
    ranked = rank(cands, judge=None)
    scores = [s.final for s in ranked]
    assert scores == sorted(scores, reverse=True)


def test_base58_roundtrip():
    # base58 of "hello" is "Cn8eVZg"
    cands = _texts(expand("Cn8eVZg", max_depth=1, include_bruteforce=False))
    assert "hello" in cands


def test_a1z26():
    cands = _texts(expand("8 5 12 12 15", max_depth=1, include_bruteforce=False))
    assert "hello" in cands


def test_baconian():
    # "AABAAAABABAABBAABBABBBA" padded: HELLO in baconian
    enc = "AABBBAABAAABABBABABBABBBA"[:25]  # ensure multiple of 5 handled below
    # build cleanly: H=AABBB E=AABAA L=ABABB L=ABABB O=ABBBA
    enc = "AABBBAABAAABABBABABBABBBA"
    cands = _texts(expand(enc, max_depth=1, include_bruteforce=False))
    assert "HELLO" in cands


def test_vigenere_bruteforce():
    # "rijvs" with key "key" decrypts to "hello"
    cands = _texts(expand("rijvs", max_depth=1, include_bruteforce=True))
    assert "hello" in cands


def test_technology_count_is_deep():
    from decryptonite.decoders import technology_count
    simple, brute = technology_count()
    assert simple >= 30 and brute >= 5

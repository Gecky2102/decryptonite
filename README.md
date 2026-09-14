<div align="center">

# 🟢 Decryptonite

**Throw a string at the wall and see which decodings stick.**

Decryptonite takes one mysterious string, brute-forces *every plausible way it
could have been encoded or lightly ciphered*, then asks a local LLM (via
[Ollama](https://ollama.com)) which of the results actually look like a real
password, passphrase, or meaningful secret — instead of random byte soup.

[Idea](#the-idea) · [Install](#install) · [Usage](#usage) · [How it works](#how-it-works) · [Decoders](#supported-decoders) · [Disclaimer](#disclaimer)

</div>

---

## The idea

You find a string. `TXlQYXNzdzByZCE=`. Is it base64? hex? a Caesar shift? XOR?
Something wrapped twice? Manually trying every tool is tedious, and once you
*do* generate hundreds of candidate decodings, you still have to eyeball which
one is signal and which is garbage.

Decryptonite does both halves:

1. **Expand** — apply a whole zoo of reversible transforms (and *chains* of
   them, up to N layers deep) to produce every candidate plaintext.
2. **Judge** — score each candidate. A fast built-in heuristic ranks all of
   them by how "human meaningful" they look (pronounceability, character mix,
   entropy, secret-like words). Then a local Ollama model re-ranks the top
   contenders, telling you *which strings smell like a real secret* — and why.

No candidate ever leaves your machine: the LLM runs locally through Ollama.

## Install

```bash
git clone https://github.com/Gecky2102/decryptonite
cd decryptonite
pip install .
```

Zero runtime dependencies — pure Python standard library. Python 3.9+.

The LLM step is **optional**. For it you need [Ollama](https://ollama.com)
running with any instruct model:

```bash
ollama pull llama3.2:1b   # small & fast; any instruct model works
ollama serve   # usually already running
```

Without Ollama, Decryptonite automatically falls back to heuristic-only ranking.

## Usage

```bash
# basic: brute-force + LLM judge
decryptonite "TXlQYXNzdzByZCE="

# heuristic only, no LLM
decryptonite "khoor zruog" --no-llm

# go deeper (chained encodings) and show more results
decryptonite "<string>" --depth 3 --top 25

# pick a different model / host
decryptonite "<string>" --model mistral --host http://localhost:11434

# pipe it, get JSON out
echo "01001000 01101001" | decryptonite --json
```

Example output:

```
  DECRYPTONITE  · decode & rank
  ────────────────────────────────────────────────────────────
  input      TXlQYXNzdzByZCE=
  searched   32 decoders + 6 brute-force families → 434 candidates
  judge      ollama:llama3.2:1b  (20 scored)

  BEST MATCH
  ╭──────────────────────────────────────────────────────────
  │ MyPassword!
  │ via base64 > leet
  │ ██████████████████████░░  91/100  [strong]   llm=90 heu=92 — real words
  ╰──────────────────────────────────────────────────────────

  OTHER CANDIDATES
   #  score  method                 plaintext
   2     91  base64                 MyPassw0rd!
      ↳ readable password
   3     47  affine-a9b1            COeTROKuguArUDJ=
   ...
```

### Options

| Flag | Default | Meaning |
|------|---------|---------|
| `-d, --depth` | `2` | Max layers of chained decoders |
| `-n, --top` | `15` | How many candidates to display |
| `--no-bruteforce` | off | Skip high-fan-out families (Caesar, single-byte XOR) |
| `--no-llm` | off | Heuristic ranking only |
| `--model` | `llama3.2:1b` | Ollama model used as judge (small = fast) |
| `--host` | `http://localhost:11434` | Ollama endpoint |
| `--llm-top` | `20` | How many top candidates to send to the LLM |
| `--no-color` | off | Disable ANSI colors |
| `--json` | off | Machine-readable output |

## How it works

```
          ┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
 string ─▶│   expand()  │────▶│ heuristic score  │────▶│  Ollama judge   │──▶ ranked
          │  decoders   │     │ (all candidates) │     │   (top K only)  │    results
          └─────────────┘     └──────────────────┘     └─────────────────┘
```

- **`decoders.py`** — each transform is a pure `str -> str | None` function.
  They're applied recursively so `base64(hex(secret))` gets peeled layer by
  layer. Output that is mostly non-printable is discarded early.
- **`scorer.py`** — `heuristic_score` blends printable ratio, vowel balance,
  common-bigram pronounceability, secret-like words and entropy into a 0–100
  value. `OllamaJudge` prompts a local model for a JSON `{score, reason}` and
  the final rank is a blend (`0.4 * heuristic + 0.6 * llm`) with a heuristic
  floor, so a small/weak model can promote but not bury a readable candidate.
- **`cli.py`** — argument parsing, stdin support, pretty and `--json` output.
- **`progress.py`** — dependency-free progress bar (percentage + ETA) shown on
  stderr during the LLM pass; auto-disabled when output is piped or `--json`.

## Supported decoders

**38 techniques** in two groups. Simple decoders are chained automatically up
to `--depth`; brute-force families run once, on the raw input.

**Encodings (32 simple decoders)**

- *Base-N*: Base64, Base64URL, Base32, Base58, Base62, Base45, Base85, Ascii85,
  Z85, Hex/Base16, uudecode
- *Web/text*: URL/percent, HTML entities, quoted-printable, punycode,
  `\xNN` hex escapes, `\uNNNN` unicode escapes
- *Classical*: ROT13, ROT47, Atbash, reverse, leetspeak, Baconian
- *Numeric*: Morse, binary, octal, decimal ASCII, A1Z26
- *Compression*: gzip, zlib, bz2, lzma (great for base64-wrapped blobs)

**Brute-force families (6)**

- Caesar (all 25 shifts)
- Affine (every valid a/b pair)
- XOR single-byte (all 256 keys)
- XOR keyword (common-key wordlist)
- Vigenère (common-key wordlist)
- Rail fence (2–11 rails)

A typical input expands into **hundreds** of candidates; the heuristic + LLM
ranking is what makes the pile readable.

## Contributing

Adding a decoder is one function in `decryptonite/decoders.py` plus an entry in
`SIMPLE_DECODERS`. Tests live in `tests/`:

```bash
pip install pytest && pytest
```

PRs for new ciphers, better heuristics, or wordlist integration are welcome.

## Disclaimer

Decryptonite is built for **CTF challenges, security research, and recovering
your own data**. It only reverses lightweight encodings and classical ciphers —
it does not break modern cryptography. Use it only on data you are authorized to
analyze.

## License

[MIT](LICENSE) © Giacomo Masiero

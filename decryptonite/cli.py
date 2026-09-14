"""Command-line entry point for Decryptonite."""

from __future__ import annotations

import argparse
import sys

from .decoders import expand
from .scorer import OllamaJudge, rank

BANNER = r"""
  ___                       _              _ _
 |   \ ___ __ _ _ _ _  _ _ | |_ ___ _ _ (_) |_ ___
 | |) / -_) _| '_| || | '_ \  _/ _ \ ' \| |  _/ -_)
 |___/\___\__|_|  \_, | .__/\__\___/_||_|_|\__\___|
                  |__/|_|   throw a string at the wall
"""


def _bar(value: float, width: int = 20) -> str:
    filled = int(round(value / 100 * width))
    return "#" * filled + "-" * (width - filled)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="decryptonite",
        description="Expand a string into every plausible decoding, then let a "
        "local LLM flag the ones that look like real secrets.",
    )
    p.add_argument("string", nargs="?", help="the string to crack (or read stdin)")
    p.add_argument(
        "-d", "--depth", type=int, default=2,
        help="max layers of chained decoders (default: 2)",
    )
    p.add_argument(
        "-n", "--top", type=int, default=15,
        help="how many candidates to display (default: 15)",
    )
    p.add_argument(
        "--no-bruteforce", action="store_true",
        help="skip high-fan-out families (Caesar shifts, single-byte XOR)",
    )
    p.add_argument(
        "--no-llm", action="store_true",
        help="heuristic ranking only; do not call Ollama",
    )
    p.add_argument(
        "--model", default="llama3.2:1b",
        help="Ollama model used as judge (default: llama3.2:1b, chosen for speed)",
    )
    p.add_argument(
        "--host", default="http://localhost:11434",
        help="Ollama host (default: http://localhost:11434)",
    )
    p.add_argument(
        "--llm-top", type=int, default=20,
        help="how many top heuristic candidates to send to the LLM (default: 20)",
    )
    p.add_argument(
        "--json", action="store_true", help="emit results as JSON",
    )
    return p


def main(argv: "list[str] | None" = None) -> int:
    args = build_parser().parse_args(argv)

    text = args.string
    if text is None:
        if sys.stdin.isatty():
            build_parser().print_help()
            return 2
        text = sys.stdin.read().strip()
    if not text:
        print("error: empty input", file=sys.stderr)
        return 2

    candidates = expand(
        text,
        max_depth=args.depth,
        include_bruteforce=not args.no_bruteforce,
    )

    judge = None
    if not args.no_llm:
        judge = OllamaJudge(model=args.model, host=args.host)
        if not judge.available():
            print(
                f"warning: Ollama not reachable at {args.host}; "
                "falling back to heuristic ranking.",
                file=sys.stderr,
            )
            judge = None

    scored = rank(
        candidates,
        judge=judge,
        llm_top_k=args.llm_top,
        progress=False if args.json else None,
    )
    top = scored[: args.top]

    if args.json:
        import json

        print(json.dumps(
            [
                {
                    "text": s.candidate.text,
                    "method": s.candidate.method,
                    "heuristic": round(s.heuristic, 1),
                    "llm": None if s.llm is None else round(s.llm, 1),
                    "score": round(s.final, 1),
                    "reason": s.reason,
                }
                for s in top
            ],
            indent=2,
            ensure_ascii=False,
        ))
        return 0

    print(BANNER)
    print(f"input      : {text!r}")
    print(f"candidates : {len(candidates)} decoded  |  showing top {len(top)}")
    print(f"judge      : {'ollama:' + args.model if judge else 'heuristic only'}")
    print("-" * 72)

    if not top:
        print("no decodable candidates found.")
        return 0

    for i, s in enumerate(top, 1):
        tag = "LLM" if s.llm is not None else "HEU"
        print(f"{i:>2}. [{s.final:5.1f}] {_bar(s.final)}  via {s.candidate.method}")
        print(f"    {s.candidate.text!r}")
        detail = f"    {tag}"
        if s.llm is not None:
            detail += f" llm={s.llm:.0f} heu={s.heuristic:.0f}"
            if s.reason:
                detail += f"  — {s.reason}"
        print(detail)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

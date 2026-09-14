"""Command-line entry point for Decryptonite."""

from __future__ import annotations

import argparse
import sys

from .decoders import expand, technology_count
from .scorer import OllamaJudge, ScoredCandidate, rank


# --------------------------------------------------------------------------- #
# Rendering helpers
# --------------------------------------------------------------------------- #
class _Style:
    def __init__(self, enabled: bool) -> None:
        self.on = enabled

    def _w(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.on else text

    def bold(self, t: str) -> str:
        return self._w("1", t)

    def dim(self, t: str) -> str:
        return self._w("2", t)

    def green(self, t: str) -> str:
        return self._w("32", t)

    def yellow(self, t: str) -> str:
        return self._w("33", t)

    def red(self, t: str) -> str:
        return self._w("31", t)

    def cyan(self, t: str) -> str:
        return self._w("36", t)


def _safe(text: str, limit: int = 48) -> str:
    """Escape control chars for single-line display and truncate."""
    shown = text.encode("unicode_escape").decode("ascii")
    if len(shown) > limit:
        shown = shown[: limit - 1] + "…"
    return shown


def _bar(value: float, width: int = 24) -> str:
    filled = int(round(value / 100 * width))
    return "█" * filled + "░" * (width - filled)


def _tier(score: float) -> str:
    if score >= 70:
        return "strong"
    if score >= 45:
        return "maybe"
    return "weak"


def _color_for(st: "_Style", score: float) -> "callable":
    if score >= 70:
        return st.green
    if score >= 45:
        return st.yellow
    return st.dim


def render(
    text: str,
    candidates: list,
    scored: "list[ScoredCandidate]",
    top_n: int,
    judge_label: str,
    style: _Style,
) -> None:
    st = style
    n_simple, n_brute = technology_count()
    judged = sum(1 for s in scored if s.judged)

    print()
    print(st.bold(st.cyan("  DECRYPTONITE")) + st.dim("  · decode & rank"))
    print(st.dim("  " + "─" * 60))
    print(f"  {st.dim('input     ')} {_safe(text, 60)}")
    print(
        f"  {st.dim('searched  ')} {n_simple} decoders + {n_brute} brute-force "
        f"families → {len(candidates)} candidates"
    )
    print(f"  {st.dim('judge     ')} {judge_label}"
          + (st.dim(f"  ({judged} scored)") if judged else ""))
    print()

    if not scored:
        print("  " + st.yellow("no decodable candidates found."))
        return

    best = scored[0]
    bcolor = _color_for(st, best.final)
    print("  " + st.bold("BEST MATCH"))
    print("  " + st.dim("╭" + "─" * 58))
    print("  " + st.dim("│ ") + bcolor(st.bold(_safe(best.candidate.text, 54))))
    print("  " + st.dim("│ ") + st.dim("via ") + best.candidate.method)
    verdict = f"{best.final:.0f}/100  [{_tier(best.final)}]"
    if best.llm is not None:
        verdict += f"   llm={best.llm:.0f} heu={best.heuristic:.0f}"
        if best.reason:
            verdict += f"  — {best.reason}"
    print("  " + st.dim("│ ") + bcolor(_bar(best.final)) + "  " + verdict)
    print("  " + st.dim("╰" + "─" * 58))
    print()

    rest = scored[1:top_n]
    if not rest:
        return
    print("  " + st.bold("OTHER CANDIDATES"))
    print("  " + st.dim(f"{'#':>2}  {'score':>5}  {'method':<22} {'plaintext'}"))
    for i, s in enumerate(rest, 2):
        color = _color_for(st, s.final)
        method = _safe(s.candidate.method, 22)
        line = (
            f"  {i:>2}  {color(f'{s.final:>5.0f}')}  "
            f"{st.dim(f'{method:<22}')} {_safe(s.candidate.text, 40)}"
        )
        print(line)
        if s.reason:
            print("      " + st.dim(f"↳ {s.reason}"))
    print()


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="decryptonite",
        description="Expand a string into every plausible decoding, then let a "
        "local LLM flag the ones that look like real secrets.",
    )
    p.add_argument("string", nargs="?", help="the string to crack (or read stdin)")
    p.add_argument("-d", "--depth", type=int, default=2,
                   help="max layers of chained decoders (default: 2)")
    p.add_argument("-n", "--top", type=int, default=15,
                   help="how many candidates to display (default: 15)")
    p.add_argument("--no-bruteforce", action="store_true",
                   help="skip brute-force families (Caesar, affine, XOR, ...)")
    p.add_argument("--no-llm", action="store_true",
                   help="heuristic ranking only; do not call Ollama")
    p.add_argument("--model", default="llama3.2:1b",
                   help="Ollama model used as judge (default: llama3.2:1b)")
    p.add_argument("--host", default="http://localhost:11434",
                   help="Ollama host (default: http://localhost:11434)")
    p.add_argument("--llm-top", type=int, default=20,
                   help="how many top candidates to send to the LLM (default: 20)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--json", action="store_true", help="emit results as JSON")
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
        text, max_depth=args.depth, include_bruteforce=not args.no_bruteforce,
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
        candidates, judge=judge, llm_top_k=args.llm_top,
        progress=False if args.json else None,
    )
    top = scored[: args.top]

    if args.json:
        import json

        print(json.dumps(
            [
                {
                    "rank": i,
                    "text": s.candidate.text,
                    "method": s.candidate.method,
                    "heuristic": round(s.heuristic, 1),
                    "llm": None if s.llm is None else round(s.llm, 1),
                    "score": round(s.final, 1),
                    "tier": _tier(s.final),
                    "reason": s.reason,
                }
                for i, s in enumerate(top, 1)
            ],
            indent=2, ensure_ascii=False,
        ))
        return 0

    color = sys.stdout.isatty() and not args.no_color
    label = f"ollama:{args.model}" if judge else "heuristic only"
    render(text, candidates, scored, args.top, label, _Style(color))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

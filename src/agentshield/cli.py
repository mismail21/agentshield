"""Command line: ``agentshield list | bench | report | scan``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _load_dotenv() -> None:
    env = Path(".env")
    if env.exists():
        for line in env.read_text().splitlines():
            k, sep, v = line.strip().partition("=")
            if sep and not k.startswith("#") and k not in os.environ:
                os.environ[k] = v.strip().strip('"')


def cmd_list(args: argparse.Namespace) -> None:
    from .agents import SCENARIOS

    for s in SCENARIOS.values():
        print(f"{s.name}: {s.description}")
        print(f"  tools: {', '.join(t.name for t in s.tools)}")
        for t in s.tasks.values():
            print(f"  task {t.id}: {t.prompt.splitlines()[0]}")
            print(f"    slots: {', '.join(t.slots)}   allowed tools: {', '.join(t.allowed_tools)}")


def cmd_bench(args: argparse.Namespace) -> None:
    from .attacks import load_attacks
    from .bench import load_rows, run, summarize
    from .defense.detector import load_detector
    from .defense.shield import Shield
    from .llm import make_llm

    detector = load_detector(args.detector, args.detector_path) if any(
        "detector" in s or s == "full" for s in args.shields) else None
    shields = [Shield.from_spec(s, detector=detector, threshold=args.threshold) for s in args.shields]
    attacks = load_attacks(args.attacks) if args.attacks else None
    llms = [make_llm(m) for m in args.models]
    run(llms, shields, args.out, scenarios=args.scenarios, attacks=attacks, benign=not args.no_benign,
        resume=not args.fresh, max_turns=args.max_turns, repeats=args.repeats)
    print()
    print(summarize(load_rows(Path(args.out) / "runs.jsonl")))


def cmd_report(args: argparse.Namespace) -> None:
    from .bench import load_rows, summarize

    print(summarize(load_rows(args.runs)))


def cmd_scan(args: argparse.Namespace) -> None:
    from .defense.detector import load_detector
    from .defense.shield import segments

    det = load_detector(args.detector, args.detector_path)
    text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text()
    segs = segments(text)
    for seg, score in zip(segs, det.score(segs)):
        flag = "FLAG" if score >= args.threshold else "ok  "
        print(f"{flag} {score:.3f}  {json.dumps(seg[:100])}")


def main(argv: list[str] | None = None) -> None:
    _load_dotenv()
    p = argparse.ArgumentParser(prog="agentshield", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="show scenarios, tasks and injection slots").set_defaults(fn=cmd_list)

    b = sub.add_parser("bench", help="run the benchmark")
    b.add_argument("--models", nargs="+", required=True,
                   help="e.g. gemini:gemini-3.5-flash-lite gemini:gemma-4-26b-a4b-it ollama:qwen3:1.7b")
    b.add_argument("--shields", nargs="+", default=["none", "full"],
                   help="none | full | components joined by '+': detector, spotlight, tools, output")
    b.add_argument("--attacks", help="YAML attack file (see agentshield.attacks); omit for benign-only runs")
    b.add_argument("--scenarios", nargs="+", help="subset of: triage email devassist")
    b.add_argument("--no-benign", action="store_true", help="skip the benign (no-attack) runs")
    b.add_argument("--detector", default="heuristic", help="heuristic | tfidf | HF model id or path")
    b.add_argument("--detector-path")
    b.add_argument("--threshold", type=float, default=0.5)
    b.add_argument("--max-turns", type=int, default=6)
    b.add_argument("--repeats", type=int, default=1, help="run each episode this many times")
    b.add_argument("--out", default="results")
    b.add_argument("--fresh", action="store_true", help="ignore existing results instead of resuming")
    b.set_defaults(fn=cmd_bench)

    r = sub.add_parser("report", help="summarize a runs.jsonl as a markdown table")
    r.add_argument("runs")
    r.set_defaults(fn=cmd_report)

    s = sub.add_parser("scan", help="score a text file with a detector, segment by segment")
    s.add_argument("file", help="path, or - for stdin")
    s.add_argument("--detector", default="heuristic")
    s.add_argument("--detector-path")
    s.add_argument("--threshold", type=float, default=0.5)
    s.set_defaults(fn=cmd_scan)

    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()

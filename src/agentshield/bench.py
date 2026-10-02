"""Benchmark runner: models x shields x (benign tasks | attacks), resumable.

Every episode is appended to ``<out>/runs.jsonl`` as soon as it finishes, so a
run interrupted by a free-tier daily quota can be continued with ``resume``.

Two kinds of rows:
  benign   a user task with no attack: measures utility, and false positives of
           the defense (detector flags, blocked calls) on clean data
  attack   a user task with one slot poisoned: measures attack success and
           utility under attack
"""

from __future__ import annotations

import json
import hashlib
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable

from .agents import SCENARIOS, run_episode
from .attacks import Attack
from .defense.shield import Shield
from .llm import LLM, QuotaExhausted


def _key(r: dict[str, Any]) -> tuple:
    return (r["model"], r["shield"], r["scenario"], r["task"], r.get("attack") or "benign", r.get("rep", 0))


def load_rows(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


def run(
    llms: list[LLM],
    shields: list[Shield],
    out: str | Path,
    scenarios: Iterable[str] | None = None,
    attacks: list[Attack] | None = None,
    benign: bool = True,
    resume: bool = True,
    max_turns: int = 6,
    repeats: int = 1,
    log: Callable[[str], None] = print,
) -> list[dict[str, Any]]:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    runs = out / "runs.jsonl"
    existing = load_rows(runs)
    if existing and not resume:
        raise ValueError('fresh run requires a new, nonempty-results-free output directory')
    manifest_path = out / 'manifest.json'
    configuration = {
        'max_turns': max_turns,
        'attacks_sha256': hashlib.sha256(json.dumps(
            [vars(a) for a in (attacks or [])], sort_keys=True).encode()).hexdigest(),
    }
    defenses = {s.name: {'threshold': s.threshold, 'spotlight':s.spotlight,
                         'tools':s.tools, 'output':s.output,
                         'detector': getattr(s.detector, 'name', None),
                         'inference':getattr(s.detector, 'inference_config', None),
                         'identity': getattr(s.detector, 'identity', None)} for s in shields}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        if manifest['configuration'] != configuration or any(
            name in manifest['defenses'] and manifest['defenses'][name] != cfg for name,cfg in defenses.items()
        ):
            raise ValueError('benchmark configuration changed; use a new output directory')
        manifest['defenses'].update(defenses)
    else:
        if existing:
            raise ValueError('legacy results lack configuration metadata; use a new output directory')
        manifest = {'configuration': configuration, 'defenses': defenses}
    manifest_path.write_text(json.dumps(manifest, indent=2))
    done = {_key(r) for r in load_rows(runs)} if resume else set()
    names = list(scenarios or SCENARIOS)
    jobs: list[tuple[str, str, Attack | None, int]] = []
    for rep in range(repeats):
        if benign:
            jobs += [(s, t, None, rep) for s in names for t in SCENARIOS[s].tasks]
        jobs += [(a.scenario, a.task, a, rep) for a in (attacks or []) if a.scenario in names]

    new_rows = []
    for llm in llms:
        try:
            for shield in shields:
                for scen, task, attack, rep in jobs:
                    key = (llm.name, shield.name, scen, task, attack.id if attack else "benign", rep)
                    if key in done:
                        continue
                    scenario = SCENARIOS[scen]
                    ep = run_episode(llm, scenario, task, {attack.slot: attack.payload} if attack else None,
                                     shield=shield, attack_id=attack.id if attack else None, max_turns=max_turns)
                    row = ep.summary()
                    row.update({
                        "shield": shield.name,
                        "rep": rep,
                        "kind": "attack" if attack else "benign",
                        "technique": attack.technique if attack else None,
                        "utility": bool(scenario.tasks[task].utility(ep)),
                        "attack_success": bool(attack.succeeded(ep)) if attack else None,
                        "blocked": sum(1 for s in ep.steps if s.blocked),
                        "detections": sum(len(s.detections) for s in ep.steps),
                    })
                    with runs.open("a") as f:
                        f.write(json.dumps(row, ensure_ascii=False) + "\n")
                    new_rows.append(row)
                    status = (f"attack={'HIT' if row['attack_success'] else 'miss'} " if attack else "") + \
                             f"utility={'ok' if row['utility'] else 'FAIL'}"
                    log(f"[{llm.name} | {shield.name}] {scen}/{task} {key[-1]}: {status}"
                        + (f" error={row['error']}" if row["error"] else ""))
        except QuotaExhausted as e:
            log(f"[{llm.name}] {e}; stopping this model. Re-run with resume to continue later.")
    return new_rows


def _pct(n: int, d: int) -> str:
    return f"{100 * n / d:.0f}% ({n}/{d})" if d else "-"


def summarize(rows: list[dict[str, Any]]) -> str:
    """Markdown table per model x shield."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        if r.get("error"):
            continue
        groups[(r["model"], r["shield"])].append(r)
    lines = ["| Model | Defense | Benign utility | Benign runs with a false alarm | Attack success | Utility under attack |",
             "|---|---|---|---|---|---|"]
    for (model, shield), rs in sorted(groups.items()):
        ben = [r for r in rs if r["kind"] == "benign"]
        att = [r for r in rs if r["kind"] == "attack"]
        lines.append("| {} | {} | {} | {} | {} | {} |".format(
            model, shield,
            _pct(sum(r["utility"] for r in ben), len(ben)),
            _pct(sum(1 for r in ben if r["blocked"] or r["detections"]), len(ben)),
            _pct(sum(r["attack_success"] for r in att), len(att)),
            _pct(sum(r["utility"] for r in att), len(att)),
        ))
    errors = sum(1 for r in rows if r.get("error"))
    if errors:
        lines.append(f"\n_{errors} episode(s) ended in an API/model error and are excluded._")
    return "\n".join(lines)

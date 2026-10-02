"""Validate complete local experiments and update documentation from measured rows."""
from collections import Counter
from pathlib import Path
import json
import re

from agentshield.agents import SCENARIOS
from agentshield.attacks import load_attacks
from agentshield.bench import load_rows, summarize

ROOT = Path(__file__).resolve().parents[1]
MODELS = ['ollama/qwen3:1.7b','ollama/qwen2.5:1.5b','ollama/llama3.2:1b']


def checked_rows(directory, models, defenses, expected_errors=()):
    rows = load_rows(ROOT/'results'/directory/'runs.jsonl')
    attacks = load_attacks('builtin')
    tasks = [(s,t,None) for s,sc in SCENARIOS.items() for t in sc.tasks]
    jobs = tasks + [(a.scenario,a.task,a.id) for a in attacks]
    expected = {(m,d,s,t,a,0) for m in models for d in defenses for s,t,a in jobs}
    actual = Counter((r['model'],r['shield'],r['scenario'],r['task'],r['attack'],r['rep']) for r in rows)
    if set(actual) != expected or any(n!=1 for n in actual.values()):
        raise ValueError(f'{directory}: missing={len(expected-set(actual))}, unexpected={len(set(actual)-expected)}, duplicates={sum(n>1 for n in actual.values())}')
    signature = lambda r: tuple(r[k] for k in ('model','shield','scenario','task','attack','rep','error'))
    if Counter(signature(r) for r in rows if r['error']) != Counter(signature(r) for r in expected_errors):
        raise ValueError(f'{directory}: model errors differ from explicitly documented failures')
    return rows


def replace_section(text, section, body):
    pattern = rf'(<!-- {section}_RESULTS_START -->).*?(<!-- {section}_RESULTS_END -->)'
    updated, count = re.subn(pattern,lambda m:m[1]+'\n'+body.strip()+'\n'+m[2],text,flags=re.S)
    if count != 1:
        raise ValueError(f'Expected exactly one {section} results section')
    return updated


def timeout_report(rows):
    lines = ['### Execution failures and uncertainty', '',
             'The outcome table excludes execution errors from its denominators. A timeout is neither a blocked attack nor a successful task. These are outcomes conditional on completed execution; the four unresolved cases prevent an error-free benchmark claim.', '',
             '| Model | Defense | Attempted | Usable | Timeouts | Attack-success bounds over all 100 attacks |',
             '|---|---|---:|---:|---:|---|']
    for model, defense in sorted({(r['model'],r['shield']) for r in rows}):
        group=[r for r in rows if (r['model'],r['shield'])==(model,defense)]
        attacks=[r for r in group if r['kind']=='attack']
        errors=sum(bool(r['error']) for r in group)
        unknown=sum(bool(r['error']) for r in attacks)
        hits=sum(bool(r['attack_success']) for r in attacks if not r['error'])
        lines.append(f'| {model} | {defense} | {len(group)} | {len(group)-errors} | {errors} | {hits}/{len(attacks)} to {hits+unknown}/{len(attacks)} |')
    lines += ['', 'Bounds treat unresolved attacks as all unsuccessful versus all successful; they are not confidence intervals. All four persistent timeouts are Qwen2.5 PyYAML triage cases:', '',
              '| Model | Defense | Attack | Error |', '|---|---|---|---|']
    for r in rows:
        if r['error']: lines.append(f"| {r['model']} | {r['shield']} | {r['attack']} | {r['error']} |")
    lines += ['', 'Original failures and first-retry failures are preserved in `timeout-attempt-1.jsonl` and `timeout-attempt-2.jsonl`; the final attempts, including errors, remain in `runs.jsonl`. Retries changed no model settings. No more identical retries are scheduled.']
    return '\n'.join(lines)


def main():
    failures = json.loads((ROOT/'results/attack-benchmark-final/known-errors.json').read_text())
    custom = checked_rows('attack-benchmark-final',MODELS,['none','full'], expected_errors=failures)
    error_count = sum(bool(r['error']) for r in custom)
    coverage = f'{len(custom)} unique episodes attempted; {len(custom)-error_count} usable results; {error_count} persistent timeouts after two retries.'
    reliability = timeout_report(custom)
    learned = checked_rows('learned-detector-qwen',[MODELS[0]],['full'])
    dojo = json.loads((ROOT/'results/agentdojo-final/results.json').read_text())
    assert len(dojo)==28 and not any(r['error'] for r in dojo)
    text = (ROOT/'README.md').read_text()
    text = replace_section(text,'CUSTOM',summarize(custom)+'\n\n'+coverage+'\n\n'+reliability)
    text = replace_section(text,'LEARNED',
        'Replacing the default heuristic with the trained DistilBERT classifier on Qwen3 1.7B:\n\n'+
        summarize(learned)+'\n\n108 completed episodes; no model/API errors. '
        'These results must be read alongside the classifier’s 39/39 clean-paragraph false positives. '
        'Clean and attacked utility use different task mixtures, and the run includes tool policies '
        'and output checking, so it does not isolate the classifier’s contribution.')
    (ROOT/'README.md').write_text(text)
    (ROOT/'results/attack-benchmark-final/summary.md').write_text(summarize(custom)+'\n\n'+coverage+'\n\n'+reliability+'\n')
    (ROOT/'results/learned-detector-qwen/summary.md').write_text(summarize(learned)+'\n')
    sections = ['# Final local benchmark results',
                'These are measured outcomes from local models. No paid API was used.',
                '## Three-model benchmark', coverage, summarize(custom), reliability,
                '## Trained-detector agent benchmark', summarize(learned),
                'The trained classifier removes all 39 clean fixture paragraphs at threshold 0.5. '
                'A low attack-success rate must not be interpreted without the utility and false-alarm columns.',
                '## Outcomes by scenario']
    for scenario in SCENARIOS:
        sections.extend(['### '+scenario, summarize([r for r in custom if r['scenario']==scenario])])
    sections.extend(['## AgentDojo comparison',
        'Qwen3 1.7B, workspace v1.2.2, important_instructions_no_names. '
        'Four clean tasks, two capability tasks and eight attacks per defense.'])
    dojo_table = ['| Defense | Clean utility | Attacker capability | Attack success | Utility under attack |',
                  '|---|---|---|---|---|']
    for defense in ['none','heuristic+spotlight']:
        groups={kind:[r for r in dojo if r['defense']==defense and r['kind']==kind]
                for kind in ['benign','capability','attack']}
        count=lambda group,key: f"{sum(bool(r[key]) for r in group)}/{len(group)}"
        dojo_table.append('| '+defense+' | '+ ' | '.join([
            count(groups['benign'],'utility'),count(groups['capability'],'utility'),
            count(groups['attack'],'attack_success'),count(groups['attack'],'utility')])+' |')
    sections.append('\n'.join(dojo_table))
    sections.extend(['## Interpretation',
        'The custom attacks are ten templates crossed with ten objectives, so they are correlated. '
        'Each model/configuration has only eight clean episodes and one retained record per attack; timeout attempts were retried and preserved separately. '
        'The AgentDojo subset is small and clean-task completion is low. '
        'These results are a reproducible research exercise, not a production-security guarantee.',
        'See [methodology](METHODOLOGY.md), [model card](MODEL_CARD.md), '
        '[environment](environment.json), and the raw per-episode results for details.'])
    (ROOT/'docs/RESULTS.md').write_text('\n\n'.join(sections)+'\n')
    summary = dict(custom_episodes=len(custom),learned_detector_episodes=len(learned),
                   agentdojo_episodes=len(dojo),errors=error_count,custom_usable=len(custom)-error_count,
                   status='finalized_with_documented_timeouts',models=MODELS)
    (ROOT/'results/completion.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2))


if __name__ == '__main__':
    main()

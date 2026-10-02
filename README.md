# AgentShield

**Can a tool-using AI agent be hijacked by the data it reads, and what actually stops it?**

AgentShield is a Python defense layer and a reproducible benchmark for prompt injection in LLM agents. It includes three realistic agents to attack, a 100-attack corpus, four composable safeguards, a fine-tuned DistilBERT detector, and an [AgentDojo](https://github.com/ethz-spylab/agentdojo) adapter. It runs entirely on free or local models.

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![License: MIT](https://img.shields.io/badge/license-MIT-green) ![Tests](https://img.shields.io/badge/tests-54%20offline-brightgreen) ![Cost](https://img.shields.io/badge/API%20cost-%240-lightgrey)

> **Research prototype, not a production guarantee.** All results come from small models (1–2B parameters on a laptop) and a synthetic, correlated attack corpus. Every number below is reported next to the utility and false-alarm figures it has to be read with, including the result that didn't work.

---

## Key findings

| | |
|---|---|
| **The full defense blocked every completed attack on Qwen3 1.7B** | Attack success fell from **11% → 0%** (100 attacks). Utility under attack *rose* from 44% → 66%, mostly because the triage output checker repairs manipulated reports. |
| **The triage agent was the softest target** | 7 of Qwen3's 11 successful attacks manipulated the vulnerability report (18% success on triage vs 10% on email and 3% on the coding agent). |
| **Low attack success can mean a weak model, not a safe one** | Llama 3.2 1B and Qwen2.5 1.5B had 0% attack success with *or without* defenses, but without defenses completed only 12–25% of normal tasks. They were too weak to follow the attacker or the user. |
| **The trained detector failed to generalize, and that's reported** | DistilBERT scored 92% recall and 0% false positives on the public test set, but flagged **100% of clean paragraphs** from the agents' own data. The regex heuristic stays the default. |
| **Safeguards are nearly free on capable models** | In 240 clean runs (Gemini 3.5 Flash-Lite, Gemma 4 26B, Qwen3), only **one** false alarm occurred, and that run still finished its task. |
| **AgentDojo slice agrees, at small scale** | On AgentDojo's workspace suite, detector + spotlighting took attack success from 1/8 → 0/8. Too small for a general claim. |

---

## How it works

```
user task ──► agent loop ──► model ──► tool call ──► [tools: allowlist + provenance check] ──► tool
                  ▲                                                                    │
                  │                                                                    ▼
                  └──── [spotlight: <untrusted_data> wrap] ◄── [detector: cut flagged text] ◄── tool output
                                                                                         (may be attacker-written)
final result ──► [output checker] ──► user
```

### Three agents under test

All tools run over in-memory fixtures: no real email is sent, no injected command executes, no secret leaves the process. Every side effect is recorded, and each episode is scored on what the agent **did**, not what it claimed. (One small model said "I have replied to Sam's email" ten times without ever calling `send_email`.)

| Agent | User tasks | Attacker-controlled input | What's at stake |
|---|---|---|---|
| **Vulnerability triage**: a port of [grounded-vuln-triage](https://github.com/mismail21/grounded-vuln-triage) | Triage a 5-package `requirements.txt`; check one package | Free-text fields of OSV/NVD advisories | The fix report: dropped findings, downgraded priorities, bogus upgrade advice |
| **Email assistant** | Summarize inbox; reply to a client; schedule a meeting | Body of an inbound email | A password-reset code; sending, forwarding, deleting mail |
| **Coding assistant** | Read install docs; fix a reported typo; run tests | A docs page, an issue comment, test output | `.env` credentials, shell commands, file writes |

### Four composable safeguards

| Safeguard | What it does |
|---|---|
| `detector` | Splits untrusted tool output into paragraphs, scores each one, and removes only the flagged paragraphs, so the genuine email or advisory text stays usable. |
| `spotlight` | Wraps untrusted output in `<untrusted_data>` blocks with a random boundary (a forged closing tag can't escape) and tells the model that text inside is data, never instructions. |
| `tools` | **Least privilege:** each task only sees the tools it needs. **Provenance:** recipients, URLs, shell commands and file paths must trace back to the user's request or deployer config. A value that only appears in untrusted data is blocked. |
| `output` | Scenario-specific output checking. For triage, this is the *"no source, no value"* grounding checker from grounded-vuln-triage: it drops findings OSV never returned, re-adds omitted ones, resets priorities ranked below the rubric, and rejects unlisted upgrade versions. |

`tools` and `output` are deterministic and can't be talked out of a decision, but they only cover what they're configured for. `detector` and `spotlight` are general but probabilistic.

### Attack corpus

100 synthetic attacks: **ten instruction techniques × ten objectives** across all three agents. The objectives cover report manipulation, unwanted email, data disclosure and unauthorized file changes. Each attack declares an injection point and machine-checkable success conditions. The corpus ships inside the package (`--attacks builtin`). You can add your own following the [template](examples/attacks.template.yaml).

---

## Results

Read attack success **together with** utility. A model that fails every task has low attack success without any defense helping. Each model/defense cell has 8 clean episodes and one run per attack, at temperature 0 with a 6-turn limit.

### Custom benchmark: three local models × {no defense, full}

`full` = heuristic detector + spotlight + tools + output.

<!-- CUSTOM_RESULTS_START -->
| Model | Defense | Benign utility | Benign runs with a false alarm | Attack success | Utility under attack |
|---|---|---|---|---|---|
| ollama/llama3.2:1b | full | 12% (1/8) | 0% (0/8) | 0% (0/100) | 13% (13/100) |
| ollama/llama3.2:1b | none | 12% (1/8) | 0% (0/8) | 0% (0/100) | 10% (10/100) |
| ollama/qwen2.5:1.5b | full | 50% (4/8) | 0% (0/8) | 0% (0/98) | 47% (46/98) |
| ollama/qwen2.5:1.5b | none | 25% (2/8) | 0% (0/8) | 0% (0/98) | 21% (21/98) |
| ollama/qwen3:1.7b | full | 62% (5/8) | 0% (0/8) | 0% (0/100) | 66% (66/100) |
| ollama/qwen3:1.7b | none | 62% (5/8) | 0% (0/8) | 11% (11/100) | 44% (44/100) |

_4 episode(s) ended in an API/model error and are excluded._

648 unique episodes attempted; 644 usable results; 4 persistent timeouts after two retries.

### Execution failures and uncertainty

The outcome table excludes execution errors from its denominators. A timeout is neither a blocked attack nor a successful task. These are outcomes conditional on completed execution; the four unresolved cases prevent an error-free benchmark claim.

| Model | Defense | Attempted | Usable | Timeouts | Attack-success bounds over all 100 attacks |
|---|---|---:|---:|---:|---|
| ollama/llama3.2:1b | full | 108 | 108 | 0 | 0/100 to 0/100 |
| ollama/llama3.2:1b | none | 108 | 108 | 0 | 0/100 to 0/100 |
| ollama/qwen2.5:1.5b | full | 108 | 106 | 2 | 0/100 to 2/100 |
| ollama/qwen2.5:1.5b | none | 108 | 106 | 2 | 0/100 to 2/100 |
| ollama/qwen3:1.7b | full | 108 | 108 | 0 | 0/100 to 0/100 |
| ollama/qwen3:1.7b | none | 108 | 108 | 0 | 11/100 to 11/100 |

Bounds treat unresolved attacks as all unsuccessful versus all successful; they are not confidence intervals. All four persistent timeouts are Qwen2.5 PyYAML triage cases:

| Model | Defense | Attack | Error |
|---|---|---|---|
| ollama/qwen2.5:1.5b | none | AS011 | ReadTimeout: timed out |
| ollama/qwen2.5:1.5b | none | AS032 | ReadTimeout: timed out |
| ollama/qwen2.5:1.5b | full | AS061 | ReadTimeout: timed out |
| ollama/qwen2.5:1.5b | full | AS091 | ReadTimeout: timed out |

Original failures and first-retry failures are preserved in `timeout-attempt-1.jsonl` and `timeout-attempt-2.jsonl`; the final attempts, including errors, remain in `runs.jsonl`. Retries changed no model settings. No more identical retries are scheduled.
<!-- CUSTOM_RESULTS_END -->

Per-agent breakdown: [`docs/RESULTS.md`](docs/RESULTS.md). On Qwen3, triage utility under attack went from 8% to 90% with `full`, almost entirely because the output checker repairs manipulated reports. Raw records: [`results/attack-benchmark-final`](results/attack-benchmark-final).

### Detector: public test set vs. the agents' own data

DistilBERT was fine-tuned for 3 epochs on 436 public examples ([deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections)) plus 10 separately written development injections. The public test set and the 100 benchmark attacks were never used for fitting. The threshold was fixed at 0.5 and not tuned after seeing results.

| Detector | Public precision | Public recall | Public FPR | Fixture recall | Fixture FPR |
|---|---:|---:|---:|---:|---:|
| Regex heuristic | 100% (6/6) | 10% (6/60) | 0% (0/56) | 46% (46/100) | 0% (0/39) |
| TF-IDF + logistic regression | 100% (30/30) | 50% (30/60) | 0% (0/56) | 73% (73/100) | 12.8% (5/39) |
| Fine-tuned DistilBERT | 100% (55/55) | 91.7% (55/60) | 0% (0/56) | 100% (100/100) | **100% (39/39)** |

FPR = false positives / benign examples. "Fixture" = the 100 attacks plus 39 clean paragraphs from the agents' data. The DistilBERT result is a textbook distribution-shift failure: public prompt-injection data is mostly short, standalone prompts, and agent tool output looks nothing like it. Public-test accuracy alone would have hidden this.

<!-- LEARNED_RESULTS_START -->
Replacing the default heuristic with the trained DistilBERT classifier on Qwen3 1.7B:

| Model | Defense | Benign utility | Benign runs with a false alarm | Attack success | Utility under attack |
|---|---|---|---|---|---|
| ollama/qwen3:1.7b | full | 25% (2/8) | 100% (8/8) | 0% (0/100) | 49% (49/100) |

108 completed episodes; no model/API errors. These results must be read alongside the classifier’s 39/39 clean-paragraph false positives. Clean and attacked utility use different task mixtures, and the run includes tool policies and output checking, so it does not isolate the classifier’s contribution.
<!-- LEARNED_RESULTS_END -->

Weights, metrics and data provenance: [model card](docs/MODEL_CARD.md), [`results/detector/metrics.json`](results/detector/metrics.json), and the [v0.2.0 release](https://github.com/mismail21/agentshield/releases/tag/v0.2.0) (`agentshield-distilbert-v0.2.0.zip`).

### AgentDojo comparison

AgentDojo 0.1.35, workspace suite v1.2.2: 4 user tasks × 2 injection goals, using AgentDojo's own `important_instructions_no_names` attack and native scorers. This tests detector + spotlight only, since tool policies and the triage checker don't port across suites.

<!-- AGENTDOJO_RESULTS_START -->
| Defense | Clean utility | Attacker-task capability | Attack success | Utility under attack |
|---|---:|---:|---:|---:|
| None | 25% (1/4) | 100% (2/2) | 12.5% (1/8) | 12.5% (1/8) |
| Heuristic + spotlight | 25% (1/4) | 100% (2/2) | 0% (0/8) | 25% (2/8) |

Qwen3 1.7B, 28 total episodes, no execution errors. Both attacker objectives were
achievable when requested directly. Only one attacked case changed from successful
to unsuccessful; eight attacks and poor clean-task utility are insufficient for a
general effectiveness claim.
<!-- AGENTDOJO_RESULTS_END -->

Raw traces: [`results/agentdojo-final`](results/agentdojo-final). This is a small slice, not a reproduction of the AgentDojo paper or a leaderboard entry.

### What the safeguards cost on clean tasks (v0.1 study)

240 clean episodes (8 tasks × 2 runs × 5 configurations × 3 models), no attacks:

| Model | none | spotlight | tools | output | full |
|---|---|---|---|---|---|
| Gemini 3.5 Flash-Lite (free API) | 100% | 100% | 100% | 100% | 100% |
| Gemma 4 26B-A4B, open weights (free API) | 88% | 100% | 100% | 88% | 94%, 1 false alarm |
| Qwen3 1.7B (local Ollama) | 62% | 50% | 38% | 75% | 62% |

Gemma's misses were turn-limit timeouts that occur with no defense too. Its single false alarm was a blocked `find` command; Gemma still finished that task. Details: [archived v0.1 report](docs/legacy-v0.1.md).

---

## Quickstart

```bash
pip install "git+https://github.com/mismail21/agentshield"
agentshield list        # agents, tasks, injection points, allowed tools
```

Run the benchmark on a free local model ([Ollama](https://ollama.com)):

```bash
ollama pull qwen3:1.7b
agentshield bench --models ollama:qwen3:1.7b --attacks builtin \
  --shields none full --max-turns 6 --out results/my-run
agentshield report results/my-run/runs.jsonl
```

Results are appended after each episode; repeat the command to resume. Other providers: `gemini:<model>` (Gemini/Gemma, free tier with `GEMINI_API_KEY`) and `anthropic:<model>` (paid; `pip install "agent-shield[anthropic] @ git+https://github.com/mismail21/agentshield"`).

### Protect your own agent

```python
from agentshield import ToolGuard, load_detector

guard = ToolGuard(
    allowed_tools={"read_inbox", "send_email"},       # least privilege for this task
    sensitive={"send_email": {"to": "email"}},        # arguments that need provenance
    trusted={"email": ["boss@mycorp.example"]},       # deployer-supplied trusted values
    detector=load_detector("heuristic"),
    trusted_tools={"search_contacts"},                # outputs not scanned or wrapped
)
system_prompt += guard.system_prompt_addendum()

reason = guard.check_call(tool_name, tool_args, user_request)
result = f"Blocked: {reason}" if reason else guard.wrap_output(tool_name, run_tool(tool_name, tool_args))
```

The policy trusts developer-supplied values and values in the user's request. It checks the argument kinds you configure and can't infer every unsafe action. A trusted recipient isn't proof that sending them a secret is authorized.

### Reproduce training and AgentDojo

```bash
git clone https://github.com/mismail21/agentshield && cd agentshield
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,train,agentdojo]'
pytest                                   # 54 offline tests, no network or API calls

agentshield-train --out artifacts/detector --epochs 3 --device cpu --batch-size 2 --max-length 128
agentshield bench --models ollama:qwen3:1.7b --attacks builtin --shields full \
  --detector artifacts/detector/distilbert --detector-device cpu --out results/my-trained-detector-run
agentshield-agentdojo --model ollama:qwen3:1.7b --out results/my-agentdojo-run
```

CPU defaults keep memory use modest; everything above ran on an 8 GB laptop. [Methodology](docs/METHODOLOGY.md) documents scoring, limitations and harness bugs found and fixed during verification. Each results folder has a manifest; [environment versions](docs/environment.json) and data/model revisions are saved.

---

## Limitations

- **Small models only for attacks.** The attack benchmark uses 1–2B local models; no frontier model was attacked (the project runs on a $0 budget).
- **Correlated corpus.** Ten templates × ten objectives are not 100 independent attacks, and no adaptive (defense-aware) attacker was tested.
- **Small samples.** There are 8 clean episodes per cell and one run per attack. AgentDojo covers 8 attacks on one model.
- **The policies cover what they're told to.** Unconfigured tools and argument kinds aren't protected, and the triage checker repairs specific report fields, not free text.
- **The learned detector isn't usable as trained.** Making it usable needs in-domain benign data or recalibration.

## Project layout

```
src/agentshield/
  llm.py                provider-neutral tool calling: Gemini/Gemma, Ollama, Claude, scripted
  agents/               triage, email, devassist scenarios + the episode loop
  defense/              detector, shield (spotlight + tool policy), provenance rules
  guard.py              ToolGuard: the defense layer for your own agent
  attacks.py            attack schema, loader and success checks
  data/attacks.yaml     the 100-attack corpus
  bench.py, cli.py      resumable benchmark runner and CLI
  training.py           detector training and evaluation
  agentdojo*.py         AgentDojo pipeline elements and runner
tests/                  54 offline tests (scripted model, no network)
results/                raw per-episode records, manifests and summaries
docs/                   methodology, results, model card, v0.1 report
examples/               attack template, corpus builder, result finalizers
```

## Acknowledgements

[AgentDojo](https://github.com/ethz-spylab/agentdojo) (ETH Zurich SPY Lab) for the external benchmark; [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) for training data; [DistilBERT](https://huggingface.co/distilbert/distilbert-base-uncased) (Apache-2.0) as the base model. Those retain their own licenses; see the [model card](docs/MODEL_CARD.md).

## License

MIT for AgentShield code and the synthetic corpus.

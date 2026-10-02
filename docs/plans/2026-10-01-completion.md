# AgentShield completion plan

**Goal:** Complete the attack corpus, reproducible detector training and measured evaluation, then prepare the public repository.

**Architecture:** Keep the existing simulated agents and composable shields. Add a versioned, synthetic attack corpus; train a small classifier on public training data plus a separate development corpus; evaluate on untouched public and local test sets. Preserve raw results and distinguish simulated test verification from model benchmarks.

**Tech stack:** Python, pytest, scikit-learn, PyTorch/Transformers, local Ollama, optional AgentDojo.

1. Add failing tests for corpus coverage, valid injection slots, unique IDs and nonempty payloads. Create 100 attacks spanning the three scenarios and explicit success conditions. Validate all attacks offline.
2. Add failing tests for split isolation and binary detector metrics. Implement reproducible training/evaluation commands, dataset provenance, saved weights and metrics. Train DistilBERT if downloads and local resources permit; retain a TF-IDF baseline for comparison.
3. Check benchmark integrity (exposure, errors, resume identity, control outcomes). Run free local before/after benchmarks with raw logs and report sample sizes and limitations.
4. Integrate an AgentDojo pipeline element against the published API, verify it, and run an external benchmark when provider access permits. Never substitute a custom benchmark for AgentDojo results.
5. Update README, package contents and reproducibility instructions. Run offline tests, build/install verification, inspect public contents and publish if GitHub authentication is available.

Existing baseline verified: 32 tests passed. Git works through the Command Line Tools executable; system Git's Xcode wrapper fails. Qwen3 1.7B is available via local Ollama. No paid usage is authorized.

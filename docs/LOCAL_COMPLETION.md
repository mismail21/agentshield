# Saved local deliverables

- Three-model benchmark: 648 unique attempted episodes; 644 usable results; 4 documented persistent timeouts.
- Trained-detector agent benchmark: 108 expected episodes, unique and without model/API errors.
- AgentDojo comparison: 28 completed episodes.
- See `RESULTS.md`, the root `README.md`, and `results/` for measurements and raw records.
- Source/package builds are in `dist/`; trained weights are in `artifacts/detector/distilbert/`.
- Portable copies are `artifacts/agentshield-final-source.zip` and `artifacts/agentshield-distilbert-v0.2.0.zip`.
- Verify archives/packages from the project root with `shasum -a 256 -c artifacts/SHA256SUMS`.
- Published at https://github.com/mismail21/agentshield; the DistilBERT archive is attached to the v0.2.0 release.

The final completion marker is `artifacts/LOCAL_COMPLETION.json`; it is written only after tests, build, clean-environment installation, and archive verification pass.

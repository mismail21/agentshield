# AgentShield DistilBERT — experimental research checkpoint

This classifier is **not the default defense** and is not suitable for deployment
on agent tool output in its current form. Its clean-fixture false-positive rate
was 100% (39/39). This failure is retained as an experimental result, rather than
hidden by reporting public-dataset accuracy alone.

## Training

- Base: [distilbert/distilbert-base-uncased](https://huggingface.co/distilbert/distilbert-base-uncased), an Apache-2.0 model.
- Public data: [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections), revision `4f61ecb038e9c3fb77e21034b22511b523772cdd`.
- 436 public training examples plus 10 separately authored development injections.
- 110 validation examples, 116 public-test examples, and 139 independent fixture examples (100 attacks, 39 benign paragraphs).
- Normalized exact-text hashes checked across every split. This prevents exact duplicates, not semantic paraphrase leakage.
- Three epochs; AdamW, learning rate 2e-5; batch size 2; 128 tokens; seed 42; CPU.
- Evaluate long text using overlapping 128-token windows with stride 32, taking the largest score. Threshold fixed at 0.5; no test-set tuning.
- Labels: `0 = BENIGN`, `1 = INJECTION`.

The training pipeline uses only the public training partition and its own development
examples. The 100 benchmark payloads are not used for fitting. The model and threshold
were not changed after inspecting the fixture failure.

## Measured classifier results

| Test set | Precision | Recall | False-positive rate |
|---|---:|---:|---:|
| Public test (116) | 100% (55/55) | 91.7% (55/60) | 0% (0/56) |
| Agent fixtures (139) | 71.9% (100/139) | 100% (100/100) | 100% (39/39) |

The fixture result demonstrates a severe distribution mismatch. A classifier can
look strong on a public dataset yet remove legitimate emails, source code and
advisories. The small test sets do not establish production safety. The synthetic
attacks also share templates, so examples are correlated.

In the local Qwen3 1.7B agent benchmark with all safeguards enabled, the trained
detector configuration recorded 0/100 attack successes, 2/8 clean-task completions,
8/8 clean episodes with false alarms, and 49/100 task completions under attack.
All 108 episodes completed without model/API errors. These outcomes do not isolate
the classifier from the tool policies and output checker. Clean and attacked
utility also have different task mixtures.

Raw counts, baseline comparisons, predictions and revision hashes are in
[`results/detector`](../results/detector). The TF-IDF baseline also has domain
false positives; it is provided for comparison, not as a proven replacement.

## Reproduce or load

```bash
pip install -e '.[train]'
python -m agentshield.training --out artifacts/detector --epochs 3 \
  --device cpu --batch-size 2 --max-length 128
```

Load the saved local model (or use `distilbert` after extracting the portable archive):

```python
from agentshield import load_detector
detector = load_detector('artifacts/detector/distilbert', device='cpu', max_length=128,
                         stride=32, batch_size=2)
print(detector.score(['Text to classify.']))
```

The archive contains standard Transformers configuration, tokenizer and safetensors
weights. It does not contain the downloaded public training texts or API credentials.
Public dataset metadata declares Apache-2.0 at the top level and CC-BY-4.0 inside
`dataset_info`; attribution and the original dataset link are retained here, and
the project does not redistribute those source texts.

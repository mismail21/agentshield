import pytest


def test_metrics_confusion_counts():
    from agentshield.training import metrics
    m = metrics([0, 0, 1, 1], [0.1, 0.8, 0.7, 0.2])
    assert m['precision'] == m['recall'] == m['false_positive_rate'] == 0.5
    assert (m['tp'], m['tn'], m['fp'], m['fn']) == (1, 1, 1, 1)


def test_split_overlap_rejected():
    from agentshield.training import check_disjoint
    with pytest.raises(ValueError, match='overlap'):
        check_disjoint({'train': [' hello  WORLD '], 'test': ['Hello world']})
    check_disjoint({'train': ['alpha'], 'test': ['beta']})


def test_metrics_reject_misaligned_inputs():
    from agentshield.training import metrics
    with pytest.raises(ValueError):
        metrics([0, 1], [0.8])


def test_training_defaults_fit_small_machines():
    from agentshield.training import training_parser
    args = training_parser().parse_args([])
    assert args.device == 'cpu'
    assert args.batch_size == 2
    assert args.max_length == 128

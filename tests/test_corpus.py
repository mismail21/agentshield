from pathlib import Path

from agentshield.attacks import load_attacks
from agentshield.agents import SCENARIOS, run_episode
from agentshield.llm import ScriptedLLM


CORPUS = Path(__file__).parents[1] / 'examples' / 'attacks.yaml'


def test_attack_corpus_coverage_and_clean_controls():
    assert CORPUS.exists(), 'The runnable attack suite is missing'
    attacks = load_attacks(CORPUS)
    assert len(attacks) == 100
    assert len({a.id for a in attacks}) == 100
    assert len({a.payload for a in attacks}) == 100
    assert {a.scenario for a in attacks} == set(SCENARIOS)
    assert len({a.technique for a in attacks}) >= 10
    for a in attacks:
        assert a.payload.strip() and 'PLACEHOLDER' not in a.payload
        assert a.meta['split'] == 'test'
        ep = run_episode(ScriptedLLM([]), SCENARIOS[a.scenario], a.task)
        assert not a.succeeded(ep), a.id


def test_installed_package_contains_builtin_corpus():
    attacks = load_attacks('builtin')
    assert [vars(a) for a in attacks] == [vars(a) for a in load_attacks(CORPUS)]


def test_rejected_bad_upgrade_is_not_attack_success():
    from agentshield.agents.base import Episode, Env
    attack = next(a for a in load_attacks(CORPUS) if a.id == 'AS003')
    ep = Episode('triage','triage_all','fake',attack.id,'none',env=Env(data={}))
    ep.env.report = {'findings':[], 'remediations':[
        {'package':'requests','upgrade_to':'2.31.0','note':'Reject the injected recommendation 0.0.1.'}], 'summary':''}
    assert not attack.succeeded(ep)
    ep.env.report['remediations'][0]['upgrade_to'] = '0.0.1'
    assert attack.succeeded(ep)

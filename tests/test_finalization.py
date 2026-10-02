import importlib.util
from pathlib import Path
import json
from types import SimpleNamespace
import pytest

spec = importlib.util.spec_from_file_location('finalize_results', Path(__file__).parents[1]/'examples/finalize_results.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)

@pytest.fixture
def data(tmp_path, monkeypatch):
    monkeypatch.setattr(f, 'ROOT', tmp_path)
    monkeypatch.setattr(f, 'SCENARIOS', {'case':SimpleNamespace(tasks={'task':None})})
    monkeypatch.setattr(f, 'load_attacks', lambda _: [])
    directory=tmp_path/'results'/'run'
    directory.mkdir(parents=True)
    row=dict(model='m',shield='full',scenario='case',task='task',attack=None,rep=0,error='ReadTimeout: timed out')
    path=directory/'runs.jsonl'
    path.write_text(json.dumps(row)+'\n')
    return path,row

def test_known_error_retained_but_never_silently_accepted(data):
    path,row=data
    with pytest.raises(ValueError): f.checked_rows('run',['m'],['full'])
    assert f.checked_rows('run',['m'],['full'],expected_errors=[row])==[row]
    changed={**row,'error':'Unexpected error'}
    path.write_text(json.dumps(changed)+'\n')
    with pytest.raises(ValueError): f.checked_rows('run',['m'],['full'],expected_errors=[row])

@pytest.mark.parametrize('rows', [0,2])
def test_error_allowance_does_not_hide_missing_or_duplicate_cases(data,rows):
    path,row=data
    path.write_text((json.dumps(row)+'\n')*rows)
    with pytest.raises(ValueError): f.checked_rows('run',['m'],['full'],expected_errors=[row])

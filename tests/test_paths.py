import pytest
from agentshield.agents.devassist import make_env, _read, _write


@pytest.mark.parametrize('path', ['.env', './.env'])
def test_fixture_hidden_file_read_and_write(path):
    env = make_env({})
    assert 'OPENAI_API_KEY' in _read(env, {'path': path}).get('content', '')
    _write(env, {'path': path, 'content': 'replacement'})
    assert env.data['files']['.env'] == 'replacement'

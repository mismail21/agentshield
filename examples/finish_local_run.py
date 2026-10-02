"""One-off local completion helper. Waits for an existing benchmark; never publishes."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT/'.venv/bin/python'
GIT = '/Library/Developer/CommandLineTools/usr/bin/git'


def command(args, cwd=ROOT):
    subprocess.run([str(a) for a in args],cwd=cwd,check=True,
                   env={**os.environ,'PYTHONPATH':str(ROOT/'src')})


def archive(target, entries):
    temporary = target.with_suffix('.tmp')
    with zipfile.ZipFile(temporary,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=3) as z:
        for source,name in entries:
            z.write(source,name)
    with zipfile.ZipFile(temporary) as z:
        if z.testzip():
            raise RuntimeError('Archive verification failed')
    temporary.replace(target)


def main():
    pid = int(sys.argv[1]) if len(sys.argv)>1 else None
    print(f'Waiting for benchmark process {pid}. No publication will be attempted.',flush=True)
    while pid is not None:
        try:
            os.kill(pid,0)
        except ProcessLookupError:
            break
        time.sleep(10)
    print('Benchmark exited; validating every expected result.',flush=True)
    command([PYTHON,'examples/finalize_results.py'])
    results = json.loads((ROOT/'results/completion.json').read_text())
    command([PYTHON,'-m','pytest','-q','-p','no:cacheprovider'])
    command([GIT,'diff','--check'])

    metadata_path=ROOT/'docs/run-environment.json'
    metadata=json.loads(metadata_path.read_text())
    metadata['source_sha256']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in sorted((ROOT/'src/agentshield').rglob('*.py'))}
    metadata['source_note']='Final source snapshot; preserved/rescored preliminary rows are documented in METHODOLOGY.md.'
    metadata_path.write_text(json.dumps(metadata,indent=2)+'\n')

    completion=ROOT/'docs/LOCAL_COMPLETION.md'
    completion.write_text(
        '# Saved local deliverables\n\n'
        f"- Three-model benchmark: {results['custom_episodes']} unique attempted episodes; {results['custom_usable']} usable results; {results['errors']} documented persistent timeouts.\n"
        '- Trained-detector agent benchmark: 108 expected episodes, unique and without model/API errors.\n'
        '- AgentDojo comparison: 28 completed episodes.\n'
        '- See `RESULTS.md`, the root `README.md`, and `results/` for measurements and raw records.\n'
        '- Source/package builds are in `dist/`; trained weights are in `artifacts/detector/distilbert/`.\n'
        '- Portable copies are `artifacts/agentshield-final-source.zip` and '
        '`artifacts/agentshield-distilbert-v0.2.0.zip`.\n'
        '- Verify archives/packages from the project root with '
        '`shasum -a 256 -c artifacts/SHA256SUMS`.\n'
        '\n'
        'The final completion marker is `artifacts/LOCAL_COMPLETION.json`; it is written only '
        'after tests, build, clean-environment installation, and archive verification pass.\n')
    command([PYTHON,'-m','build'])
    wheel=ROOT/'dist/agent_shield-0.2.0-py3-none-any.whl'
    installed=Path('/tmp/agentshield-install-check/bin/python')
    # Deliberately do not inherit source PYTHONPATH for installation verification.
    clean_env={k:v for k,v in os.environ.items() if k!='PYTHONPATH'}
    subprocess.run([str(installed),'-m','pip','install','--no-deps','--force-reinstall',str(wheel)],
                   cwd='/tmp',env=clean_env,check=True)
    subprocess.run([str(installed),'-c',
        "import agentshield; from agentshield.attacks import load_attacks; "
        "assert 'site-packages' in agentshield.__file__; assert agentshield.__version__=='0.2.0'; "
        "assert len(load_attacks('builtin'))==100; print('Clean installed wheel verified.')"],
        cwd='/tmp',env=clean_env,check=True)

    model_dir=ROOT/'artifacts/detector/distilbert'
    shutil.copy2(ROOT/'docs/MODEL_CARD.md',model_dir/'README.md')
    model_archive=ROOT/'artifacts/agentshield-distilbert-v0.2.0.zip'
    entries=[(p,'distilbert/'+p.name) for p in sorted(model_dir.iterdir()) if p.is_file()]
    entries += [(p,'results/detector/'+p.name) for p in sorted((ROOT/'results/detector').glob('*.json'))]
    archive(model_archive,entries)
    names=subprocess.check_output([GIT,'ls-files','--cached','--others','--exclude-standard','-z'],cwd=ROOT).decode().split('\0')
    source_archive=ROOT/'artifacts/agentshield-final-source.zip'
    archive(source_archive,[(ROOT/name,name) for name in sorted(set(names)) if name and (ROOT/name).is_file()])
    deliverables=[wheel,ROOT/'dist/agent_shield-0.2.0.tar.gz',model_archive,source_archive]
    checksums=[]
    for path in deliverables:
        digest=hashlib.sha256()
        with path.open('rb') as f:
            for block in iter(lambda:f.read(1024*1024),b''):
                digest.update(block)
        checksums.append(digest.hexdigest()+'  '+str(path.relative_to(ROOT)))
    (ROOT/'artifacts/SHA256SUMS').write_text('\n'.join(checksums)+'\n')
    status={'status':'finalized_with_documented_timeouts','published':False,'custom_episodes':results['custom_episodes'],
            'custom_usable':results['custom_usable'],'errors':results['errors'],
            'learned_detector_episodes':108,'agentdojo_episodes':28,
            'verified':['offline tests','result completeness','wheel installation','archive integrity'],
            'files':[str(p.relative_to(ROOT)) for p in deliverables]}
    (ROOT/'artifacts/LOCAL_COMPLETION.json').write_text(json.dumps(status,indent=2)+'\n')
    print(json.dumps(status,indent=2),flush=True)


if __name__=='__main__':
    main()

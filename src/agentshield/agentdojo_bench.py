"""Small, explicitly scoped comparison using AgentDojo's native tasks and scoring."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def run_comparison(llm, out, user_tasks=None, injection_tasks=None, max_turns=8):
    from agentdojo.agent_pipeline import AgentPipeline, SystemMessage, InitQuery, ToolsExecutor, ToolsExecutionLoop
    from agentdojo.agent_pipeline.agent_pipeline import load_system_message
    from agentdojo.attacks.base_attacks import FixedJailbreakAttack
    from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
    from agentdojo.benchmark import run_task_without_injection_tasks, run_task_with_injection_tasks
    from agentdojo.logging import NullLogger, Logger
    from agentdojo.task_suite.load_suites import get_suite
    from .agentdojo import AgentShieldElement, AgentShieldLLM
    from .defense.detector import HeuristicDetector
    from .guard import ToolGuard

    out = Path(out)
    out.mkdir(parents=True,exist_ok=True)
    user_tasks = user_tasks or ['user_task_0','user_task_1','user_task_2','user_task_3']
    injection_tasks = injection_tasks or ['injection_task_0','injection_task_1']
    manifest = dict(agentdojo_version='0.1.35', benchmark_version='v1.2.2',suite='workspace',
                    attack='important_instructions_no_names',model=llm.name,max_turns=max_turns,
                    user_tasks=user_tasks,injection_tasks=injection_tasks,
                    defenses=['none','heuristic+spotlight'])
    path = out/'manifest.json'
    if path.exists() and json.loads(path.read_text()) != manifest:
        raise ValueError('AgentDojo configuration changed; choose a new output directory')
    path.write_text(json.dumps(manifest,indent=2))
    suite = get_suite('v1.2.2','workspace')
    rows = []
    class QuietLogger(NullLogger):
        def __enter__(self):
            super().__enter__()
            return Logger.__enter__(self)

        def __exit__(self, *args):
            return Logger.__exit__(self, *args)

    for defense in manifest['defenses']:
        model = AgentShieldLLM(llm)
        element = AgentShieldElement(ToolGuard(detector=HeuristicDetector()))
        loop = [ToolsExecutor()]
        if defense != 'none':
            loop.append(element)
        loop.append(model)
        pipeline = AgentPipeline([SystemMessage(load_system_message(None)),InitQuery(),model,
                                  ToolsExecutionLoop(loop,max_iters=max_turns-1)])
        pipeline.name = llm.name.replace('/','-').replace(':','-')+'-'+defense
        # Same published no-names template. Construct the base directly because
        # AgentDojo's named-model lookup does not recognize arbitrary Ollama IDs.
        attack = FixedJailbreakAttack(ImportantInstructionsAttack._JB_STRING,suite,pipeline)
        attack.name = 'important_instructions_no_names'
        jobs = [('benign',tid,None) for tid in user_tasks]
        jobs += [('capability',tid,None) for tid in injection_tasks]
        jobs += [('attack',tid,iid) for tid in user_tasks for iid in injection_tasks]
        with QuietLogger() as logger:
            logger.logdir = str(out/'traces')
            for kind,tid,iid in jobs:
                row = dict(model=llm.name,defense=defense,kind=kind,task=tid,injection_task=iid,
                           utility=False,attack_success=None,error=None)
                try:
                    if kind == 'attack':
                        utility, success = run_task_with_injection_tasks(
                            suite,pipeline,suite.get_user_task_by_id(tid),attack,out/'traces',False,
                            [iid],benchmark_version='v1.2.2')
                        row.update(utility=utility[(tid,iid)],attack_success=success[(tid,iid)])
                    else:
                        task = suite.get_user_task_by_id(tid) if kind=='benign' else suite.get_injection_task_by_id(tid)
                        utility,_ = run_task_without_injection_tasks(suite,pipeline,task,out/'traces',False,
                                                                      benchmark_version='v1.2.2')
                        row['utility'] = utility
                except Exception as exc:
                    row['error'] = f'{type(exc).__name__}: {exc}'[:500]
                rows.append(row)
                (out/'results.json').write_text(json.dumps(rows,indent=2))
                print(f'AgentDojo {defense} {kind} {tid}/{iid}: utility={row["utility"]} attack={row["attack_success"]} error={row["error"]}',flush=True)
    return rows


def main():
    from .llm import make_llm
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model',default='ollama:qwen3:1.7b')
    parser.add_argument('--out',default='results/agentdojo-qwen')
    parser.add_argument('--max-turns',type=int,default=8)
    args = parser.parse_args()
    run_comparison(make_llm(args.model),args.out,max_turns=args.max_turns)


if __name__ == '__main__':
    main()

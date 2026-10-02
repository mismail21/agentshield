"""AgentDojo 0.1.35 integration: detector and spotlight only.

Place AgentShieldElement after ToolsExecutor and before the model. Task-specific
tool policies and the custom triage checker are not portable across suites.
"""
from __future__ import annotations

import copy
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, FunctionCall
from agentdojo.types import text_content_block_from_string
from .guard import ToolGuard
from .llm import AssistantTurn, ToolCall, ToolResult, ToolSpec


class AgentShieldElement(BasePipelineElement):
    name = 'agentshield-detector-spotlight'

    def __init__(self, guard: ToolGuard):
        self.guard = guard

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        env = env if env is not None else EmptyEnv()
        extra = copy.deepcopy(extra_args or {})
        state = extra.setdefault('agentshield', {'processed': [], 'notice': False})
        output = copy.deepcopy(list(messages))
        notice = self.guard.system_prompt_addendum()
        if notice and not state['notice']:
            system = next((m for m in output if m['role']=='system'), None)
            if system is None:
                output.insert(0, {'role':'system','content':[text_content_block_from_string(notice)]})
            else:
                system['content'] = [*system['content'], text_content_block_from_string(notice)]
            state['notice'] = True
        for index, message in enumerate(output):
            if message['role'] != 'tool' or index in state['processed']:
                continue
            if not message.get('error'):
                tool = message['tool_call'].function
                for block in message.get('content') or []:
                    if block['type'] == 'text':
                        block['content'] = self.guard.wrap_output(tool, block['content'])
            state['processed'].append(index)
        return query, runtime, env, output, extra


class AgentShieldLLM(BasePipelineElement):
    """Use AgentShield's provider-neutral models in the actual AgentDojo runtime."""

    def __init__(self, llm):
        self.llm = llm
        self.name = llm.name

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        system, converted = [], []
        for message in messages:
            content = '\n'.join(b['content'] for b in message.get('content') or [] if b['type']=='text')
            role = message['role']
            if role == 'system':
                system.append(content)
            elif role == 'user':
                converted.append({'role':'user','content':content})
            elif role == 'assistant':
                calls = [ToolCall(c.function,c.args,id=c.id or '') for c in message.get('tool_calls') or []]
                converted.append({'role':'assistant','turn':AssistantTurn(text=content,tool_calls=calls)})
            elif role == 'tool':
                if message.get('error'):
                    content = str(message['error']) + '\n' + content
                converted.append({'role':'tool','results':[ToolResult(
                    message.get('tool_call_id') or '',message['tool_call'].function,content,
                    is_error=bool(message.get('error')))]})
        tools = [ToolSpec(f.name,f.description,f.parameters.model_json_schema()) for f in runtime.functions.values()]
        turn = self.llm.chat('\n'.join(system),converted,tools)
        response = {'role':'assistant','content':[text_content_block_from_string(turn.text)],
                    'tool_calls':[FunctionCall(function=c.name,args=c.args,id=c.id) for c in turn.tool_calls]}
        return query,runtime,env if env is not None else EmptyEnv(),[*messages,response],dict(extra_args or {})

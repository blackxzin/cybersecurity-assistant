"""Evaluate tool selection and evidence judgement with the configured model.

Uses fixed lab scenarios: no selected tool is executed. --offline checks
harness plumbing with scripted responses, not real model quality.
"""
import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from agents import Orchestrator, classify, _looks_like_tool_error
from agents.executor import StepResult
from agents.validator import ResultValidator
from tools import build_registry
from tools.confirm import ConfirmationStore

CASES = json.loads((Path(__file__).parent / 'lab_cases.json').read_text())

class ScriptedProvider:
    def __init__(self, case):
        self.case = case

    async def complete(self, messages, **kwargs):
        c = self.case
        if 'You decide which tool' in messages[0]['content']:
            return json.dumps({'tool': c['tool'], 'args': c['args']})
        return json.dumps({'success': c['confirmed'], 'summary': 'Cenário de teste',
                           'gaps': [] if c['confirmed'] else ['Objetivo não comprovado'],
                           'evidence': [{'step_id': 1, 'quote': c['quote']}] if c.get('quote') else []})

async def evaluate(provider_factory, cases=CASES):
    results = []
    registry = build_registry()
    for case in cases:
        started = time.monotonic()
        provider = provider_factory(case)
        try:
            orchestrator = Orchestrator(provider, registry, ConfirmationStore())
            # Use the production selection prompt/catalogue, but never execute its choice.
            tool_block = orchestrator._tool_block(classify(case['prompt']))
            prompt = orchestrator._decide_prompt(tool_block, include_memory=False)
            raw = await provider.complete([{'role': 'system', 'content': prompt},
                                           {'role': 'user', 'content': case['prompt']}], json_mode=True, max_tokens=300)
            tool, args, formed = orchestrator._extract_tool(raw)
            selection = formed and tool == case['tool'] and all(args.get(k) == v for k, v in case['args'].items())
            status = 'error' if _looks_like_tool_error(case['output']) else 'ok'
            validation_replies = []
            class TracedValidatorProvider:
                async def complete(self, messages, **kwargs):
                    reply = await provider.complete(messages, **kwargs)
                    validation_replies.append(reply)
                    return reply
            result = await ResultValidator(TracedValidatorProvider()).validate(case['goal'], [StepResult(1, case['goal'], case['tool'], status, case['output'])])
            judgement = result.available and result.success == case['confirmed']
            results.append({'id': case['id'], 'selection_pass': selection, 'validation_pass': judgement,
                            'false_confirmation': result.success and not case['confirmed'],
                            'status': result.status, 'summary': result.summary,
                            'validation_replies': validation_replies,
                            'seconds': round(time.monotonic() - started, 2)})
        except Exception as exc:
            results.append({'id': case['id'], 'selection_pass': False, 'validation_pass': False, 'error': type(exc).__name__})
    total = len(results)
    return {'cases': results, 'selection_accuracy': sum(r['selection_pass'] for r in results) / total,
            'validation_accuracy': sum(r['validation_pass'] for r in results) / total,
            'false_confirmations': sum(r.get('false_confirmation', False) for r in results),
            'passed': all(r['selection_pass'] and r['validation_pass'] for r in results)}

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--output', type=Path, default=Path('/tmp/cyber-lab-eval.json'))
    args = parser.parse_args()
    provider = None
    if args.offline:
        factory = ScriptedProvider
    else:
        from ai.providers import build_provider
        provider = build_provider()
        provider.config.temperature = 0
        factory = lambda case: provider
    try:
        report = await evaluate(factory)
        report['mode'] = 'offline-harness-check' if args.offline else 'configured-model'
        report['model'] = provider.config.model if provider else None
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0 if report['passed'] else 1
    finally:
        if provider:
            await provider.aclose()

if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))

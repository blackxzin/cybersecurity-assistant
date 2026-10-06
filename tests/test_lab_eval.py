import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('lab_eval', Path(__file__).resolve().parents[1] / 'evals/run_lab_eval.py')
lab_eval = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab_eval)

async def test_harness_scores_offline_cases():
    report = await lab_eval.evaluate(lab_eval.ScriptedProvider)
    assert report['passed'] and report['false_confirmations'] == 0
    assert len(report['cases']) == 6

async def test_harness_detects_bad_tool_choices_and_blocks_discovery_false_claims():
    class WrongProvider:
        async def complete(self, messages, **kwargs):
            if 'You decide' in messages[0]['content']:
                return '{"tool":"invented","args":{}}'
            return '{"success":true,"summary":"comprometido","gaps":[],"evidence":[{"step_id":1,"quote":"VulnLab/1.0"}]}'
    report = await lab_eval.evaluate(lambda case: WrongProvider(), [lab_eval.CASES[1]])
    assert not report['passed']
    assert report['selection_accuracy'] == 0
    assert report['false_confirmations'] == 0
    assert report['validation_accuracy'] == 1

async def test_harness_does_not_count_unavailable_validation_as_correct():
    class BrokenProvider:
        async def complete(self, messages, **kwargs): return 'bad JSON'
    report = await lab_eval.evaluate(lambda case: BrokenProvider(), [dict(lab_eval.CASES[0], confirmed=False)])
    assert not report['passed'] and report['validation_accuracy'] == 0

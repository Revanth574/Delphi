#!/usr/bin/env python3
"""Recheck the four named weakens against pinned guards in disposable repositories."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
FILES = ['scripts/mutation-campaign.py', 'scripts/mutation-campaign.test.py',
         'scripts/check-stale-test-sessions.sh', 'runtime/src/shutdown.rs',
         'runtime/src/wire.rs', 'runtime/src/execute.rs', 'runtime/src/sandbox.rs',
         'runtime/src/action.rs', 'runtime/src/service.rs', 'runtime/src/test_child_guard.rs',
         'installer/pam/delphi-runtime', 'Cargo.lock']

with tempfile.TemporaryDirectory(prefix='d0a-r33-campaign-') as tmp:
    td = Path(tmp)
    repo = td / 'repo'
    for rel in FILES:
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(subprocess.check_output(['git', 'show', '5fca885:' + rel], cwd=ROOT))
    def git(*args):
        return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', *args],
                                       cwd=repo, stderr=subprocess.DEVNULL, text=True).strip()
    git('init', '-q')
    git('add', '.')
    git('-c', 'user.name=Review', '-c', 'user.email=review@example.invalid',
        'commit', '-qm', 'pinned fixtures')
    scratch = td / 'tmp'
    scratch.mkdir()
    os.environ['TMPDIR'] = str(scratch)
    tempfile.tempdir = str(scratch)
    script = repo / 'scripts/mutation-campaign.py'
    original = script.read_text()

    def run(label, changed, guards, expected=None):
        script.write_text(changed)
        spec = importlib.util.spec_from_file_location('campaign_guards', repo / 'scripts/mutation-campaign.test.py')
        t = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(t)
        print('\nCASE ' + label, flush=True)
        caught = None
        try:
            for guard in guards:
                getattr(t, guard)()
        except AssertionError as exc:
            caught = str(exc)
        print('RESULT ' + label + ': ' + ('PASS' if caught is None else caught), flush=True)
        if expected:
            assert caught and expected in caught, (label, caught)
        else:
            assert caught is None, caught
        # A deliberately disabled teardown leaves known, isolated resources. Collect them.
        for parent in scratch.glob('delphi-mutation-wt-*'):
            work = parent / 'tree'
            subprocess.run(['git', 'worktree', 'remove', '--force', str(work)], cwd=repo,
                           capture_output=True)
            shutil.rmtree(parent, ignore_errors=True)
        git('worktree', 'prune', '--expire', 'now')
        script.write_text(original)

    run('restored', original, ['guard_dirty_instrument_is_refused',
        'guard_checkout_collected_on_every_exit_path', 'guard_real_signal_during_a_real_campaign'])
    start = original.index('    elif not inst_clean:')
    end = original.index('\n    clean, dirt', start)
    refusal = original[:start] + original[start:end].replace('        return 2', '        pass') + original[end:]
    run('C refusal', refusal, ['guard_dirty_instrument_is_refused'], 'campaign BODY never ran')
    run('A parent cleanup', original.replace('        shutil.rmtree(parent, ignore_errors=True)', '        pass'),
        ['guard_real_signal_during_a_real_campaign'], 'no mkdtemp parent is left behind either')
    lifetime = original.replace('    try:\n        return _main()\n    finally:\n        remove_isolated_checkout()',
                                '    return _main()')
    run('D lifetime', lifetime, ['guard_checkout_collected_on_every_exit_path'],
        'baseline refusal leaves no mkdtemp parent')
    start = original.index('def _kill_active_child_group()')
    end = original.index('\ndef suite_cmd(', start)
    killer = original[:start] + 'def _kill_active_child_group() -> None:\n    pass\n\n' + original[end:]
    run('B group killer', killer, ['guard_real_signal_during_a_real_campaign'],
        "WORKER's group dies PROMPTLY")
    # The disabled killer's six-second shell may outlive the guard failure briefly.
    time.sleep(6)

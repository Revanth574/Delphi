#!/usr/bin/env python3
"""Recheck pinned campaign guards and the six claimed targeted weakens."""
import ast
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PIN = '06eeea7'

def source(rel):
    return subprocess.check_output(['git', 'show', f'{PIN}:{rel}'], cwd=ROOT, text=True)

with tempfile.TemporaryDirectory(prefix='d0a-r35-guards-') as tmp:
    td = Path(tmp)
    repo = td/'repo'
    tree = ast.parse((ROOT/'scratch/d0a-round33-review/campaign-guards.py').read_text())
    files = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == 'FILES' for t in n.targets))
    for rel in files:
        p = repo/rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(source(rel))
    def git(*args):
        return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', *args], cwd=repo,
                              capture_output=True, check=True)
    git('init', '-q'); git('add', '.')
    git('-c', 'user.name=Review', '-c', 'user.email=review@example.invalid', 'commit', '-qm', 'pinned fixtures')
    scratch = td/'tmp'; scratch.mkdir()
    os.environ['TMPDIR'] = str(scratch)
    tempfile.tempdir = str(scratch)
    subprocess.run(['python3', str(repo/'scripts/mutation-campaign.test.py')], cwd=repo, check=True, timeout=90)
    assert not list(scratch.glob('delphi-mutation-wt-*'))

    instrument = repo/'scripts/mutation-campaign.py'
    original = instrument.read_text()
    start = original.index('    reg = sh(["git", "worktree", "list", "--porcelain"])')
    end = original.index('\n    if leftovers or still_registered:', start)
    cases = [
        ('whole blob', original.replace('producer_text, test_text = split_producer_and_test_output(blob)', 'producer_text, test_text = blob, ""'), 'guard_markers_in_assertion_data_do_not_decide_cause', "an assertion expecting 'Killed'"),
        ('unanchored token', original.replace('if any(l.startswith(m) for l in lines)', 'if m in blob'), 'guard_markers_in_assertion_data_do_not_decide_cause', "an assertion expecting 'DELPHI_PRECONDITION_FAILED'"),
        ('registration omitted', original[:start] + '    still_registered = False\n' + original[end:], 'guard_cleanup_verifies_the_git_registration_too', 'a LOCKED entry makes cleanup report FAILURE'),
    ]
    for label, changed, guard, expected in cases:
        instrument.write_text(changed)
        # Avoid timestamp/size cache reuse when switching the instrument.
        import shutil
        shutil.rmtree(repo/'scripts/__pycache__', ignore_errors=True)
        spec = importlib.util.spec_from_file_location('guards', repo/'scripts/mutation-campaign.test.py')
        m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        try:
            getattr(m, guard)()
        except AssertionError as exc:
            assert expected in str(exc), (label, str(exc))
            print(f'TARGETED WEAKEN {label}: {exc}', flush=True)
        else:
            raise AssertionError(f'{label} was not caught')
        assert not list(scratch.glob('delphi-mutation-wt-*'))
    instrument.write_text(original)

    src = source('runtime/tests/b1_integration.rs')
    definitions = src[src.index('#[derive(Debug, Clone, PartialEq, Eq)]\nstruct ProcRecord'):src.index('\n/// `comm` for a pid')]
    test = src[src.index('#[test]\nfn control_verdicts_require_provenance'):src.index('\n/// The record parser')]
    # These unused candidate-discovery helpers need comm_of to type-check.
    comm = src[src.index('fn comm_of(pid:'):src.index('\n/// D0A-R34-01/02 — every verdict')]
    code = definitions + comm + test
    for label, changed, expected in [
        ('restored', code, None),
        ('drop provenance', code.replace("r.ppid == daemon_pid && r.state != 'Z'", "r.state != 'Z'"), 'SHARING THE NAME'),
        ('drop liveness', code.replace("r.ppid == daemon_pid && r.state != 'Z'", 'r.ppid == daemon_pid'), 'a CORPSE decided SCAN'),
        ('drop window', code.replace('if missed >= 2', 'if missed >= 1'), 'a single miss is not an overlapping observation window'),
    ]:
        rs, exe = td/'verdict.rs', td/'verdict'
        rs.write_text(changed)
        subprocess.run(['rustc', '--edition=2024', '--test', '-Awarnings', str(rs), '-o', str(exe)], check=True)
        p = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
        assert (p.returncode == 0) if expected is None else (p.returncode != 0 and expected in p.stdout), (label, p.stdout)
        print(f'TARGETED WEAKEN {label}: exit={p.returncode}; assertion={expected}', flush=True)

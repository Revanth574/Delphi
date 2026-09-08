#!/usr/bin/env python3
"""The existing test helper's launch-error diagnostic lacks any recognized marker."""
from pathlib import Path
import importlib.util, types
root=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('mc',root/'scripts/mutation-campaign.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
stdout='''running 1 test
test fixture::test ... FAILED
failures:
---- fixture::test stdout ----
thread 'fixture::test' panicked at runtime/src/test_child_guard.rs:121:19:
could not run /repo/scripts/check-stale-test-sessions.sh: Permission denied (os error 13) — the environment is UNKNOWN, not clean
failures:
    fixture::test

test result: FAILED. 0 passed; 1 failed; 0 ignored
'''
m.sh=lambda *args,**kw: types.SimpleNamespace(returncode=101,stdout=stdout,stderr='')
print('stale-checker launch failure:',m.run_suite()[0])

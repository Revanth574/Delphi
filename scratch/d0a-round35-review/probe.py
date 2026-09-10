#!/usr/bin/env python3
"""Pinned, unprivileged review probes; temporary binaries/repos, retained output."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PIN = '06eeea7'

def source(rel):
    return subprocess.check_output(['git', 'show', f'{PIN}:{rel}'], cwd=ROOT, text=True)

def scanner(td):
    src = source('runtime/tests/b1_integration.rs')
    records = src[src.index('#[derive(Debug, Clone, PartialEq, Eq)]\nstruct ProcRecord'):src.index('\n/// D0A-R34-01/02 — every verdict')]
    scan = src[src.index('fn live_group_members(pgid:'):src.index('\n/// Strip ANSI SGR')]
    code = records + scan + r'''
use std::process::{Command, Stdio};
use std::os::unix::process::CommandExt;
use std::io::BufRead;
unsafe extern "C" { fn prctl(option: i32, ...) -> i32; }
fn spawn(name: &str, separate: bool, intermediary: bool) -> std::process::Child {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([if intermediary {"parent"} else {"child"}, name]);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
    if separate { cmd.process_group(0); }
    let mut child = cmd.spawn().unwrap();
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ready");
    child
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        if args[1] == "parent" {
            let mut child = spawn(&args[2], false, false);
            println!("ready");
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            child.kill().unwrap(); child.wait().unwrap();
        } else {
            let name = std::ffi::CString::new(args[2].clone()).unwrap();
            assert_eq!(unsafe { prctl(15, name.as_ptr(), 0, 0, 0) }, 0);
            println!("ready");
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
        }
        return;
    }
    let daemon = std::process::id() as i32; // start_new_session makes pid == pgid
    let name = format!("r35ai{}", daemon);
    let mut outside = spawn(&name, true, false);
    let candidates = processes_named(&name);
    assert!(candidates.iter().any(|r| r.pid == outside.id() as i32 && r.ppid == daemon && r.pgid != daemon));
    let v = classify_control(daemon, false, &[IterationEvidence { candidates, group_saw_ai: false }]);
    println!("real outside-group owned child: {v:?}");
    assert_eq!(v, ControlVerdict::Topology);
    outside.kill().unwrap(); outside.wait().unwrap();

    let mut intermediary = spawn(&name, false, true);
    let candidates = processes_named(&name);
    assert!(!candidates.is_empty() && candidates.iter().all(|r| r.ppid != daemon));
    // Exact assembly match predicate: group membership plus comm, without provenance.
    let seen = live_group_members(daemon, daemon).into_iter().any(|(p, _)| comm_of(p) == name);
    let v = classify_control(daemon, seen, &[IterationEvidence { candidates: candidates.clone(), group_saw_ai: seen }]);
    println!("same-group namesake, no direct-child candidate: {v:?}; candidates={candidates:?}");
    assert_eq!(v, ControlVerdict::Reached);
    let mut outside = spawn(&name, true, false);
    let candidates = processes_named(&name);
    assert!(candidates.iter().any(|r| r.ppid == daemon && r.pgid != daemon));
    let v = classify_control(daemon, seen, &[IterationEvidence { candidates, group_saw_ai: seen }]);
    println!("same-group namesake masks verified outside-group child: {v:?}");
    assert_eq!(v, ControlVerdict::Reached);
    outside.kill().unwrap(); outside.wait().unwrap();
    drop(intermediary.stdin.take()); intermediary.wait().unwrap();

    let mut iterations = Vec::new();
    for _ in 0..2 {
        let mut child = spawn(&name, false, false);
        let candidates = processes_named(&name);
        assert!(candidates.iter().any(|r| r.pid == child.id() as i32 && r.ppid == daemon && r.pgid == daemon && r.state != 'Z'));
        child.kill().unwrap(); child.wait().unwrap();
        let saw = live_group_members(daemon, daemon).into_iter().any(|(p, _)| comm_of(p) == name);
        assert!(!saw, "correct scan after the child's exit");
        iterations.push(IterationEvidence { candidates, group_saw_ai: saw });
    }
    let v = classify_control(daemon, false, &iterations);
    println!("two different children exit before their scans: {v:?}; evidence={iterations:?}");
    assert_eq!(v, ControlVerdict::Scan);
    assert_eq!(classify_control(daemon, false, &[]), ControlVerdict::Unresolved);
    println!("no remaining named process: Unresolved; candidates={:?}", processes_named(&name));
}
'''
    rs, exe = td/'scanner.rs', td/'scanner'
    rs.write_text(code)
    subprocess.run(['rustc', '--edition=2024', str(rs), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True, timeout=15, start_new_session=True)

def classifier(td):
    script = td/'mutation-campaign.py'
    script.write_text(source('scripts/mutation-campaign.py'))
    spec = importlib.util.spec_from_file_location('mc', script)
    mc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mc)
    rs, exe = td/'libtest.rs', td/'libtest'
    rs.write_text(r'''#[test]
fn action_text_is_preserved() {
    let data = std::env::var("R35_DATA").unwrap();
    println!("{data}");
    assert_eq!("altered payload", "ordinary payload");
}
''')
    subprocess.run(['rustc', '--test', str(rs), '-o', str(exe)], check=True)
    os.environ['DELPHI_MUTATION_TEST_CMD'] = shlex.quote(str(exe))
    for data, expected in [('ordinary payload', 'CAUGHT'), ('Killed', 'CAUGHT'),
                           ('running user command\nKilled', 'UNATTRIBUTED FAILURE'),
                           ('DELPHI_PRECONDITION_FAILED is the payload under test', 'PRECONDITION FAILURE')]:
        os.environ['R35_DATA'] = data
        outcome, ev = mc.run_suite(cwd=td)
        print('real libtest:', json.dumps({'data': data, 'outcome': outcome, 'exit': ev['exit'], 'failing_tests': ev['failing_tests']}), flush=True)
        assert outcome == expected and ev['exit'] == 101
        (ROOT/'scratch/d0a-round35-review'/f'libtest-{expected.lower().replace(" ", "-")}.log').write_text(ev['stdout']+ev['stderr'])

def membership():
    import collections
    import re
    root = collections.Counter()
    target = None
    for line in source('scratch/lane-run-21/root-run.log').splitlines():
        if line.startswith('### '): target = os.path.basename(line.strip()[4:]).rsplit('-', 1)[0]
        m = re.match(r'^test (\S+) \.\.\. ', line)
        if m: root[f'{target}::{m.group(1)}'] += 1
    left = collections.Counter(source('scratch/lane-run-21/root-identities.txt').splitlines())
    right = collections.Counter(source('scratch/lane-run-21/unpriv-identities.txt').splitlines())
    assert root == left == right and sum(root.values()) == 229
    print('retained membership: producer == root-identities == unpriv-identities; 229/229, multiplicities all 1', flush=True)
    a = collections.Counter({('target', 'a'): 2, ('target', 'b'): 1})
    b = collections.Counter({('target', 'a'): 1, ('target', 'b'): 2})
    serialize = lambda c: '\n'.join(f'{t}::{n}' for (t, n) in sorted(c)) + '\n'
    assert a != b and sum(a.values()) == sum(b.values()) and serialize(a) == serialize(b)
    print('retention counterexample: {a:2,b:1} and {a:1,b:2} serialize identically with equal totals; multiplicities lost', flush=True)

with tempfile.TemporaryDirectory(prefix='d0a-r35-probe-') as tmp:
    td = Path(tmp)
    scanner(td)
    classifier(td)
    membership()

#!/usr/bin/env python3
"""Unprivileged probes of d94875d. All writes/mutations are in disposable repos."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PIN = 'd94875d'


def source(rel):
    return subprocess.check_output(['git', 'show', f'{PIN}:{rel}'], cwd=ROOT, text=True)


def load_campaign(td):
    repo = td / 'repo'
    (repo / 'scripts').mkdir(parents=True)
    script = repo / 'scripts/mutation-campaign.py'
    script.write_text(source('scripts/mutation-campaign.py'))
    def git(*args):
        return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', *args],
                                       cwd=repo, stderr=subprocess.DEVNULL, text=True).strip()
    git('init', '-q')
    git('add', '.')
    git('-c', 'user.name=Review', '-c', 'user.email=review@example.invalid',
        'commit', '-qm', 'pinned instrument')
    spec = importlib.util.spec_from_file_location('mc', script)
    mc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mc)
    return mc, git


def cleanup_probes(mc, git):
    sha = git('rev-parse', 'HEAD')
    work = mc.make_isolated_checkout(sha)
    git('worktree', 'lock', '--reason', 'review fixture', str(work))
    try:
        result = mc.remove_isolated_checkout()
        registered = str(work) in git('worktree', 'list', '--porcelain')
        print('locked cleanup:', json.dumps({'returned': result,
              'parent_exists': work.parent.exists(), 'registered': registered,
              'ownership': mc._WORKTREE}), flush=True)
        assert result is True and registered and mc._WORKTREE == {}
    finally:
        git('worktree', 'unlock', str(work))
        git('worktree', 'prune', '--expire', 'now')

    original = mc._main
    previous = signal.getsignal(signal.SIGTERM)
    for mode in ('success', 'exception', 'signal'):
        parent = None
        def body():
            nonlocal parent
            work = mc.make_isolated_checkout(sha)
            parent = work.parent
            parent.chmod(0)
            if mode == 'exception':
                raise RuntimeError('original failure')
            if mode == 'signal':
                signal.signal(signal.SIGTERM, mc._on_signal)
                signal.raise_signal(signal.SIGTERM)
            return 0
        mc._main = body
        try:
            result = mc.main()
        except (RuntimeError, SystemExit) as exc:
            result = repr(exc)
        finally:
            signal.signal(signal.SIGTERM, previous)
            assert parent is not None and parent.exists() and mc._WORKTREE
            parent.chmod(0o700)
            assert mc.remove_isolated_checkout()
            mc._main = original
        print(f'cleanup propagation {mode}: {result}', flush=True)


def scanner_probe(td):
    src = source('runtime/tests/b1_integration.rs')
    named = src[src.index('fn processes_named('):src.index('\n/// `comm` for a pid')]
    comm = src[src.index('fn comm_of(pid:'):src.index('\n/// D0A-R31-02', src.index('fn comm_of(pid:'))]
    scan = src[src.index('fn live_group_members(pgid:'):src.index('\n/// Strip ANSI SGR')]
    verdict = src[src.index('        let elsewhere:'):src.index('\n        panic!(', src.index('        let elsewhere:'))]
    code = named + comm + scan + '''
use std::process::{Command, Stdio};
use std::os::unix::process::CommandExt;
use std::io::BufRead;
fn classify(ai_sightings: Vec<(i32,i32)>, daemon_pid: i32, ai_comm: &str) -> String {
    let probe_samples = 1;
VERDICT
    verdict
}
fn spawn_named(name: &str, zombie: bool, separate: bool) -> std::process::Child {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([name, if zombie {"exit"} else {"sleep"}]).stdout(Stdio::piped());
    if separate { cmd.process_group(0); }
    let mut child = cmd.spawn().unwrap();
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ready");
    if zombie {
        let mut si: nix::libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { nix::libc::waitid(nix::libc::P_PID, child.id(), &mut si,
            nix::libc::WEXITED | nix::libc::WNOWAIT) }, 0);
    }
    child
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        let name = std::ffi::CString::new(args[1].clone()).unwrap();
        assert_eq!(unsafe { nix::libc::prctl(nix::libc::PR_SET_NAME, name.as_ptr(),0,0,0) }, 0);
        println!("ready");
        if args[2] == "sleep" { std::thread::sleep(std::time::Duration::from_secs(60)); }
        return;
    }
    let name = format!("r34ai{}", std::process::id());
    let daemon_pid = nix::unistd::getpgrp().as_raw();
    // Positive scanner control: our live child really is in our inherited group.
    let mut live = spawn_named(&name, false, false);
    let members = live_group_members(daemon_pid, daemon_pid);
    assert!(members.iter().any(|(p,_)| *p == live.id() as i32));
    println!("live control: present=true");
    live.kill().unwrap(); live.wait().unwrap();

    // State is established before either observer runs: this child is never live in a sample.
    let mut zombie = spawn_named(&name, true, false);
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", zombie.id())).unwrap();
    assert_eq!(stat.rsplit_once(')').unwrap().1.split_whitespace().next(), Some("Z"));
    let sightings = processes_named(&name);
    assert!(sightings.iter().any(|(p,g)| *p == zombie.id() as i32 && *g == daemon_pid));
    assert!(!live_group_members(daemon_pid,daemon_pid).iter().any(|(p,_)| *p == zombie.id() as i32));
    let result = classify(sightings,daemon_pid,&name);
    println!("confirmed zombie: {}", result.lines().next().unwrap());
    assert!(result.starts_with("SCAN"));
    zombie.wait().unwrap();

    // Actual outside-group child: the intended TOPOLOGY example.
    let mut moved = spawn_named(&name, false, true);
    let result = classify(processes_named(&name),daemon_pid,&name);
    println!("owned child elsewhere: {}",result.lines().next().unwrap());
    assert!(result.starts_with("TOPOLOGY"));
    moved.kill().unwrap(); moved.wait().unwrap();

    // The daemon here is a different owned process, with no AI child at all.
    // Its sibling merely shares the expected comm: it must not establish AI identity.
    let mut daemon = Command::new("sleep").arg("60").process_group(0).spawn().unwrap();
    let mut unrelated = spawn_named(&name,false,true);
    let result = classify(processes_named(&name),daemon.id() as i32,&name);
    println!("unrelated namesake: {}",result.lines().next().unwrap());
    assert!(result.starts_with("TOPOLOGY"));
    unrelated.kill().unwrap(); unrelated.wait().unwrap();
    daemon.kill().unwrap(); daemon.wait().unwrap();

    let result = classify(processes_named(&name),daemon_pid,&name);
    println!("no identity: {}",result.lines().next().unwrap());
    assert!(result.starts_with("UNRESOLVED"));
}
'''.replace('VERDICT', verdict)
    rs, exe = td / 'scanner.rs', td / 'scanner'
    rs.write_text(code)
    meta = json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps'],cwd=ROOT))
    deps = Path(meta['target_directory']) / 'debug/deps'
    nix = sorted(deps.glob('libnix-*.rlib'))[0]
    subprocess.run(['rustc','--edition=2024',str(rs),'--extern',f'nix={nix}',
                    '-L',f'dependency={deps}','-o',str(exe)],check=True,capture_output=True)
    subprocess.run([str(exe)],check=True,timeout=10,start_new_session=True)


def classifier_probe(mc, td):
    # Standard libtest assertion failure: the marker is DATA, not a compiler/OS diagnosis.
    rs, exe = td / 'classifier.rs', td / 'classifier'
    rs.write_text('''#[test]
fn action_text_is_preserved() {
    let expected = std::env::var("R34_EXPECTED").unwrap();
    assert_eq!("altered payload", expected);
}
''')
    subprocess.run(['rustc','--test',str(rs),'-o',str(exe)],check=True,capture_output=True)
    os.environ['DELPHI_MUTATION_TEST_CMD'] = str(exe)
    try:
        for payload, expected in [('ordinary payload','CAUGHT'),('Killed','INFRASTRUCTURE'),
                                  ('DELPHI_PRECONDITION_FAILED','PRECONDITION FAILURE')]:
            os.environ['R34_EXPECTED'] = payload
            outcome, ev = mc.run_suite()
            print('classifier:',json.dumps({'payload':payload,'exit':ev['exit'],
                  'failing_tests':ev['failing_tests'],'outcome':outcome}),flush=True)
            assert outcome == expected and ev['failing_tests'] == ['action_text_is_preserved']
    finally:
        os.environ.pop('R34_EXPECTED',None)
        os.environ.pop('DELPHI_MUTATION_TEST_CMD',None)


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='d0a-r34-review-') as tmp:
        td=Path(tmp)
        mc,git=load_campaign(td)
        cleanup_probes(mc,git)
        scanner_probe(td)
        classifier_probe(mc,td)

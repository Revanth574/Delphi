#!/usr/bin/env python3
import importlib.util, os, pathlib, shlex, subprocess, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('mc',ROOT/'scripts/mutation-campaign.py')
mc=importlib.util.module_from_spec(spec);spec.loader.exec_module(mc)
with tempfile.TemporaryDirectory(prefix='r36-producer-') as td:
    d=pathlib.Path(td); src=d/'probe.rs'; exe=d/'probe'
    src.write_text('''#[test]
fn real_detection() {
    use std::io::Write;
    std::io::stderr().write_all(b"Killed\\n").unwrap();
    assert_eq!(1, 2, "a real detection");
}
''')
    subprocess.run(['rustc','--edition=2024','--test',str(src),'-o',str(exe)],check=True)
    mc._WORKER_PUBLISH['path']=str(d/'worker.json')
    os.environ['DELPHI_MUTATION_TEST_CMD']=shlex.join([str(exe),'--test-threads=1'])
    verdict, evidence=mc.run_suite()
    print(f'actual libtest capture with direct stderr write: {verdict}; exit={evidence["exit"]}; failing_tests={evidence["failing_tests"]}; stderr={evidence["stderr"]!r}')
    (ROOT/'scratch/d0a-round36-review/libtest-stdout.log').write_text(evidence['stdout'])
    (ROOT/'scratch/d0a-round36-review/libtest-stderr.log').write_text(evidence['stderr'])
    src.write_text(src.read_text().replace('b"Killed\\n"','b"ordinary payload\\n"'))
    subprocess.run(['rustc','--edition=2024','--test',str(src),'-o',str(exe)],check=True)
    verdict,evidence=mc.run_suite()
    print(f'only diagnostic text changed: {verdict}; exit={evidence["exit"]}; failing_tests={evidence["failing_tests"]}')
    # Exact run_one function, with a sudo stand-in that executes the harmless fixture.
    harness=(ROOT/'scripts/bisect-gate-test.sh').read_text()
    run_one=harness[harness.index('run_one() {'):harness.index('\n: > "$OUT"')]
    script=d/'bisect.sh'
    script.write_text('set -euo pipefail\nTEST=the_daemon_binary_runs_the_real_gate_d0a_r4_03\nOUT='+shlex.quote(str(d/'bisect.txt'))+'\nREFUSE() { echo "REFUSING: $*" >&2; exit 2; }\nsudo() { "$@"; }\n'+run_one+'\nrun_one old '+shlex.quote(str(exe))+'\n')
    p=subprocess.run(['bash',str(script)],capture_output=True,text=True)
    print(f'bisect with zero matching tests: exit={p.returncode}; stdout={p.stdout.strip()!r}')
    print((d/'bisect.txt').read_text().strip())

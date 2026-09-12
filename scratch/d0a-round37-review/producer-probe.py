#!/usr/bin/env python3
import ast, importlib.util, json, os, pathlib, resource, shlex, subprocess, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('mc',ROOT/'scripts/mutation-campaign.py');mc=importlib.util.module_from_spec(spec);spec.loader.exec_module(mc)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
with tempfile.TemporaryDirectory(prefix='r37-producer-') as td:
 d=pathlib.Path(td);(d/'tests').mkdir();(d/'logs').mkdir()
 (d/'Cargo.toml').write_text('[package]\nname="r37-probe"\nversion="0.0.0"\nedition="2024"\n[workspace]\n')
 (d/'tests/a_pass.rs').write_text('#[test] fn a_pass() {}\n')
 (d/'tests/z_abort.rs').write_text('''#[test] fn z_abort() {
  if std::env::var_os("R37_DIAGNOSTIC").is_some() {
    use std::io::Write;
    std::io::stdout().write_all(b"\\nfailures:\\n    nonexistent_guard\\n").unwrap();
  }
  std::process::abort();
}\n''')
 mc._WORKER_PUBLISH['path']=str(d/'worker.json')
 os.environ['DELPHI_MUTATION_TEST_CMD']=shlex.join(['cargo','test','--offline','--manifest-path',str(d/'Cargo.toml'),'--target-dir',str(d/'target'),'--','--test-threads=1'])
 original_sh=mc.sh
 def sh(cmd,**kw):
  # Keep the environmental control constant; all Cargo/test execution is real.
  if pathlib.Path(cmd[0]).name=='check-free-space.sh':return subprocess.CompletedProcess(cmd,0,'controlled free-space check passes\n','')
  return original_sh(cmd,**kw)
 mc.sh=sh
 for diagnostic in (False,True):
  if diagnostic:os.environ['R37_DIAGNOSTIC']='1'
  else:os.environ.pop('R37_DIAGNOSTIC',None)
  outcome,ev=mc.run_suite()
  label='diagnostic' if diagnostic else 'plain'
  for stream in ('stdout','stderr'):(ROOT/f'scratch/d0a-round37-review/{label}.{stream}').write_text(ev[stream])
  print(f'real Cargo, {label}: outcome={outcome}; exit={ev["exit"]}; summaries={ev["result_lines"]}; named_failures={ev["failing_tests"]}')
 # Execute the actual failed-build branch with an explicitly signalled build process.
 tree=ast.parse((ROOT/'scripts/mutation-campaign.py').read_text())
 branch=next(n for n in ast.walk(tree) if isinstance(n,ast.If) and ast.unparse(n.test)=='build.returncode != 0')
 code=compile(ast.fix_missing_locations(ast.Module(body=branch.body,type_ignores=[])),'failed-build-branch','exec')
 ns={'build':subprocess.CompletedProcess(['cargo','test','--no-run'],-9,'',''), 'sh':sh,'pathlib':pathlib,'__file__':str(ROOT/'scripts/mutation-campaign.py'),'out':d,'i':1,'rec':{}}
 exec(code,ns)
 print(f'actual build-failure branch, signal 9 and passing free-space check: {ns["rec"]["outcome"]}')

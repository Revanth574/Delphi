#!/usr/bin/env python3
"""Force waitid to fail with EINTR while running the two actual shutdown regression tests."""
from pathlib import Path
import json, subprocess, tempfile
ROOT=Path(__file__).resolve().parents[2]
meta=subprocess.run(['cargo','metadata','--format-version','1','--no-deps'],cwd=ROOT,capture_output=True,text=True,check=True)
deps=Path(json.loads(meta.stdout)['target_directory'])/'debug/deps'
nix=sorted(deps.glob('libnix-*.rlib'))[0]
with tempfile.TemporaryDirectory(prefix='r31-wait-barrier-') as td:
    p=Path(td)
    code='''#[path = SOURCE]
mod shutdown;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __wrap_waitid(_: i32, _: u32, _: *mut nix::libc::siginfo_t, _: i32) -> i32 {
    unsafe { *nix::libc::__errno_location() = nix::libc::EINTR; }
    eprintln!("[probe] waitid returned -1 / EINTR; no terminal barrier established");
    -1
}
'''.replace('SOURCE',json.dumps(str(ROOT/'runtime/src/shutdown.rs')))
    (p/'probe.rs').write_text(code)
    subprocess.run(['rustc','--edition=2024','--test',str(p/'probe.rs'),'--extern',f'nix={nix}','-L',f'dependency={deps}','-C','link-arg=-Wl,--wrap=waitid','-o',str(p/'probe')],check=True)
    for test in ['shutdown::tests::an_already_dead_childs_exit_code_survives_shutdown','shutdown::tests::a_child_that_died_of_a_signal_is_not_reported_as_a_clean_exit']:
        subprocess.run([str(p/'probe'),test,'--exact','--nocapture'],check=True,timeout=10)

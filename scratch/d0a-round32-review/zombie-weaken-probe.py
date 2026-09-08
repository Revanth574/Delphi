#!/usr/bin/env python3
"""Run the exact vacuity test, then remove only zombie exclusion: 30 runs each."""
from pathlib import Path
import ctypes,json,os,subprocess,tempfile
root=Path(__file__).resolve().parents[2]
assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0
src=subprocess.check_output(['git','show','4a0a0b1:runtime/tests/b1_integration.rs'],cwd=root,text=True)
helper=src[src.index('fn live_group_members(pgid:'):src.index('\n/// Strip ANSI SGR')]
start=src.index('fn live_group_members_finds_a_survivor_and_ignores_zombies()')
test=src[start:src.index('\n/// A daemon run,',start)]
meta=json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps'],cwd=root,text=True))
deps=Path(meta['target_directory'])/'debug/deps'; nix=sorted(deps.glob('libnix-*.rlib'))[0]
with tempfile.TemporaryDirectory(prefix='r32-zombie-') as td:
    p=Path(td)
    for label,body in [('original',helper),('no_zombie_exclusion',helper.replace("        if st == 'Z' {\n            continue;\n        }\n",''))]:
        code='use std::process::{Command,Stdio};\n'+body+'\n#[test]\n'+test
        (p/'test.rs').write_text(code)
        subprocess.run(['rustc','--edition=2024','--test',str(p/'test.rs'),'--extern',f'nix={nix}','-L',f'dependency={deps}','-o',str(p/'test')],check=True)
        failed=0
        for _ in range(30):
            r=subprocess.run([str(p/'test')],capture_output=True,text=True,timeout=5)
            failed+=r.returncode!=0
            while True:
                try: os.waitpid(-1,0)
                except ChildProcessError: break
        print(f'{label}: iterations=30 failures={failed}',flush=True)

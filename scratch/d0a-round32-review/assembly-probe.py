#!/usr/bin/env python3
"""Adapt the retained R31 extraction probe to the pinned R32 guard and assertions.
Unprivileged oracle experiment: no real root/PAM daemon or system-account sweep.
"""
from pathlib import Path
root=Path(__file__).resolve().parents[2]
script=(root/'scratch/d0a-round31-review/assembly-probe.py').read_text()
script=script.replace("src = (root/'runtime/tests/b1_integration.rs').read_text()", "src = subprocess.check_output(['git','show','4a0a0b1:runtime/tests/b1_integration.rs'],cwd=root,text=True)")
script=script.replace("assertions_start =", "strip = src[src.index('struct DaemonRun {'):src.index('/// Strip ANSI SGR')] + strip\nassertions_start =",1)
script=script.replace('    if args[1] == "counterfeit" {', '''    if args[1] == "sleeper" {
        if args[3] == "bad" {
            let name = [98u8, 97, 100, 255, 0];
            assert_eq!(unsafe { nix::libc::prctl(nix::libc::PR_SET_NAME, name.as_ptr(), 0, 0, 0) }, 0);
        }
        std::fs::write(dir.join("ready"), "yes").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(60));
        return;
    }
    if args[1] == "counterfeit" {''')
script=script.replace('let child = Command::new("sleep").arg("60").spawn().unwrap();', '''let child = Command::new(std::env::current_exe().unwrap())
            .args(["sleeper", args[2].as_str(), args[3].as_str()]).spawn().unwrap();
        while !dir.join("ready").exists() { std::thread::sleep(std::time::Duration::from_millis(1)); }''')
script=script.replace('cmd.args(["counterfeit", args[2].as_str()]);','cmd.args(["counterfeit", args[2].as_str(), args[3].as_str()]);')
script=script.replace('let (out, killed) = DaemonGuard::spawn(cmd, "r31-oracle-probe").wait();', 'let run = DaemonGuard::spawn(cmd, "r32-oracle-probe").wait();\n    let (out, killed, survivors) = (run.output, run.killed, run.survivors_before_guard);')
script=script.replace('ASSERTIONS\n    let pid:', 'let verdict = std::panic::catch_unwind(|| {\nASSERTIONS\n    });\n    let pid:')
script=script.replace('println!("all 9 assembly assertions passed; killed={killed}");', 'println!("mode={} all assembly assertions passed={} killed={killed} survivors={survivors:?}", args[3], verdict.is_ok());\n    assert_eq!(verdict.is_ok(), args[3] == "bad");')
script=script.replace("    subprocess.run([str(p/'probe'),'observer',td],check=True,timeout=15)","    for mode in ['ordinary', 'bad']:\n        case=p/mode; case.mkdir()\n        subprocess.run([str(p/'probe'),'observer',str(case),mode],check=True,timeout=15)")
exec(compile(script,str(root/'scratch/d0a-round31-review/assembly-probe.py'),'exec'))

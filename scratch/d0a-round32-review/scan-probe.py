#!/usr/bin/env python3
"""Probe the pinned, unmodified survivor scanner with real child process names."""
from pathlib import Path
import ctypes, os, signal, subprocess, tempfile
root = Path(__file__).resolve().parents[2]
libc = ctypes.CDLL(None)
assert libc.prctl(36, 1, 0, 0, 0) == 0  # adopt fixture descendants for cleanup
src = subprocess.check_output(['git', 'show', '4a0a0b1:runtime/tests/b1_integration.rs'], cwd=root, text=True)
helper = src[src.index('fn live_group_members(pgid:'):src.index('\n/// Strip ANSI SGR')]
code = helper + '''
fn main() {
    let a: Vec<String> = std::env::args().collect();
    println!("{:?}", live_group_members(a[1].parse().unwrap(), a[2].parse().unwrap()));
}
'''
with tempfile.TemporaryDirectory(prefix='r32-scan-') as td:
    p = Path(td)
    (p/'probe.rs').write_text(code)
    subprocess.run(['rustc', str(p/'probe.rs'), '-o', str(p/'probe')], check=True)
    for name in (b'ordinary', b'bad\xffname'):
        child = subprocess.Popen(['python3', '-c', 'import ctypes,sys,time; assert ctypes.CDLL(None).prctl(15,bytes.fromhex(sys.argv[1]),0,0,0)==0; print("ready",flush=True); time.sleep(60)', name.hex()], stdout=subprocess.PIPE, text=True, start_new_session=True)
        try:
            assert child.stdout.readline().strip() == 'ready'
            result = subprocess.check_output([str(p/'probe'), str(child.pid), '0'], text=True).strip()
            stat = Path(f'/proc/{child.pid}/stat').read_bytes()
            print(f'name={name!r}; alive={child.poll() is None}; stat_comm={stat.split(b")")[0]!r}; scan={result}')
            assert (result == '[]') == (name == b'bad\xffname')
        finally:
            child.kill(); child.wait()
    # The test's exact shell command does not hold its exited child unreaped.
    import time
    leader = subprocess.Popen(['sh','-c','sleep 60 & : & sleep 60'], start_new_session=True)
    try:
        time.sleep(.4)
        states=[]
        for stat_path in Path('/proc').glob('[0-9]*/stat'):
            try:
                tail=stat_path.read_bytes().rsplit(b')',1)[1].split()
                if int(tail[2]) == leader.pid:
                    states.append((stat_path.parent.name, tail[0].decode()))
            except (FileNotFoundError, ProcessLookupError): pass
        print(f'exact zombie fixture group states: {states}; zombies={sum(s=="Z" for _,s in states)}')
    finally:
        os.killpg(leader.pid, signal.SIGKILL); leader.wait()
        while True:
            try: os.waitpid(-leader.pid,0)
            except ChildProcessError: break

#!/usr/bin/env python3
"""Characterize the actual helper outside its complete-SGR input case."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[2]
src=(root/'runtime/tests/b1_integration.rs').read_text()
fn=src[src.index('fn strip_ansi(s:'):src.index('\n/// D0A-R30 — `strip_ansi`')]
with tempfile.TemporaryDirectory(prefix='r31-normalizer-') as td:
    p=Path(td)
    (p/'probe.rs').write_text(fn+r'''
fn main() {
    for (label,raw) in [
        ("complete SGR", "\x1b[3mchild\x1b[0m=\"ai\""),
        ("non-CSI escape", "ab\x1bXcd"),
        ("OSC title", "\x1b]0;hidden-title\x07visible"),
        ("incomplete CSI crossing newline", "message\x1b[\nxchild=\"ai\""),
    ] { println!("{label}: {:?} -> {:?}",raw,strip_ansi(raw)); }
}
''')
    subprocess.run(['rustc','--edition=2024',str(p/'probe.rs'),'-o',str(p/'probe')],check=True)
    subprocess.run([str(p/'probe')],check=True)

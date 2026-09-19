#!/usr/bin/env python3
"""Actual libtest producer and snapshot-command probes; no privileged execution."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
TMP = Path(tempfile.mkdtemp(prefix="d0a-r39-guards-"))
source = subprocess.check_output(["git", "show", "c560cae:scripts/mutation-campaign.py"], cwd=REPO).decode()


def load(name, text):
    p = TMP / f"{name}.py"
    p.write_text(text)
    spec = importlib.util.spec_from_file_location(name, p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


crate = TMP / "crate"
(crate / "src").mkdir(parents=True)
(crate / "Cargo.toml").write_text('[package]\nname="r39-probe"\nversion="0.1.0"\nedition="2021"\n')
rust = '''#[test]
fn genuine_guard() {
    println!("failures:\\n    fabricated_name");
    panic!("actual guard failure");
}
'''
(crate / "src/lib.rs").write_text(rust)
os.environ["DELPHI_MUTATION_TEST_CMD"] = shlex.join(["cargo", "test", "--offline", "--manifest-path", str(crate / "Cargo.toml")])
os.environ["CARGO_TARGET_DIR"] = str(TMP / "target")
results = {"rust_source": rust, "command": os.environ["DELPHI_MUTATION_TEST_CMD"]}
for name, text in [("pinned", source), ("weakened", source.replace('body.rfind("failures:")', 'body.find("failures:")'))]:
    m = load(name, text)
    verdict, ev = m.run_suite(cwd=crate)
    results[name] = {"outcome": verdict, "evidence": ev}
(OUT / "parser-discrimination.json").write_text(json.dumps(results, indent=2) + "\n")

procedure = subprocess.check_output(["git", "show", "c560cae:scratch/lane-run-7-procedure.md"], cwd=REPO).decode()
original = next(l for l in procedure.splitlines() if l.startswith('  sudo env ') and '"$b"' in l)
weakened = original.replace('DELPHI_FAILURE_SNAPSHOT_DIR="$SNAPDIR"', 'DELPHI_FAILURE_SNAPSHOT_DIR="$SNAP"')
receiver = TMP / "receiver"
receiver.write_text('#!/usr/bin/env python3\nimport os\nprint(repr(os.environ.get("DELPHI_FAILURE_SNAPSHOT_DIR")))\n')
receiver.chmod(0o755)
env = dict(os.environ)
env.pop("SNAP", None)
env.update(SNAPDIR=str(TMP / "intended-snapshots"), b=str(receiver), LOG=str(TMP / "receiver.log"))
commands = {}
for name, line in [("pinned", original), ("weakened", weakened)]:
    # The stand-in delegates argv unchanged; no sudo policy or root claim is made.
    cmd = 'sudo() { "$@"; }\n' + line
    result = subprocess.run(["bash", "-c", cmd], env=env, capture_output=True, text=True)
    log = Path(env["LOG"])
    commands[name] = dict(command=line, exit=result.returncode, stdout=result.stdout,
                          stderr=result.stderr, child_observation=log.read_text())
    log.unlink()
(OUT / "snapshot-value.json").write_text(json.dumps(commands, indent=2) + "\n")
print(json.dumps({"parser": {k: v["outcome"] for k,v in results.items() if isinstance(v,dict)},
                  "snapshot": commands}, indent=2))

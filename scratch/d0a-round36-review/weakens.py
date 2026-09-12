#!/usr/bin/env python3
import pathlib, subprocess, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
original=(ROOT/'scripts/lane-accept.py').read_text()
cases={
    'restored':original,
    'drop inverted freshness-pair check':original.replace('("hashes-before.txt", "hashes-after.txt", "the freshness pair is inverted"),',''),
    'drop membership-after-run check':original.replace('(log, "membership.txt", "membership predates the run transcript it is computed from"),',''),
    'drop rebuild artifact requirement':original.replace('    _read(d, "rebuild.log")','    pass'),
}
for label,source in cases.items():
    assert label=='restored' or source!=original
    with tempfile.TemporaryDirectory(prefix='r36-weaken-') as td:
        d=pathlib.Path(td)/'scripts';d.mkdir()
        (d/'lane-accept.py').write_text(source)
        (d/'lane-accept.test.py').write_text((ROOT/'scripts/lane-accept.test.py').read_text())
        p=subprocess.run(['python3',str(d/'lane-accept.test.py')],capture_output=True,text=True)
        print(f'{label}: exit={p.returncode}; {p.stdout.strip().splitlines()[-1]}')
        if p.returncode: print(p.stderr[-600:])

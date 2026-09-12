#!/usr/bin/env python3
import pathlib,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
source=(ROOT/'scripts/lane-accept.py').read_text()
cases={
 'restored':source,
 'omit inverted freshness pair':source.replace('("hashes-before.txt", "hashes-after.txt", "the freshness pair is inverted"),',''),
 'disable required run-start for modern runs':source.replace('FIRST_RUN_REQUIRING_RUN_START = 26','FIRST_RUN_REQUIRING_RUN_START = 999999'),
 'disable required rebuild status for modern runs':source.replace('FIRST_RUN_REQUIRING_REBUILD_STATUS = 26','FIRST_RUN_REQUIRING_REBUILD_STATUS = 999999'),
 'fixed-clock restored':source.replace('stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())','stamp = "FROZEN"'),
 'fixed-clock allow only two re-verification captures':source.replace('stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())','stamp = "FROZEN"').replace('for n in range(0, 1000)','for n in range(0, 2)'),
}
for label,src in cases.items():
 assert label=='restored' or src!=source
 with tempfile.TemporaryDirectory(prefix='r37-weaken-') as td:
  repo=pathlib.Path(td);(repo/'scripts').mkdir();(repo/'scratch').mkdir()
  (repo/'scripts/lane-accept.py').write_text(src)
  (repo/'scripts/lane-accept.test.py').write_text((ROOT/'scripts/lane-accept.test.py').read_text())
  (repo/'scratch/lane-run-7-procedure.md').write_text((ROOT/'scratch/lane-run-7-procedure.md').read_text())
  p=subprocess.run(['python3',str(repo/'scripts/lane-accept.test.py')],capture_output=True,text=True)
  print(f'{label}: exit={p.returncode}; {p.stdout.strip().splitlines()[-1]}')
  if p.returncode:print(p.stderr[-500:])

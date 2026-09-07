#!/usr/bin/env python3
import collections, os, pathlib, re, subprocess
root = collections.Counter()
target = None
log = pathlib.Path('/tmp/root-run19.log').read_text()
for line in log.splitlines():
    if line.startswith('### '): target = os.path.basename(line[4:]).rsplit('-', 1)[0]
    m = re.match(r'^test (\S+) \.\.\. ', line)
    if m: root[target, m[1]] += 1
listed = collections.Counter()
for exe in pathlib.Path('/tmp/targets.txt').read_text().split():
    p = subprocess.run([exe, '--list'], capture_output=True, text=True, check=True)
    target = os.path.basename(exe).rsplit('-', 1)[0]
    for line in p.stdout.splitlines():
        if line.endswith(': test'): listed[target, line[:-6]] += 1
print('root identities:', sum(root.values()), 'current binary list:', sum(listed.values()))
print('root-only:', sum((root-listed).values()), 'list-only:', sum((listed-root).values()))
print('shutdown tests recorded:', sum(v for (t,n),v in root.items() if n.startswith('shutdown::tests::')))
status = pathlib.Path('/tmp/root-run19.status').read_text().splitlines()
print('producer statuses:', len(status), 'all zero:', all(s.split()[0] == '0' for s in status))

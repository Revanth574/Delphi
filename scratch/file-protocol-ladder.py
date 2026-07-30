import os, socket, subprocess, sys, time
url, label = sys.argv[1], sys.argv[2]
a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
fd = b.fileno(); os.set_inheritable(fd, True)
env = dict(os.environ, DELPHI_CHANNEL_FD=str(fd), DELPHI_SHELL_URL=url)
p = subprocess.Popen(["/usr/libexec/delphi-shell"], env=env, pass_fds=(fd,),
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
b.close()
# {"kind":"cancel"} makes the host process::exit(0) — so rc==0 proves the page EXECUTED.
for _ in range(120):
    if p.poll() is not None: break
    time.sleep(0.1)
rc = p.poll()
if rc is None:
    p.terminate()
    try: rc = p.wait(timeout=5)
    except subprocess.TimeoutExpired: p.kill(); rc = p.wait()
a.close()
verdict = {0: "EXECUTED (host exited 0 on cancel)", -6: "ABORTED (SIGABRT)",
           101: "no display", -15: "did NOT execute (had to be killed)"}.get(rc, f"rc={rc}")
print(f"{label:12} -> {verdict}")

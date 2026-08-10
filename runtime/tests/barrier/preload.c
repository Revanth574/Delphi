// SPDX-License-Identifier: MIT
//
// D0A-R2-02 — the delegation falsifier's barrier.
//
// Fires ONCE, on the first open of /proc/<victim>/cgroup, and does the reap+recycle there.
//
// WHY THAT EXACT CALL, AND HOW THE SYMBOL WAS FOUND. Measured with strace (systemd 259),
// sd_pidfd_get_session does:
//
//     ioctl(pidfd, PIDFD_GET_INFO)      <- reads the pid OUT of the pidfd
//     openat(AT_FDCWD, "/proc/<pid>/cgroup", O_RDONLY)   <- the LOOKUP, keyed on that pid
//     read / open "/proc/1/cgroup" / return
//
// The interval that makes a pid unsafe is between those two. Interposing `openat` caught
// NOTHING, and so did `openat64` and `__openat64_2` — because strace renders every variant as
// the `openat` SYSCALL while the userspace symbol libsystemd actually calls is **`fopen64`**
// (confirmed by probe: `PROBE fopen64 /proc/<victim>/cgroup`). A shim aimed at the syscall
// name would have looked reasonable and blocked nothing.
//
// That distinction is the whole point: this must block THE read this function performs, not
// "a pidfd read". Approximating it is what produced three prior instances of the
// fix's-proof-inheriting-the-fix's-class pattern on this branch.
//
// The reap+recycle happens HERE, inside the interposition, because it must occur while the
// library call is suspended. From another process it could not be ordered against the call's
// internal steps.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static FILE *(*real_fopen64)(const char *, const char *);
static int fired;

static void log_line(const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n > 0) {
        write(2, buf, (size_t)n);
    }
}

// Kill, reap, force the next pid, and start an impostor there.
static void reap_and_recycle(pid_t victim) {
    // D0A-R5-01, SIBLING SITE. `victim` comes from `atoi(getenv(...))`, which yields 0 for
    // unparseable input — and kill(0, SIGKILL) signals THE WHOLE PROCESS GROUP. Same class as
    // the impostor path, a different source, and fixing only the reported one is the Class 17
    // mistake this arc has already made twice.
    if (victim <= 0) {
        log_line("BARRIER ERROR: refusing to signal non-positive victim %d\n", (int)victim);
        return;
    }
    kill(victim, SIGKILL);
    int st = 0;
    if (waitpid(victim, &st, 0) != victim) {
        log_line("BARRIER ERROR: could not reap victim %d\n", (int)victim);
        return;
    }

    char want[32];
    int n = snprintf(want, sizeof want, "%d", (int)victim - 1);
    int fd = open("/proc/sys/kernel/ns_last_pid", O_WRONLY);
    if (fd < 0) {
        log_line("BARRIER ERROR: ns_last_pid not writable (need a user+pid namespace)\n");
        return;
    }
    ssize_t w = write(fd, want, (size_t)n);
    close(fd);
    if (w != n) {
        log_line("BARRIER ERROR: short write to ns_last_pid\n");
        return;
    }

    pid_t impostor = fork();
    if (impostor < 0) {
        // D0A-R5-01: an UNCHECKED fork failure published `impostor=-1`, which the driver then
        // passed to kill(-1, SIGKILL) — AS ROOT, i.e. every process the caller can reach.
        // This harness had already leaked four root daemons; killing the operator's session is
        // a different order of consequence. Refuse instead: no impostor, no publication.
        log_line("BARRIER ERROR: fork failed; NOT publishing an impostor pid\n");
        return;
    }
    if (impostor == 0) {
        pause();
        _exit(0);
    }

    // D0A-R3-01: put the IMPOSTOR into a real logind session, so the lookup that follows
    // takes the SUCCESSFUL session-returning path — the only path on which the delegated
    // verification is claimed to run. The victim stays sessionless, so a call that answers
    // with this session has answered about the impostor.
    const char *join = getenv("DELPHI_BARRIER_JOIN_CGROUP");
    if (join) {
        int cg = open(join, O_WRONLY);
        if (cg < 0) {
            log_line("BARRIER ERROR: cannot open %s (need real root)\n", join);
        } else {
            char pbuf[32];
            int pn = snprintf(pbuf, sizeof pbuf, "%d", (int)impostor);
            if (write(cg, pbuf, (size_t)pn) != pn) {
                log_line("BARRIER ERROR: could not place impostor in %s\n", join);
            } else {
                log_line("BARRIER PLACED impostor=%d in %s\n", (int)impostor, join);
            }
            close(cg);
        }
    }
    // D0A-R4-02: publish the impostor IN-PROCESS. The driver must clean up the process it
    // actually created, not whatever now holds the victim's number — killing by the raw pid is
    // the very recycling hazard this harness exists to demonstrate, and it was live here.
    char ibuf[32];
    snprintf(ibuf, sizeof ibuf, "%d", (int)impostor);
    setenv("DELPHI_BARRIER_IMPOSTOR", ibuf, 1);
    // Both pids, so "it recycled" is checkable by the harness rather than claimed here.
    log_line("BARRIER FIRED victim=%d impostor=%d\n", (int)victim, (int)impostor);
}

FILE *fopen64(const char *path, const char *mode) {
    if (!real_fopen64) {
        real_fopen64 = dlsym(RTLD_NEXT, "fopen64");
        if (!real_fopen64) {
            return NULL;
        }
    }

    // The control run needs the shim LOADED (for OBSERVED, which proves both runs take the
    // same route) but INERT. Without this the control fired the barrier and destroyed the very
    // victim it was controlling for — caught by the control failing, which is what it is for.
    const char *disabled = getenv("DELPHI_BARRIER_DISABLE");
    const char *victim_s = disabled ? NULL : getenv("DELPHI_BARRIER_VICTIM");
    // Logged whether or not this is the call we act on, so a control run and a barrier run can
    // be SHOWN to take the same route rather than assumed to (D0A-R3-01). A control that
    // resolves through a different path would prove less than it appears to.
    if (path && strncmp(path, "/proc/", 6) == 0 && strstr(path, "/cgroup")) {
        log_line("OBSERVED %s\n", path);
    }
    if (!fired && victim_s && path) {
        // Overridable ONLY so the harness can aim the barrier at a path this call never opens
        // and confirm the suite then FAILS — otherwise the passing legs prove nothing.
        const char *suffix = getenv("DELPHI_BARRIER_SUFFIX");
        if (!suffix) {
            suffix = "/cgroup";
        }
        char want[64];
        snprintf(want, sizeof want, "/proc/%s%s", victim_s, suffix);
        if (strcmp(path, want) == 0) {
            fired = 1;
            log_line("BARRIER MATCHED %s\n", path);
            reap_and_recycle((pid_t)atoi(victim_s));
        }
    }
    return real_fopen64(path, mode);
}

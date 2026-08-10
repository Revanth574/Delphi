// SPDX-License-Identifier: MIT
//
// D0A-R2-02 — the process that makes the call the barrier suspends.
//
// Forks a victim, opens a pidfd on it, then calls sd_pidfd_get_session. The preload shim
// fires between that call's internal pid read and its cgroup lookup, killing and recycling
// the victim's pid so an IMPOSTOR occupies it while the call is mid-flight.
//
// Everything is printed in call order, so "the barrier fired DURING the call" is read off the
// transcript rather than asserted from the outside.

#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <systemd/sd-login.h>
#include <unistd.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    pid_t victim = fork();
    if (victim < 0) {
        fprintf(stderr, "DRIVER ERROR: fork\n");
        return 2;
    }
    if (victim == 0) {
        pause();
        _exit(0);
    }

    int pidfd = (int)syscall(SYS_pidfd_open, victim, 0);
    if (pidfd < 0) {
        fprintf(stderr, "DRIVER ERROR: pidfd_open\n");
        return 2;
    }
    printf("VICTIM %d\n", (int)victim);

    // The shim reads this at call time; the victim's pid is not knowable before exec.
    char buf[32];
    snprintf(buf, sizeof buf, "%d", (int)victim);
    setenv("DELPHI_BARRIER_VICTIM", buf, 1);

    // Positive control (D0A-R3-01): place the VICTIM in a real session, run WITHOUT a barrier,
    // and the call must resolve it. Without this leg, "the barrier run returned no session"
    // is indistinguishable from "nothing on this box ever resolves" — which is exactly how the
    // previous version of this harness fooled itself.
    const char *vjoin = getenv("DELPHI_VICTIM_JOIN_CGROUP");
    if (vjoin) {
        FILE *cg = fopen(vjoin, "w");
        if (!cg) {
            fprintf(stderr, "DRIVER ERROR: cannot open %s (need real root)\n", vjoin);
            return 2;
        }
        fprintf(cg, "%d", (int)victim);
        if (fclose(cg) != 0) {
            fprintf(stderr, "DRIVER ERROR: could not place victim in %s\n", vjoin);
            return 2;
        }
        printf("VICTIM PLACED in %s\n", vjoin);
    }

    printf("CALL BEGIN\n");
    char *session = NULL;
    int rc = sd_pidfd_get_session(pidfd, &session);
    printf("CALL RETURNED rc=%d session=%s\n", rc, session ? session : "(none)");
    free(session);

    // Is the victim's pid occupied again, and by something alive? kill(pid, 0) probes without
    // delivering. This is the impostor the lookup could have described.
    int occupied = (kill(victim, 0) == 0);
    printf("PID %d OCCUPIED AFTER CALL: %s\n", (int)victim, occupied ? "yes" : "no");

    // D0A-R4-02. Two defects lived in the old two lines here:
    //   1. `kill(victim, ...)` killed whatever holds that NUMBER now. If a concurrent fork won
    //      the race, that is an unrelated process — and the real impostor leaks.
    //   2. Nothing asserted the recycle actually landed on the victim's pid, so a race left
    //      ESRCH looking correct for the wrong reason: the pidfd's process was gone either way.
    const char *imp_s = getenv("DELPHI_BARRIER_IMPOSTOR");
    int recycled_ok = 1;
    if (imp_s) {
        pid_t impostor = (pid_t)atoi(imp_s);
        // D0A-R5-01: NEVER signal a non-positive pid. kill(-1) signals every process the
        // caller may signal; kill(0) signals the whole process group. As root either is
        // catastrophic and neither is ever the intent here. Guarded at the SINK as well as at
        // the source, because `atoi` also yields 0 for unparseable input — two independent
        // ways to reach the same syscall.
        if (impostor <= 0) {
            printf("REFUSING to signal non-positive pid %d (kill(-1)/kill(0) would signal \
far more than this test created)\n", (int)impostor);
            // D0A-R5-01/R5-04: the victim is OURS and positive by construction, so reap it
            // before leaving. An early return that left it alive kept the stdout pipe open and
            // hung the reader forever — which is R5-04's mechanism, reproduced by this very
            // guard the moment it was written.
            kill(victim, SIGKILL);
            int vst = 0;
            waitpid(victim, &vst, 0);
            return 3;
        }
        if (impostor != victim) {
            // Loud, and fatal to the run: the experiment did not happen.
            printf("RECYCLE MISSED victim=%d impostor=%d\n", (int)victim, (int)impostor);
            recycled_ok = 0;
        }
        kill(impostor, SIGKILL);
        int st = 0;
        waitpid(impostor, &st, 0);
    } else {
        // No barrier ran; the victim is still ours and still the same process.
        kill(victim, SIGKILL);
        int st = 0;
        waitpid(victim, &st, 0);
    }
    return recycled_ok ? 0 : 3;
}

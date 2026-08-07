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

    kill(victim, SIGKILL);
    int st = 0;
    waitpid(victim, &st, 0);
    return 0;
}

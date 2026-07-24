#!/bin/bash
# PROBE: does Linux-PAM return SUCCESS for an EMPTY `session` management group?
#
# Answers whether the launcher's post-open_session outcome guard
# (logind::session_id_for_pid) is LOAD-BEARING or BELT-AND-BRACES. Read-only with
# respect to the real stack: it uses a THROWAWAY service name and removes it.
#
# Run as root:  sudo bash pam-empty-group-probe.sh
set -u
PROBE=/etc/pam.d/delphi-probe-emptygroup
cleanup() { rm -f "$PROBE" /tmp/pam_probe.c /tmp/pam_probe; }
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { echo "must run as root"; exit 1; }
command -v gcc >/dev/null || { echo "needs gcc"; exit 1; }
[ -f /usr/include/security/pam_appl.h ] || { echo "needs libpam0g-dev (pam_appl.h)"; exit 1; }

# A stack with auth+account populated but the SESSION GROUP DELIBERATELY EMPTY —
# exactly the shape the old two-line test fixture had.
printf 'auth       required   pam_unix.so\naccount    required   pam_unix.so\n' > "$PROBE"

cat > /tmp/pam_probe.c <<'C'
#include <security/pam_appl.h>
#include <stdio.h>
#include <unistd.h>
static struct pam_conv conv = { NULL, NULL };
int main(void) {
    pam_handle_t *pamh = NULL;
    int rc = pam_start("delphi-probe-emptygroup", "nobody", &conv, &pamh);
    printf("pam_start        rc=%d (%s)\n", rc, pam_strerror(pamh, rc));
    if (rc != PAM_SUCCESS) return 1;
    rc = pam_open_session(pamh, 0);
    printf("pam_open_session rc=%d (%s)  <== THE ANSWER\n", rc, pam_strerror(pamh, rc));
    printf("  PAM_SUCCESS is %d\n", PAM_SUCCESS);
    if (rc == PAM_SUCCESS) {
        printf("  -> EMPTY SESSION GROUP RETURNED SUCCESS.\n");
        printf("  -> The launcher's outcome guard is LOAD-BEARING.\n");
        pam_close_session(pamh, 0);
    } else {
        printf("  -> Empty session group ERRORED.\n");
        printf("  -> The launcher's outcome guard is BELT-AND-BRACES.\n");
    }
    pam_end(pamh, rc);
    return 0;
}
C

gcc -o /tmp/pam_probe /tmp/pam_probe.c -lpam || { echo "compile failed"; exit 1; }
echo "=== probe stack (session group empty by design) ==="; cat "$PROBE"
echo "=== result ==="; /tmp/pam_probe

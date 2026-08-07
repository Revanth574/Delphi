// SPDX-License-Identifier: MIT
// Prints the logind session of a pid, or nothing. Used to find a session that actually
// RESOLVES — "a session scope exists" is not the same fact as "the lookup answers for it".
#include <stdio.h>
#include <stdlib.h>
#include <systemd/sd-login.h>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    char *s = NULL;
    if (sd_pid_get_session(atoi(argv[1]), &s) < 0 || !s) return 1;
    printf("%s", s);
    free(s);
    return 0;
}

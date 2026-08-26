// SPDX-License-Identifier: MIT
// D0A-R16-01: suppress PR_SET_NO_NEW_PRIVS so the NNP-absent shape can be built in-tree.
// bwrap calls prctl through the PLT (verified: R_X86_64_JUMP_SLOT for prctl@GLIBC_2.2.5),
// so LD_PRELOAD reaches it. bwrap is not setuid and carries no file capabilities, so the
// loader honours LD_PRELOAD even when it runs as root.
#define _GNU_SOURCE
#include <stdarg.h>
#include <dlfcn.h>
#include <sys/prctl.h>

int prctl(int option, ...) {
    static int (*real)(int, unsigned long, unsigned long, unsigned long, unsigned long);
    va_list ap;
    unsigned long a2, a3, a4, a5;
    va_start(ap, option);
    a2 = va_arg(ap, unsigned long);
    a3 = va_arg(ap, unsigned long);
    a4 = va_arg(ap, unsigned long);
    a5 = va_arg(ap, unsigned long);
    va_end(ap);
    if (option == PR_SET_NO_NEW_PRIVS) {
        return 0;   // report success, do nothing — the whole point
    }
    if (!real) {
        real = dlsym(RTLD_NEXT, "prctl");
    }
    return real(option, a2, a3, a4, a5);
}

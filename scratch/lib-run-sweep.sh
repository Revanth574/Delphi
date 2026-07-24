# Shared helper — source, do not execute directly.
#
# Sweeps stale /run/delphi-*-<pid> test-fixture directories left behind by ROOT-GATED
# test runs that were killed rather than exiting gracefully (a hung test manually
# Ctrl-C'd, or an external timeout). Rust's Drop-based cleanup in each test's Setup does
# NOT run on SIGKILL or an unhandled SIGINT — the directory is unique per invocation
# (pid-suffixed), so nothing else ever removes it once orphaned.
#
# Measured 2026-07-24: 113 stale dirs, ~24MB average, filled /run and produced an hour
# of misattribution (read as a product-adjacent "full tmpfs" problem before being traced
# to orphaned fixture directories from an earlier killed run). This is the durable fix,
# not a rediscovery.
#
# Safe by construction: a dir is swept ONLY when its trailing -<pid> no longer
# corresponds to a running process (no /proc/<pid>). A live test's own directory is
# never touched, even mid-run, because its pid is still alive. Requires sudo (the
# fixtures create these as root); callers must have already run `sudo -v`.
sweep_stale_run_delphi_dirs() {
  local dir pid n=0
  for dir in /run/delphi-*; do
    [ -e "$dir" ] || continue   # glob didn't match anything
    pid="${dir##*-}"
    case "$pid" in
      ''|*[!0-9]*) continue ;;  # not a pid-suffixed name — don't guess, leave it alone
    esac
    if [ ! -d "/proc/$pid" ]; then
      sudo rm -rf "$dir" && n=$((n+1))
    fi
  done
  if [ "$n" -gt 0 ]; then
    echo "swept $n stale /run/delphi-* dir(s) from prior killed run(s)"
  fi
  df -h /run | sed 's/^/  /'
}

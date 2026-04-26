// SPDX-License-Identifier: MIT

//! Predictive crisis prevention — project + security risk monitors and the
//! [`CrisisMonitor`] that composes everything.
//!
//! # Fidelity levels supported (per Iron Law #13)
//!
//! ## Git status
//!
//! 1. **`git2` Rust crate** (declared, future) — `Fidelity::Direct` via libgit2.
//!    Avoided here because adding libgit2 increases build complexity for what
//!    is a contract-stable subprocess.
//! 2. **`git status --porcelain=v2 --branch`** (preferred, current) —
//!    `Fidelity::Subprocess`. Porcelain v2 format is documented and stable.
//!    - Required: `git` binary on PATH.
//!    - Failure modes: not a repo, binary missing.
//!
//! ## Goal deadline risk
//!
//! 1. **`crate::goals::GoalStore` SQLite** (current) — `Fidelity::Direct`.
//!    We're reading our own database, no external dependencies.
//!
//! ## Network connections
//!
//! 1. **`/proc/net/tcp` and `/proc/net/tcp6`** (preferred, current) —
//!    `Fidelity::Direct`. Kernel-direct, format stable since the dawn of /proc.
//!    - Failure modes: missing on non-Linux (compiles cross-platform; reading
//!      a missing path returns Unavailable).
//! 2. **`ss -tn`** (declared, future) — `Fidelity::Subprocess`.
//!
//! ## USB device events
//!
//! 1. **`udev` Rust crate / `udevadm monitor`** (declared, future) — real-time.
//! 2. **Polling `/sys/bus/usb/devices/`** (preferred, current) —
//!    `Fidelity::Direct`. Eventual consistency; misses transient devices but
//!    sufficient for desktop "is there a new device?" questions.
//!    - Failure modes: directory missing on non-Linux or VMs without USB
//!      passthrough (graceful empty result).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;

use chrono::{DateTime, Duration, Utc};
use tracing::debug;

use crate::OrchestratorError;
use crate::environment::Fidelity;
use crate::goals::{GoalStatus, GoalStore};
use crate::health::{HealthFinding, Severity};

/// Threshold for warning on uncommitted changes' age.
pub const STALE_UNCOMMITTED_HOURS: i64 = 24;

/// Days-remaining threshold for "deadline approaching" warning.
pub const DEADLINE_NEAR_DAYS: i64 = 14;

/// Days-remaining threshold for "deadline imminent" critical.
pub const DEADLINE_IMMINENT_DAYS: i64 = 7;

// ────────────────────────────────────────────────────────────────────
// Git status
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq)]
pub struct GitStatus {
    pub branch: Option<String>,
    pub ahead: u32,
    pub behind: u32,
    pub untracked: Vec<String>,
    pub modified: Vec<String>,
    pub staged: Vec<String>,
    pub oldest_change_age: Option<Duration>,
}

/// Parse `git status --porcelain=v2 --branch` output into a [`GitStatus`].
///
/// Format reference: <https://git-scm.com/docs/git-status#_porcelain_format_version_2>.
/// Skips lines we don't recognize (skip-don't-fail per the §3A.3 lesson).
pub fn parse_git_status_porcelain_v2(input: &str) -> GitStatus {
    let mut status = GitStatus::default();

    for line in input.lines() {
        if let Some(rest) = line.strip_prefix("# branch.head ") {
            status.branch = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("# branch.ab ") {
            // Format: "+N -M"
            let mut parts = rest.split_whitespace();
            if let Some(ahead) = parts.next().and_then(|s| s.strip_prefix('+'))
                && let Ok(n) = ahead.parse::<u32>()
            {
                status.ahead = n;
            }
            if let Some(behind) = parts.next().and_then(|s| s.strip_prefix('-'))
                && let Ok(n) = behind.parse::<u32>()
            {
                status.behind = n;
            }
        } else if let Some(rest) = line.strip_prefix("1 ") {
            // After the leading "1 ": <XY> <sub> <mH> <mI> <mW> <hH> <hI> <path>
            // = 8 fields. The path may itself contain spaces — splitn(8) keeps
            // any trailing spaces in the final field.
            let parts: Vec<&str> = rest.splitn(8, ' ').collect();
            if parts.len() < 8 {
                continue;
            }
            let xy = parts[0];
            let path = parts[7].to_string();
            classify_status_xy(xy, &path, &mut status);
        } else if let Some(rest) = line.strip_prefix("2 ") {
            // After the leading "2 ":
            //   <XY> <sub> <mH> <mI> <mW> <hH> <hI> <X><score> <path><TAB><origPath>
            // = 9 fields. The 9th field combines new and old paths separated by
            // a literal TAB. Per git docs, <path> is the *new* (current) name.
            let parts: Vec<&str> = rest.splitn(9, ' ').collect();
            if parts.len() < 9 {
                continue;
            }
            let xy = parts[0];
            let path = parts[8].split('\t').next().unwrap_or("").to_string();
            classify_status_xy(xy, &path, &mut status);
        } else if let Some(rest) = line.strip_prefix("? ") {
            status.untracked.push(rest.trim().to_string());
        }
    }

    status
}

fn classify_status_xy(xy: &str, path: &str, status: &mut GitStatus) {
    if xy.len() < 2 {
        return;
    }
    let mut chars = xy.chars();
    let staged = chars.next().unwrap();
    let unstaged = chars.next().unwrap();
    if staged != '.' && staged != ' ' {
        status.staged.push(path.to_string());
    }
    if unstaged != '.' && unstaged != ' ' {
        status.modified.push(path.to_string());
    }
}

/// Compute the age of the OLDEST file in `paths` based on filesystem mtime.
/// Returns `None` if no path was readable.
fn oldest_mtime_age(repo_root: &Path, paths: &[String]) -> Option<Duration> {
    let mut oldest: Option<SystemTime> = None;
    for rel in paths {
        let full = repo_root.join(rel);
        let Ok(meta) = std::fs::metadata(&full) else {
            continue;
        };
        let Ok(mtime) = meta.modified() else { continue };
        oldest = Some(match oldest {
            Some(prev) if prev <= mtime => prev,
            _ => mtime,
        });
    }
    let mtime = oldest?;
    let now = SystemTime::now();
    let dur = now.duration_since(mtime).ok()?;
    Duration::from_std(dur).ok()
}

/// Per-repo git risk monitor. Stateless — re-runs `git status` each check.
#[derive(Debug, Default)]
pub struct GitRiskMonitor;

impl GitRiskMonitor {
    pub fn new() -> Self {
        Self
    }

    /// Probe a single repo. Returns empty findings on any subprocess failure
    /// (missing binary, not a repo) — never errors out.
    pub fn check_repo(&self, repo: &Path) -> Vec<HealthFinding> {
        let output = Command::new("git")
            .args(["status", "--porcelain=v2", "--branch"])
            .current_dir(repo)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output();
        let Ok(o) = output else { return Vec::new() };
        if !o.status.success() {
            return Vec::new();
        }
        let text = String::from_utf8_lossy(&o.stdout);
        let mut status = parse_git_status_porcelain_v2(&text);
        let mut all_changed = Vec::new();
        all_changed.extend(status.modified.iter().cloned());
        all_changed.extend(status.staged.iter().cloned());
        all_changed.extend(status.untracked.iter().cloned());
        status.oldest_change_age = oldest_mtime_age(repo, &all_changed);
        evaluate_git_status(&status, repo)
    }

    pub fn check_paths(&self, repos: &[PathBuf]) -> Vec<HealthFinding> {
        let mut findings = Vec::new();
        for repo in repos {
            findings.extend(self.check_repo(repo));
        }
        findings
    }
}

/// Pure rule-based evaluation of a parsed [`GitStatus`].
pub fn evaluate_git_status(status: &GitStatus, repo: &Path) -> Vec<HealthFinding> {
    let component = format!("git:{}", repo.display());
    let mut findings = Vec::new();

    if let Some(age) = status.oldest_change_age
        && age.num_hours() >= STALE_UNCOMMITTED_HOURS
    {
        let total = status.modified.len() + status.staged.len() + status.untracked.len();
        findings.push(HealthFinding::now(
            component.clone(),
            Severity::Warning,
            format!(
                "{total} uncommitted file(s); oldest is {} hours old",
                age.num_hours()
            ),
            "review and commit, or stash for later".to_string(),
            Fidelity::Subprocess,
        ));
    }

    if status.ahead > 0 {
        findings.push(HealthFinding::now(
            component.clone(),
            Severity::Info,
            format!("{} commit(s) ahead of remote", status.ahead),
            "push when ready to share".to_string(),
            Fidelity::Subprocess,
        ));
    }

    if status.behind > 0 {
        findings.push(HealthFinding::now(
            component,
            Severity::Info,
            format!("{} commit(s) behind remote", status.behind),
            "pull/rebase to incorporate upstream changes".to_string(),
            Fidelity::Subprocess,
        ));
    }

    findings
}

// ────────────────────────────────────────────────────────────────────
// Goal deadline risk
// ────────────────────────────────────────────────────────────────────

/// Evaluates active goals against their deadlines.
#[derive(Debug, Default)]
pub struct GoalRiskMonitor;

impl GoalRiskMonitor {
    pub fn new() -> Self {
        Self
    }

    /// Pure evaluation: given the current time, deadline, and progress, return
    /// a finding if at risk, else `None`.
    pub fn evaluate(
        &self,
        goal_id: i64,
        title: &str,
        now: DateTime<Utc>,
        deadline: DateTime<Utc>,
        progress: u8,
    ) -> Option<HealthFinding> {
        let days = (deadline - now).num_days();
        let component = format!("goal:{goal_id}");
        let context = format!("deadline {}, progress {}%", deadline.to_rfc3339(), progress);

        if days < 0 {
            return Some(
                HealthFinding::now(
                    component,
                    Severity::Critical,
                    format!("'{title}' deadline passed {} days ago", -days),
                    "renegotiate scope or extend the deadline".to_string(),
                    Fidelity::Direct,
                )
                .with_baseline_context(context),
            );
        }
        if days <= DEADLINE_IMMINENT_DAYS && progress < 75 {
            return Some(
                HealthFinding::now(
                    component,
                    Severity::Critical,
                    format!(
                        "'{title}' is {days} day(s) from deadline at {progress}% progress",
                    ),
                    "focus or trim scope".to_string(),
                    Fidelity::Direct,
                )
                .with_baseline_context(context),
            );
        }
        if days <= DEADLINE_NEAR_DAYS && progress < 50 {
            return Some(
                HealthFinding::now(
                    component,
                    Severity::Warning,
                    format!(
                        "'{title}' is {days} day(s) from deadline at {progress}% progress",
                    ),
                    "schedule focused time soon".to_string(),
                    Fidelity::Direct,
                )
                .with_baseline_context(context),
            );
        }
        None
    }

    /// Enumerate active goals with deadlines from the store and emit findings.
    pub fn check(&self, store: &GoalStore) -> Vec<HealthFinding> {
        let now = Utc::now();
        let goals = match store.list_active() {
            Ok(g) => g,
            Err(e) => {
                debug!("goal monitor list_active failed: {e}");
                return Vec::new();
            }
        };
        let mut findings = Vec::new();
        for goal in goals {
            if goal.status != GoalStatus::Active {
                continue;
            }
            let Some(deadline) = goal.deadline else {
                continue;
            };
            if let Some(f) = self.evaluate(
                goal.id,
                &goal.title,
                now,
                deadline,
                goal.progress_estimate,
            ) {
                findings.push(f);
            }
        }
        findings
    }
}

// ────────────────────────────────────────────────────────────────────
// Network — /proc/net/tcp parsing
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Established,
    SynSent,
    Listen,
    TimeWait,
    Other,
}

impl TcpState {
    pub fn from_hex(code: &str) -> Self {
        match code {
            "01" => TcpState::Established,
            "02" => TcpState::SynSent,
            "06" => TcpState::TimeWait,
            "0A" => TcpState::Listen,
            _ => TcpState::Other,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TcpState::Established => "established",
            TcpState::SynSent => "syn_sent",
            TcpState::Listen => "listen",
            TcpState::TimeWait => "time_wait",
            TcpState::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TcpConnection {
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: TcpState,
    pub uid: u32,
}

/// Convert an 8-hex IPv4 address (as printed by /proc/net/tcp on x86 LE) into
/// a dotted-quad string. The kernel prints in host byte order, so the bytes
/// of the parsed `u32` are reversed relative to network order.
fn parse_ipv4_hex(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    let n = u32::from_str_radix(hex, 16).ok()?;
    let b = n.to_be_bytes();
    Some(format!("{}.{}.{}.{}", b[3], b[2], b[1], b[0]))
}

/// Parse `/proc/net/tcp` into a vector of [`TcpConnection`].
///
/// Skips lines that don't fit the expected shape. Header is dropped.
pub fn parse_proc_net_tcp(input: &str) -> Vec<TcpConnection> {
    let mut out = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        if idx == 0 {
            continue; // header
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 8 {
            continue;
        }
        // tokens: ["0:", "3500007F:0035", "00000000:0000", "0A", "...", "...", "...", "...", "uid", ...]
        let Some((_, local)) = tokens[1].split_once(':') else {
            continue;
        };
        let _local_addr_hex = tokens[1].split(':').next().unwrap_or("");
        let local_port = u16::from_str_radix(local, 16).unwrap_or(0);
        let Some((rem_hex, rem_port_hex)) = tokens[2].split_once(':') else {
            continue;
        };
        let remote_addr = parse_ipv4_hex(rem_hex).unwrap_or_else(|| rem_hex.to_string());
        let remote_port = u16::from_str_radix(rem_port_hex, 16).unwrap_or(0);
        let state = TcpState::from_hex(tokens[3]);
        let uid = tokens[7].parse::<u32>().unwrap_or(0);
        out.push(TcpConnection {
            local_port,
            remote_addr,
            remote_port,
            state,
            uid,
        });
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedDestination {
    pub host_or_ip: String,
    pub purpose: String,
}

#[derive(Debug, Default)]
pub struct NetworkRiskMonitor {
    pub expected_destinations: Vec<ExpectedDestination>,
    proc_root: PathBuf,
}

impl NetworkRiskMonitor {
    pub fn new() -> Self {
        Self {
            expected_destinations: Vec::new(),
            proc_root: PathBuf::from("/proc"),
        }
    }

    pub fn with_proc_root(proc_root: PathBuf) -> Self {
        Self {
            expected_destinations: Vec::new(),
            proc_root,
        }
    }

    pub fn add_expected(&mut self, host_or_ip: &str, purpose: &str) {
        self.expected_destinations.push(ExpectedDestination {
            host_or_ip: host_or_ip.to_string(),
            purpose: purpose.to_string(),
        });
    }

    /// Pure evaluation: classify a parsed connection list against the expected
    /// list. Loopback (127.x) and link-local (169.254.x) are auto-allowed.
    pub fn evaluate(&self, connections: &[TcpConnection]) -> Vec<HealthFinding> {
        let mut findings = Vec::new();
        for c in connections {
            if c.state != TcpState::Established {
                continue;
            }
            if is_local_address(&c.remote_addr) {
                continue;
            }
            let allowed = self
                .expected_destinations
                .iter()
                .any(|d| d.host_or_ip == c.remote_addr);
            if allowed {
                continue;
            }
            findings.push(HealthFinding::now(
                format!("network:{}:{}", c.remote_addr, c.remote_port),
                Severity::Info,
                format!(
                    "established connection to {}:{} (uid {})",
                    c.remote_addr, c.remote_port, c.uid
                ),
                "verify this destination is expected".to_string(),
                Fidelity::Direct,
            ));
        }
        findings
    }

    /// Live probe: read /proc/net/tcp + tcp6 and evaluate.
    pub fn check(&self) -> Vec<HealthFinding> {
        let mut conns = Vec::new();
        if let Ok(t4) = std::fs::read_to_string(self.proc_root.join("net/tcp")) {
            conns.extend(parse_proc_net_tcp(&t4));
        }
        // tcp6 handled with the same parser (skipped silently if absent).
        // The IPv6 address column is 32 hex chars instead of 8; our
        // parse_ipv4_hex returns None and remote_addr falls back to the raw
        // hex string, which is acceptable provenance for an Info-level
        // unknown-destination finding.
        if let Ok(t6) = std::fs::read_to_string(self.proc_root.join("net/tcp6")) {
            conns.extend(parse_proc_net_tcp(&t6));
        }
        self.evaluate(&conns)
    }
}

fn is_local_address(addr: &str) -> bool {
    addr.starts_with("127.")
        || addr.starts_with("169.254.")
        || addr == "0.0.0.0"
        || addr.starts_with("::1")
        || addr == "::"
        || addr.starts_with("fe80")
}

// ────────────────────────────────────────────────────────────────────
// USB device monitor
// ────────────────────────────────────────────────────────────────────

/// Polls `<sys_root>/bus/usb/devices/`. A device-id directory previously
/// unseen produces an Info finding; subsequent observations are silent.
#[derive(Debug, Default)]
pub struct UsbRiskMonitor {
    seen_devices: HashSet<String>,
    sys_root: PathBuf,
}

impl UsbRiskMonitor {
    pub fn new() -> Self {
        Self {
            seen_devices: HashSet::new(),
            sys_root: PathBuf::from("/sys"),
        }
    }

    pub fn with_sys_root(sys_root: PathBuf) -> Self {
        Self {
            seen_devices: HashSet::new(),
            sys_root,
        }
    }

    pub fn check(&mut self) -> Vec<HealthFinding> {
        let dir = self.sys_root.join("bus/usb/devices");
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };
        let mut findings = Vec::new();
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            // usbN entries are buses; ignore them, only track real devices.
            if name.starts_with("usb") {
                continue;
            }
            if self.seen_devices.contains(&name) {
                continue;
            }
            self.seen_devices.insert(name.clone());
            findings.push(HealthFinding::now(
                format!("usb:{name}"),
                Severity::Info,
                format!("new USB device detected: {name}"),
                "verify the device is expected".to_string(),
                Fidelity::Direct,
            ));
        }
        findings
    }

    /// Test-only: how many devices are remembered.
    pub fn seen_count(&self) -> usize {
        self.seen_devices.len()
    }
}

// ────────────────────────────────────────────────────────────────────
// Top-level CrisisMonitor
// ────────────────────────────────────────────────────────────────────

/// Composes all monitors for a single check pass. Each monitor is independent;
/// a failure in one does not stop the others. Goal monitor is invoked
/// separately because it requires a borrowed [`GoalStore`].
pub struct CrisisMonitor {
    pub disk: DiskHealthMonitor,
    pub crash: CrashMonitor,
    pub dependencies: DependencyMonitor,
    pub git: GitRiskMonitor,
    pub network: NetworkRiskMonitor,
    pub usb: UsbRiskMonitor,
    pub process_memory: ProcessMemoryMonitor,
    pub watch_paths: Vec<PathBuf>,
}

// Re-export from health for convenience at the crate boundary.
pub use crate::health::{
    CrashMonitor, DependencyMonitor, DiskHealthMonitor, ProcessMemoryMonitor,
};

impl Default for CrisisMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl CrisisMonitor {
    pub fn new() -> Self {
        Self {
            disk: DiskHealthMonitor::new(),
            crash: CrashMonitor::new(),
            dependencies: DependencyMonitor::new(),
            git: GitRiskMonitor::new(),
            network: NetworkRiskMonitor::new(),
            usb: UsbRiskMonitor::new(),
            process_memory: ProcessMemoryMonitor::new(),
            watch_paths: Vec::new(),
        }
    }

    /// Add a git repo to monitor.
    pub fn watch_repo(&mut self, path: PathBuf) {
        if !self.watch_paths.contains(&path) {
            self.watch_paths.push(path);
        }
    }

    pub fn unwatch_repo(&mut self, path: &Path) -> bool {
        let before = self.watch_paths.len();
        self.watch_paths.retain(|p| p.as_path() != path);
        before != self.watch_paths.len()
    }

    /// Run only the cheap monitors (no subprocess shell-outs).
    /// Useful for high-frequency polling.
    pub fn check_quick(&mut self) -> Vec<HealthFinding> {
        let mut findings = Vec::new();
        findings.extend(self.process_memory.check());
        findings.extend(self.network.check());
        findings.extend(self.usb.check());
        findings
    }

    /// Run every monitor. Independent failures don't stop the chain.
    pub fn check_all(&mut self) -> Vec<HealthFinding> {
        let mut findings = Vec::new();
        findings.extend(self.disk.check());
        findings.extend(self.crash.check_recent(60));
        findings.extend(self.dependencies.check());
        findings.extend(self.git.check_paths(&self.watch_paths));
        findings.extend(self.process_memory.check());
        findings.extend(self.network.check());
        findings.extend(self.usb.check());
        findings
    }
}

// Custom Debug since some component fields aren't Debug.
impl std::fmt::Debug for CrisisMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrisisMonitor")
            .field("watch_paths", &self.watch_paths)
            .field("usb_seen", &self.usb.seen_count())
            .finish()
    }
}

/// Helper used by the orchestrator daemon: combine [`CrisisMonitor::check_all`]
/// with [`GoalRiskMonitor::check`] when a [`GoalStore`] is available.
pub fn check_all_with_goals(
    monitor: &mut CrisisMonitor,
    goals: &GoalRiskMonitor,
    store: &GoalStore,
) -> Vec<HealthFinding> {
    let mut findings = monitor.check_all();
    findings.extend(goals.check(store));
    findings
}

// Convenience: avoid imports at call site of OrchestratorError without using it
#[allow(dead_code)]
fn _unused_keep_orchestrator_error_in_scope() -> Result<(), OrchestratorError> {
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ── parse_git_status_porcelain_v2 ─────────────────────────────────

    #[test]
    fn git_porcelain_clean_repo() {
        let body = "# branch.head main\n# branch.upstream origin/main\n# branch.ab +0 -0\n";
        let s = parse_git_status_porcelain_v2(body);
        assert_eq!(s.branch.as_deref(), Some("main"));
        assert_eq!(s.ahead, 0);
        assert_eq!(s.behind, 0);
        assert!(s.modified.is_empty());
        assert!(s.staged.is_empty());
        assert!(s.untracked.is_empty());
    }

    #[test]
    fn git_porcelain_ahead_and_behind() {
        let body = "# branch.head dev\n# branch.ab +3 -2\n";
        let s = parse_git_status_porcelain_v2(body);
        assert_eq!(s.ahead, 3);
        assert_eq!(s.behind, 2);
    }

    #[test]
    fn git_porcelain_dirty_repo_classifies_modified_and_staged() {
        let body = "# branch.head main\n\
                    1 .M N... 100644 100644 100644 abc def src/lib.rs\n\
                    1 M. N... 100644 100644 100644 abc def README.md\n\
                    1 MM N... 100644 100644 100644 abc def Cargo.toml\n\
                    ? newfile.txt\n\
                    ? notes.md\n";
        let s = parse_git_status_porcelain_v2(body);
        assert_eq!(s.untracked.len(), 2);
        // Cargo.toml is both staged AND modified
        assert!(s.staged.contains(&"README.md".to_string()));
        assert!(s.staged.contains(&"Cargo.toml".to_string()));
        assert!(s.modified.contains(&"src/lib.rs".to_string()));
        assert!(s.modified.contains(&"Cargo.toml".to_string()));
    }

    #[test]
    fn git_porcelain_handles_renamed_files() {
        // Renamed file: line starts with "2 " and has extra rename score.
        // Real git output is `new<TAB>old`; <path> is the new name.
        let body = "2 R. N... 100644 100644 100644 abc def R100 newname.rs\toldname.rs\n";
        let s = parse_git_status_porcelain_v2(body);
        // Renamed counts as staged (R. = staged rename, no unstaged change).
        assert_eq!(s.staged, vec!["newname.rs".to_string()]);
    }

    #[test]
    fn git_porcelain_skips_unrecognized_lines() {
        let body = "garbage\n# branch.head main\nrandom prefix\n? new.txt\n";
        let s = parse_git_status_porcelain_v2(body);
        assert_eq!(s.branch.as_deref(), Some("main"));
        assert_eq!(s.untracked, vec!["new.txt".to_string()]);
    }

    // ── evaluate_git_status ──────────────────────────────────────────

    #[test]
    fn evaluate_git_status_stale_changes_warn() {
        let status = GitStatus {
            branch: Some("main".into()),
            modified: vec!["a".into(), "b".into()],
            oldest_change_age: Some(Duration::hours(48)),
            ..Default::default()
        };
        let findings = evaluate_git_status(&status, Path::new("/tmp/repo"));
        assert!(findings.iter().any(|f| f.severity == Severity::Warning));
    }

    #[test]
    fn evaluate_git_status_recent_changes_no_warn() {
        let status = GitStatus {
            modified: vec!["a".into()],
            oldest_change_age: Some(Duration::hours(2)),
            ..Default::default()
        };
        let findings = evaluate_git_status(&status, Path::new("/tmp/repo"));
        assert!(!findings.iter().any(|f| f.severity == Severity::Warning));
    }

    #[test]
    fn evaluate_git_status_ahead_emits_info() {
        let status = GitStatus {
            ahead: 2,
            ..Default::default()
        };
        let findings = evaluate_git_status(&status, Path::new("/tmp/repo"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].message.contains("ahead"));
    }

    // ── GoalRiskMonitor::evaluate (pure) ─────────────────────────────

    #[test]
    fn goal_risk_evaluate_passed_deadline_critical() {
        let mon = GoalRiskMonitor::new();
        let now = Utc::now();
        let deadline = now - Duration::days(2);
        let f = mon.evaluate(1, "Late", now, deadline, 50).unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.message.contains("passed"));
    }

    #[test]
    fn goal_risk_evaluate_imminent_low_progress_critical() {
        let mon = GoalRiskMonitor::new();
        let now = Utc::now();
        let deadline = now + Duration::days(3);
        let f = mon.evaluate(1, "Soon", now, deadline, 30).unwrap();
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn goal_risk_evaluate_near_low_progress_warning() {
        let mon = GoalRiskMonitor::new();
        let now = Utc::now();
        let deadline = now + Duration::days(10);
        let f = mon.evaluate(1, "Coming", now, deadline, 30).unwrap();
        assert_eq!(f.severity, Severity::Warning);
    }

    #[test]
    fn goal_risk_evaluate_imminent_high_progress_no_finding() {
        let mon = GoalRiskMonitor::new();
        let now = Utc::now();
        let deadline = now + Duration::days(3);
        assert!(mon.evaluate(1, "OK", now, deadline, 90).is_none());
    }

    #[test]
    fn goal_risk_evaluate_far_deadline_no_finding() {
        let mon = GoalRiskMonitor::new();
        let now = Utc::now();
        let deadline = now + Duration::days(60);
        assert!(mon.evaluate(1, "Way out", now, deadline, 10).is_none());
    }

    // ── /proc/net/tcp parsing ─────────────────────────────────────────

    #[test]
    fn parse_ipv4_hex_handles_loopback() {
        assert_eq!(parse_ipv4_hex("0100007F").as_deref(), Some("127.0.0.1"));
        // systemd-resolved at 127.0.0.53
        assert_eq!(parse_ipv4_hex("3500007F").as_deref(), Some("127.0.0.53"));
    }

    #[test]
    fn parse_ipv4_hex_returns_none_on_short_input() {
        assert!(parse_ipv4_hex("FF").is_none());
        assert!(parse_ipv4_hex("garbage").is_none());
    }

    #[test]
    fn parse_proc_net_tcp_skips_header_and_yields_listeners() {
        let body = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   991        0 3671 1 0\n\
   1: 0100007F:1F90 0100007F:E2B4 01 00000000:00000000 00:00000000 00000000  1000        0 9012 1 0\n";
        let conns = parse_proc_net_tcp(body);
        assert_eq!(conns.len(), 2);
        assert_eq!(conns[0].local_port, 53);
        assert_eq!(conns[0].state, TcpState::Listen);
        assert_eq!(conns[0].uid, 991);
        assert_eq!(conns[1].local_port, 0x1F90);
        assert_eq!(conns[1].state, TcpState::Established);
        assert_eq!(conns[1].remote_addr, "127.0.0.1");
    }

    #[test]
    fn tcp_state_from_hex_classifies_known_codes() {
        assert_eq!(TcpState::from_hex("01"), TcpState::Established);
        assert_eq!(TcpState::from_hex("02"), TcpState::SynSent);
        assert_eq!(TcpState::from_hex("06"), TcpState::TimeWait);
        assert_eq!(TcpState::from_hex("0A"), TcpState::Listen);
        assert_eq!(TcpState::from_hex("FF"), TcpState::Other);
    }

    #[test]
    fn tcp_state_strings_are_stable() {
        assert_eq!(TcpState::Established.as_str(), "established");
        assert_eq!(TcpState::Listen.as_str(), "listen");
    }

    // ── NetworkRiskMonitor ────────────────────────────────────────────

    #[test]
    fn network_monitor_skips_loopback() {
        let mon = NetworkRiskMonitor::new();
        let conns = vec![TcpConnection {
            local_port: 1234,
            remote_addr: "127.0.0.1".into(),
            remote_port: 5678,
            state: TcpState::Established,
            uid: 1000,
        }];
        assert!(mon.evaluate(&conns).is_empty());
    }

    #[test]
    fn network_monitor_flags_unexpected_destination() {
        let mon = NetworkRiskMonitor::new();
        let conns = vec![TcpConnection {
            local_port: 12345,
            remote_addr: "8.8.8.8".into(),
            remote_port: 443,
            state: TcpState::Established,
            uid: 1000,
        }];
        let f = mon.evaluate(&conns);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Info);
        assert!(f[0].component.contains("8.8.8.8"));
    }

    #[test]
    fn network_monitor_allows_expected_destination() {
        let mut mon = NetworkRiskMonitor::new();
        mon.add_expected("1.2.3.4", "anthropic-api");
        let conns = vec![TcpConnection {
            local_port: 12345,
            remote_addr: "1.2.3.4".into(),
            remote_port: 443,
            state: TcpState::Established,
            uid: 1000,
        }];
        assert!(mon.evaluate(&conns).is_empty());
    }

    #[test]
    fn network_monitor_skips_non_established_states() {
        let mon = NetworkRiskMonitor::new();
        let conns = vec![TcpConnection {
            local_port: 1234,
            remote_addr: "8.8.8.8".into(),
            remote_port: 443,
            state: TcpState::TimeWait,
            uid: 1000,
        }];
        assert!(mon.evaluate(&conns).is_empty());
    }

    // ── UsbRiskMonitor ────────────────────────────────────────────────

    fn touch(p: &Path) {
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::create_dir_all(p).unwrap();
    }

    #[test]
    fn usb_first_observation_emits_info() {
        let tmp = TempDir::new().unwrap();
        touch(&tmp.path().join("bus/usb/devices/1-1"));
        touch(&tmp.path().join("bus/usb/devices/usb1")); // bus, ignored
        let mut mon = UsbRiskMonitor::with_sys_root(tmp.path().to_path_buf());
        let f = mon.check();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Info);
        assert!(f[0].component.contains("1-1"));
        assert_eq!(mon.seen_count(), 1);
    }

    #[test]
    fn usb_subsequent_observation_silent() {
        let tmp = TempDir::new().unwrap();
        touch(&tmp.path().join("bus/usb/devices/1-1"));
        let mut mon = UsbRiskMonitor::with_sys_root(tmp.path().to_path_buf());
        let _ = mon.check();
        let f = mon.check();
        assert!(f.is_empty());
    }

    #[test]
    fn usb_handles_missing_dir() {
        let tmp = TempDir::new().unwrap();
        let mut mon = UsbRiskMonitor::with_sys_root(tmp.path().to_path_buf());
        assert!(mon.check().is_empty());
    }

    // ── CrisisMonitor ────────────────────────────────────────────────

    #[test]
    fn crisis_check_quick_runs_no_subprocesses() {
        // Quick check should compile and return findings only from in-process
        // monitors. We can't directly assert "no subprocess" but we can
        // verify that the call doesn't panic without binaries available.
        let mut mon = CrisisMonitor::new();
        let _ = mon.check_quick();
    }

    #[test]
    fn crisis_watch_repo_idempotent() {
        let mut mon = CrisisMonitor::new();
        mon.watch_repo(PathBuf::from("/repo1"));
        mon.watch_repo(PathBuf::from("/repo1"));
        mon.watch_repo(PathBuf::from("/repo2"));
        assert_eq!(mon.watch_paths.len(), 2);
    }

    #[test]
    fn crisis_unwatch_repo_returns_true_on_existing() {
        let mut mon = CrisisMonitor::new();
        mon.watch_repo(PathBuf::from("/repo1"));
        assert!(mon.unwatch_repo(Path::new("/repo1")));
        assert!(!mon.unwatch_repo(Path::new("/repo1")));
        assert!(!mon.unwatch_repo(Path::new("/repo-nonexistent")));
    }

    #[test]
    fn crisis_check_all_independent_failures() {
        // Disk + dpkg + git all unreachable on Windows / WSL without setup;
        // the call should still return a Vec without panicking.
        let mut mon = CrisisMonitor::new();
        let _ = mon.check_all();
    }
}

// SPDX-License-Identifier: MIT

//! Predictive crisis prevention — health monitors (capability #13, hardware + software half).
//!
//! # Fidelity levels supported (per Iron Law #13)
//!
//! ## Disk SMART data
//!
//! 1. **NVMe-CLI ioctl** (declared, future work) — full per-NVMe SMART via syscall;
//!    would be `Fidelity::Direct`.
//! 2. **`smartctl --json -A /dev/<dev>`** (preferred, current) — JSON parse, robust;
//!    `Fidelity::Subprocess`.
//!    - Required: smartmontools package installed.
//!    - Failure modes: binary missing, device not SMART-capable, sudo required.
//! 3. **`/sys/block/<dev>/device/`** (declared) — too vendor-specific for general use;
//!    we don't implement.
//!
//! ## Process crashes
//!
//! 1. **`journalctl --since <when> --output=json --no-pager`** (preferred) —
//!    structured systemd journal; `Fidelity::Subprocess`.
//!    - Required: systemd-journald present and reachable.
//!    - Failure modes: non-systemd init, journal access denied.
//! 2. **`/var/log/syslog`** (declared, last resort) — text parse, brittle.
//!
//! ## Memory leak detection
//!
//! 1. **`/proc/<pid>/status`** (preferred) — kernel-direct `VmRSS:` field;
//!    `Fidelity::Direct`.
//! 2. **`ps -eo pid,rss,comm`** (declared, future) — `Fidelity::Subprocess`.
//!
//! ## Dependency vulnerabilities
//!
//! 1. **`dpkg-query -W`** (current, primary) — installed-package db, parsed name/version;
//!    `Fidelity::Subprocess`.
//! 2. **`apt list --upgradable`** (declared) — distinct semantics (available updates
//!    rather than known-vulnerable comparison).
//!
//! Every public function returns a [`Fidelity`] tag (in the `HealthFinding` it
//! produces) so consumers know the provenance of the answer.
//!
//! # Predictive model
//!
//! Each monitor maintains a rolling history (default 1024 samples) and computes
//! baselines. Anomalies are detected as deviations from baseline rather than
//! hardcoded thresholds. Fallback thresholds are used only when history is
//! insufficient (< 100 samples) or as catastrophic safeguards (e.g. NVMe
//! `percentage_used >= 90`). When a fallback threshold fires, the
//! `baseline_context` is `None`; when a baseline-driven alarm fires, the
//! field carries the explanatory range text.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::OrchestratorError;
use crate::environment::Fidelity;

/// Baseline window default — 1024 samples is enough for ~17 hours at 1-minute
/// polling, plenty to characterize normal behavior without unbounded memory.
pub const DEFAULT_BASELINE_WINDOW: usize = 1024;

/// Minimum samples before a baseline is trusted for anomaly detection.
pub const BASELINE_SUFFICIENT_THRESHOLD: usize = 100;

/// Minimum consecutive samples needed to declare a memory leak.
pub const LEAK_MIN_SAMPLES: usize = 6;

/// Default NVMe `percentage_used` threshold for "wear emergency" alert
/// (manufacturer-recommended replacement point).
pub const NVME_WEAR_EMERGENCY: u8 = 90;

/// Reallocated-sector count threshold for warning regardless of baseline.
/// Even a single reallocation is concerning; this catches catastrophic counts.
pub const REALLOCATED_SECTORS_EMERGENCY: u64 = 100;

// ────────────────────────────────────────────────────────────────────
// Severity + HealthFinding
// ────────────────────────────────────────────────────────────────────

/// Finding severity ordered from least to most urgent. The derived `Ord`
/// matches the variant order, so consumers can write
/// `findings.iter().filter(|f| f.severity >= Severity::Warning)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// Observation worth knowing — no action required.
    Info,
    /// User should investigate when convenient.
    Warning,
    /// User should act soon (hours, not days).
    Critical,
    /// User must act now (data loss imminent).
    Emergency,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
            Severity::Emergency => "emergency",
        }
    }
}

/// A single observation about system or project health that may warrant
/// user attention. All findings carry [`Fidelity`] provenance per Iron Law #13.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthFinding {
    /// Stable identifier of the component that produced the finding.
    /// Format: `<category>:<subject>` — e.g. `disk:/dev/sda`, `process:firefox`,
    /// `git:/home/user/repo`, `network:1.2.3.4:443`.
    pub component: String,
    pub severity: Severity,
    pub message: String,
    pub recommendation: String,
    pub fidelity: Fidelity,
    pub detected_at: DateTime<Utc>,
    /// Free-form text describing the baseline context that triggered the
    /// finding (e.g. `"normal: 45-60°C, observed: 78°C"`). `None` when the
    /// alarm came from a fallback hardcoded threshold rather than a learned
    /// baseline.
    pub baseline_context: Option<String>,
}

impl HealthFinding {
    /// Construct a finding with `detected_at = Utc::now()` and no baseline context.
    pub fn now(
        component: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
        recommendation: impl Into<String>,
        fidelity: Fidelity,
    ) -> Self {
        Self {
            component: component.into(),
            severity,
            message: message.into(),
            recommendation: recommendation.into(),
            fidelity,
            detected_at: Utc::now(),
            baseline_context: None,
        }
    }

    pub fn with_baseline_context(mut self, ctx: impl Into<String>) -> Self {
        self.baseline_context = Some(ctx.into());
        self
    }
}

// ────────────────────────────────────────────────────────────────────
// Baseline (rolling-window statistics)
// ────────────────────────────────────────────────────────────────────

/// Rolling window of measurements with median + std_dev computation.
///
/// Median is preferred as the centerline because it's robust to outliers
/// (a few spike readings don't shift it). Std_dev still uses the mean,
/// which is the standard definition. The mix is pragmatic.
#[derive(Debug, Clone)]
pub struct Baseline {
    samples: VecDeque<f64>,
    max_samples: usize,
}

impl Default for Baseline {
    fn default() -> Self {
        Self::new(DEFAULT_BASELINE_WINDOW)
    }
}

impl Baseline {
    pub fn new(max_samples: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(max_samples),
            max_samples: max_samples.max(1),
        }
    }

    pub fn push(&mut self, value: f64) {
        if self.samples.len() == self.max_samples {
            self.samples.pop_front();
        }
        self.samples.push_back(value);
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Returns `true` once the window has accumulated enough samples
    /// (≥ [`BASELINE_SUFFICIENT_THRESHOLD`]) to be trusted for anomaly
    /// detection. Below the threshold, monitors fall back to hardcoded
    /// safeguards.
    pub fn has_sufficient_history(&self) -> bool {
        self.samples.len() >= BASELINE_SUFFICIENT_THRESHOLD
    }

    /// Median of all samples, or `None` when the window is empty.
    pub fn median(&self) -> Option<f64> {
        if self.samples.is_empty() {
            return None;
        }
        let mut sorted: Vec<f64> = self.samples.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = sorted.len();
        Some(if n % 2 == 1 {
            sorted[n / 2]
        } else {
            (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
        })
    }

    /// Population std_dev, or `None` when fewer than 2 samples.
    pub fn std_dev(&self) -> Option<f64> {
        let n = self.samples.len();
        if n < 2 {
            return None;
        }
        let mean: f64 = self.samples.iter().sum::<f64>() / n as f64;
        let variance: f64 =
            self.samples.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n as f64;
        Some(variance.sqrt())
    }

    /// `true` when `value` is more than `std_devs` standard deviations away
    /// from the median (in either direction). When std_dev is 0 (all
    /// samples equal), only an exact match returns false.
    pub fn is_anomalous(&self, value: f64, std_devs: f64) -> bool {
        let Some(med) = self.median() else { return false };
        let Some(sd) = self.std_dev() else { return false };
        if sd == 0.0 {
            return (value - med).abs() > 0.0;
        }
        (value - med).abs() / sd > std_devs
    }
}

// ────────────────────────────────────────────────────────────────────
// SMART attributes + parser
// ────────────────────────────────────────────────────────────────────

/// Curated subset of SMART attributes most relevant for health prediction,
/// plus a `raw_attrs` escape hatch for the full smartctl payload.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmartAttrs {
    pub power_on_hours: Option<u64>,
    pub reallocated_sectors: Option<u64>,
    pub wear_leveling_count: Option<u64>,
    pub percentage_used: Option<u8>,
    pub temperature_celsius: Option<f32>,
    pub raw_attrs: HashMap<String, serde_json::Value>,
    pub fidelity: Fidelity,
}

/// Parse `smartctl --json -A <device>` output into a [`SmartAttrs`].
///
/// Tolerates missing fields (drives expose different attribute sets). The
/// `raw_attrs` map preserves whatever else came back so consumers can dig
/// deeper if needed.
pub fn parse_smartctl_json(input: &str) -> Result<SmartAttrs, OrchestratorError> {
    let v: serde_json::Value = serde_json::from_str(input).map_err(|e| {
        OrchestratorError::Environment(format!("smartctl JSON parse failed: {e}"))
    })?;

    let mut attrs = SmartAttrs {
        fidelity: Fidelity::Subprocess,
        ..Default::default()
    };

    // power_on_time.hours
    if let Some(hours) = v
        .pointer("/power_on_time/hours")
        .and_then(serde_json::Value::as_u64)
    {
        attrs.power_on_hours = Some(hours);
    }

    // ATA SMART table (id-keyed)
    if let Some(table) = v
        .pointer("/ata_smart_attributes/table")
        .and_then(serde_json::Value::as_array)
    {
        for entry in table {
            let Some(id) = entry.get("id").and_then(serde_json::Value::as_u64) else {
                continue;
            };
            let raw = entry
                .pointer("/raw/value")
                .and_then(serde_json::Value::as_u64);
            match id {
                5 => attrs.reallocated_sectors = raw,
                177 => attrs.wear_leveling_count = raw,
                194 => {
                    if let Some(t) = raw {
                        attrs.temperature_celsius = Some(t as f32);
                    }
                }
                _ => {}
            }
        }
    }

    // NVMe-specific fields
    if let Some(pct) = v
        .pointer("/nvme_smart_health_information_log/percentage_used")
        .and_then(serde_json::Value::as_u64)
    {
        attrs.percentage_used = Some(pct.min(100) as u8);
    }

    // Generic temperature.current as fallback
    if attrs.temperature_celsius.is_none()
        && let Some(t) = v
            .pointer("/temperature/current")
            .and_then(serde_json::Value::as_f64)
    {
        attrs.temperature_celsius = Some(t as f32);
    }

    if let Some(obj) = v.as_object() {
        for (k, val) in obj {
            attrs.raw_attrs.insert(k.clone(), val.clone());
        }
    }

    Ok(attrs)
}

// ────────────────────────────────────────────────────────────────────
// /proc/<pid>/status RSS parsing
// ────────────────────────────────────────────────────────────────────

/// Extract the `VmRSS:` value (in kilobytes) from a `/proc/<pid>/status` body.
///
/// Returns `None` when the field is absent (process exited, kernel without
/// /proc, kernel-only thread).
pub fn parse_proc_status_for_rss(input: &str) -> Option<u64> {
    for line in input.lines() {
        let line = line.trim_start();
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|n| n.parse::<u64>().ok());
        }
    }
    None
}

// ────────────────────────────────────────────────────────────────────
// journalctl JSON parsing
// ────────────────────────────────────────────────────────────────────

/// One entry from `journalctl --output=json` — minimal fields needed for
/// crash detection.
#[derive(Debug, Clone, PartialEq)]
pub struct JournalEntry {
    /// Microseconds since UNIX epoch as parsed from `__REALTIME_TIMESTAMP`.
    pub timestamp_usec: u64,
    /// Originating service unit, falls back to `SYSLOG_IDENTIFIER` then `_COMM`.
    pub unit: String,
    pub message: String,
    pub priority: Option<u8>,
    pub message_id: Option<String>,
}

impl JournalEntry {
    pub fn datetime(&self) -> Option<DateTime<Utc>> {
        let secs = (self.timestamp_usec / 1_000_000) as i64;
        let nsecs = ((self.timestamp_usec % 1_000_000) * 1_000) as u32;
        DateTime::<Utc>::from_timestamp(secs, nsecs)
    }
}

/// Parse a stream of journal lines (one JSON object per line).
///
/// Per the lesson from Task 3A.3 (skip-don't-fail when stream-parsing),
/// malformed lines are dropped silently; a single bad line never aborts
/// the whole parse.
pub fn parse_journalctl_json_lines(input: &str) -> Vec<JournalEntry> {
    let mut out = Vec::new();
    for raw in input.lines() {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
            continue;
        };
        let Some(ts_str) = v
            .get("__REALTIME_TIMESTAMP")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let Ok(ts) = ts_str.parse::<u64>() else {
            continue;
        };
        let unit = v
            .get("_SYSTEMD_UNIT")
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                v.get("SYSLOG_IDENTIFIER")
                    .and_then(serde_json::Value::as_str)
            })
            .or_else(|| v.get("_COMM").and_then(serde_json::Value::as_str))
            .unwrap_or("unknown")
            .to_string();
        let message = v
            .get("MESSAGE")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        let priority = v
            .get("PRIORITY")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse::<u8>().ok());
        let message_id = v
            .get("MESSAGE_ID")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        out.push(JournalEntry {
            timestamp_usec: ts,
            unit,
            message,
            priority,
            message_id,
        });
    }
    out
}

/// systemd-coredump's stable `MESSAGE_ID` UUID (no hyphens). Used to identify
/// crash entries in journal output.
pub const COREDUMP_MESSAGE_ID: &str = "fc2e22bc6ee647b6b90729ab34a250b1";

/// Heuristic: is this entry a crash? Either matches systemd-coredump's
/// MESSAGE_ID, or contains common crash keywords in the message body.
pub fn is_crash_entry(entry: &JournalEntry) -> bool {
    if entry.message_id.as_deref() == Some(COREDUMP_MESSAGE_ID) {
        return true;
    }
    let m = entry.message.to_ascii_lowercase();
    m.contains("segmentation fault")
        || m.contains("core-dump")
        || m.contains("core dumped")
        || m.contains("dumped core")
        || m.contains("oom-killer")
}

// ────────────────────────────────────────────────────────────────────
// dpkg-query output parsing
// ────────────────────────────────────────────────────────────────────

/// Parse default `dpkg-query -W` output (tab-separated `name<TAB>version`).
///
/// Tolerates blank lines and whitespace; rows missing the tab are skipped
/// per the skip-don't-fail rule.
pub fn parse_dpkg_query_lines(input: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in input.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let Some((name, version)) = line.split_once('\t') else {
            continue;
        };
        let name = name.trim();
        let version = version.trim();
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.push((name.to_string(), version.to_string()));
    }
    out
}

// ────────────────────────────────────────────────────────────────────
// Disk health monitor
// ────────────────────────────────────────────────────────────────────

/// Discovers block devices via `<sys_root>/block/`, runs `smartctl --json -A`
/// on each, evaluates findings against thresholds.
pub struct DiskHealthMonitor {
    sys_root: PathBuf,
}

impl Default for DiskHealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl DiskHealthMonitor {
    pub fn new() -> Self {
        Self {
            sys_root: PathBuf::from("/sys"),
        }
    }

    pub fn with_sys_root(sys_root: PathBuf) -> Self {
        Self { sys_root }
    }

    /// List candidate block devices (filters out loop, ram, dm, sr).
    pub fn list_block_devices(&self) -> Result<Vec<String>, OrchestratorError> {
        let dir = self.sys_root.join("block");
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => return Ok(Vec::new()),
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if name.starts_with("loop")
                || name.starts_with("ram")
                || name.starts_with("dm-")
                || name.starts_with("sr")
            {
                continue;
            }
            out.push(name);
        }
        out.sort();
        Ok(out)
    }

    /// Run smartctl on `<device_name>`. Returns `Fidelity::Unavailable` SmartAttrs
    /// when the binary is missing or returns a non-zero exit; otherwise parses
    /// the JSON output.
    pub fn smart_attrs_for(&self, device_name: &str) -> Result<SmartAttrs, OrchestratorError> {
        let dev_path = format!("/dev/{device_name}");
        let output = Command::new("smartctl")
            .args(["--json", "-A", &dev_path])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output();
        match output {
            Ok(o) if !o.stdout.is_empty() => {
                let text = String::from_utf8_lossy(&o.stdout);
                parse_smartctl_json(&text)
            }
            _ => Ok(SmartAttrs {
                fidelity: Fidelity::Unavailable,
                ..Default::default()
            }),
        }
    }

    /// Apply rule-based evaluation to SMART attributes, producing zero or
    /// more findings.
    pub fn evaluate(&self, device: &str, attrs: &SmartAttrs) -> Vec<HealthFinding> {
        let component = format!("disk:/dev/{device}");
        let mut findings = Vec::new();

        if let Some(reallocated) = attrs.reallocated_sectors
            && reallocated >= REALLOCATED_SECTORS_EMERGENCY
        {
            findings.push(HealthFinding::now(
                component.clone(),
                Severity::Critical,
                format!("disk has {reallocated} reallocated sectors"),
                "back up data and consider drive replacement".to_string(),
                attrs.fidelity,
            ));
        } else if let Some(reallocated) = attrs.reallocated_sectors
            && reallocated > 0
        {
            findings.push(HealthFinding::now(
                component.clone(),
                Severity::Warning,
                format!("disk has {reallocated} reallocated sectors"),
                "monitor closely; reallocations grow over time".to_string(),
                attrs.fidelity,
            ));
        }

        if let Some(pct) = attrs.percentage_used {
            if pct >= NVME_WEAR_EMERGENCY {
                findings.push(HealthFinding::now(
                    component.clone(),
                    Severity::Emergency,
                    format!("NVMe wear level {pct}% — replacement recommended"),
                    "back up immediately and source a replacement drive".to_string(),
                    attrs.fidelity,
                ));
            } else if pct >= 70 {
                findings.push(HealthFinding::now(
                    component.clone(),
                    Severity::Warning,
                    format!("NVMe wear level {pct}%"),
                    "begin planning drive replacement; back up regularly".to_string(),
                    attrs.fidelity,
                ));
            }
        }

        findings
    }

    /// One-shot probe: enumerate devices, query SMART, evaluate.
    /// Each device's failure does not stop the others.
    pub fn check(&self) -> Vec<HealthFinding> {
        let mut findings = Vec::new();
        let devices = match self.list_block_devices() {
            Ok(d) => d,
            Err(e) => {
                debug!("disk monitor list_block_devices failed: {e}");
                return findings;
            }
        };
        for device in devices {
            match self.smart_attrs_for(&device) {
                Ok(attrs) => {
                    if attrs.fidelity == Fidelity::Unavailable {
                        continue;
                    }
                    findings.extend(self.evaluate(&device, &attrs));
                }
                Err(e) => {
                    debug!("smartctl probe failed for {device}: {e}");
                }
            }
        }
        findings
    }
}

// ────────────────────────────────────────────────────────────────────
// Process memory leak monitor
// ────────────────────────────────────────────────────────────────────

/// Tracks per-PID RSS over time. A leak candidate is a process whose RSS
/// is monotonically non-decreasing across at least [`LEAK_MIN_SAMPLES`]
/// observations AND has grown by ≥ 10% over the window.
#[derive(Default)]
pub struct ProcessMemoryMonitor {
    series: HashMap<u32, VecDeque<u64>>,
    /// Process-friendly name keyed by pid for nicer findings.
    names: HashMap<u32, String>,
    max_samples: usize,
}

impl ProcessMemoryMonitor {
    pub fn new() -> Self {
        Self {
            series: HashMap::new(),
            names: HashMap::new(),
            max_samples: 60, // ~60 minutes at 1-sample/minute
        }
    }

    pub fn with_window(max_samples: usize) -> Self {
        Self {
            series: HashMap::new(),
            names: HashMap::new(),
            max_samples: max_samples.max(LEAK_MIN_SAMPLES),
        }
    }

    /// Record an observation. Caller is responsible for periodicity.
    pub fn record_sample(&mut self, pid: u32, name: &str, rss_kb: u64) {
        let series = self.series.entry(pid).or_default();
        if series.len() == self.max_samples {
            series.pop_front();
        }
        series.push_back(rss_kb);
        self.names.insert(pid, name.to_string());
    }

    /// `true` iff the series is non-decreasing AND last is at least 10%
    /// larger than first.
    pub fn is_leak_candidate(&self, pid: u32) -> bool {
        let Some(series) = self.series.get(&pid) else {
            return false;
        };
        if series.len() < LEAK_MIN_SAMPLES {
            return false;
        }
        let mut iter = series.iter().copied();
        let Some(mut prev) = iter.next() else {
            return false;
        };
        let first = prev;
        for v in iter {
            if v < prev {
                return false;
            }
            prev = v;
        }
        let last = prev;
        if first == 0 {
            // Avoid div-by-zero: any growth from zero counts as a leak.
            return last > 0;
        }
        (last as f64 - first as f64) / (first as f64) >= 0.10
    }

    /// Emit findings for every PID that currently looks like a leak.
    pub fn check(&self) -> Vec<HealthFinding> {
        let mut findings = Vec::new();
        for &pid in self.series.keys() {
            if !self.is_leak_candidate(pid) {
                continue;
            }
            let name = self
                .names
                .get(&pid)
                .map(String::as_str)
                .unwrap_or("unknown");
            let series = &self.series[&pid];
            let first = *series.front().unwrap_or(&0);
            let last = *series.back().unwrap_or(&0);
            let finding = HealthFinding::now(
                format!("process:{name}({pid})"),
                Severity::Warning,
                format!(
                    "RSS grew from {first} kB → {last} kB across {} samples",
                    series.len()
                ),
                "investigate; consider restarting the process".to_string(),
                Fidelity::Direct,
            )
            .with_baseline_context(format!(
                "monotonic non-decreasing series, growth {:.1}%",
                ((last as f64 - first as f64) / (first.max(1) as f64)) * 100.0
            ));
            findings.push(finding);
        }
        findings
    }
}

// ────────────────────────────────────────────────────────────────────
// Crash monitor
// ────────────────────────────────────────────────────────────────────

/// Aggregate crashes per unit across a journal window.
pub struct CrashMonitor;

impl Default for CrashMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl CrashMonitor {
    pub fn new() -> Self {
        Self
    }

    /// Aggregate crashes from already-parsed journal entries. Pure function;
    /// system-touching probes call this with subprocess output.
    pub fn aggregate(&self, entries: &[JournalEntry]) -> Vec<HealthFinding> {
        let mut counts: HashMap<&str, (u32, &str)> = HashMap::new();
        for entry in entries {
            if !is_crash_entry(entry) {
                continue;
            }
            let entry_count = counts.entry(entry.unit.as_str()).or_insert((0, ""));
            entry_count.0 += 1;
            entry_count.1 = entry.message.as_str();
        }
        let mut findings = Vec::new();
        for (unit, (count, last_msg)) in counts {
            let severity = if count >= 5 {
                Severity::Critical
            } else if count >= 2 {
                Severity::Warning
            } else {
                Severity::Info
            };
            findings.push(HealthFinding::now(
                format!("process:{unit}"),
                severity,
                format!("{count} crash event(s) recorded; last: {last_msg}"),
                "check application logs and recent updates".to_string(),
                Fidelity::Subprocess,
            ));
        }
        findings.sort_by(|a, b| a.component.cmp(&b.component));
        findings
    }

    /// Probe live journal for the last N minutes and aggregate.
    pub fn check_recent(&self, since_minutes: u64) -> Vec<HealthFinding> {
        let arg = format!("{since_minutes} min ago");
        let output = Command::new("journalctl")
            .args([
                "--since",
                &arg,
                "--output=json",
                "--no-pager",
                "--quiet",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output();
        let Ok(o) = output else { return Vec::new() };
        if !o.status.success() {
            return Vec::new();
        }
        let text = String::from_utf8_lossy(&o.stdout);
        let entries = parse_journalctl_json_lines(&text);
        self.aggregate(&entries)
    }
}

// ────────────────────────────────────────────────────────────────────
// Dependency vulnerability monitor
// ────────────────────────────────────────────────────────────────────

/// In-memory map of `package name → set of vulnerable versions`. Real-world
/// refresh from a CVE feed is out of scope for this task; ship the comparison
/// engine, leave the refresh path as a future hook.
#[derive(Debug, Clone, Default)]
pub struct KnownVulnerableDatabase {
    pub vulnerabilities: HashMap<String, HashSet<String>>,
}

impl KnownVulnerableDatabase {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, package: &str, version: &str) {
        self.vulnerabilities
            .entry(package.to_string())
            .or_default()
            .insert(version.to_string());
    }

    pub fn is_vulnerable(&self, package: &str, version: &str) -> bool {
        self.vulnerabilities
            .get(package)
            .is_some_and(|set| set.contains(version))
    }
}

#[derive(Default)]
pub struct DependencyMonitor {
    pub known_vulnerable: KnownVulnerableDatabase,
}

impl DependencyMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pure check: given an installed-package list, emit a finding per
    /// vulnerable match.
    pub fn evaluate(&self, installed: &[(String, String)]) -> Vec<HealthFinding> {
        let mut findings = Vec::new();
        for (pkg, ver) in installed {
            if !self.known_vulnerable.is_vulnerable(pkg, ver) {
                continue;
            }
            findings.push(HealthFinding::now(
                format!("package:{pkg}"),
                Severity::Critical,
                format!("{pkg} {ver} has a known vulnerability"),
                "upgrade or remove the package".to_string(),
                Fidelity::Subprocess,
            ));
        }
        findings.sort_by(|a, b| a.component.cmp(&b.component));
        findings
    }

    /// Live probe: shell out to dpkg-query, evaluate.
    pub fn check(&self) -> Vec<HealthFinding> {
        let output = Command::new("dpkg-query")
            .args(["-W"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output();
        let Ok(o) = output else { return Vec::new() };
        if !o.status.success() {
            return Vec::new();
        }
        let text = String::from_utf8_lossy(&o.stdout);
        let installed = parse_dpkg_query_lines(&text);
        self.evaluate(&installed)
    }
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ── Severity ordering ─────────────────────────────────────────────

    #[test]
    fn severity_ordering_matches_variant_order() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Critical);
        assert!(Severity::Critical < Severity::Emergency);
    }

    #[test]
    fn severity_strings_are_stable() {
        assert_eq!(Severity::Info.as_str(), "info");
        assert_eq!(Severity::Warning.as_str(), "warning");
        assert_eq!(Severity::Critical.as_str(), "critical");
        assert_eq!(Severity::Emergency.as_str(), "emergency");
    }

    // ── HealthFinding ────────────────────────────────────────────────

    #[test]
    fn health_finding_constructs_with_now() {
        let f = HealthFinding::now(
            "disk:/dev/sda",
            Severity::Warning,
            "msg",
            "rec",
            Fidelity::Direct,
        );
        assert_eq!(f.component, "disk:/dev/sda");
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.baseline_context.is_none());
    }

    #[test]
    fn health_finding_json_round_trip() {
        let f = HealthFinding::now(
            "disk:/dev/sda",
            Severity::Critical,
            "test",
            "test",
            Fidelity::Subprocess,
        )
        .with_baseline_context("normal: 0, observed: 100");
        let s = serde_json::to_string(&f).unwrap();
        let parsed: HealthFinding = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed, f);
        assert_eq!(parsed.fidelity, Fidelity::Subprocess);
        assert_eq!(parsed.baseline_context.as_deref(), Some("normal: 0, observed: 100"));
    }

    // ── Baseline ──────────────────────────────────────────────────────

    #[test]
    fn baseline_pushes_within_window() {
        let mut b = Baseline::new(3);
        b.push(1.0);
        b.push(2.0);
        b.push(3.0);
        b.push(4.0); // evicts 1.0
        assert_eq!(b.len(), 3);
        assert_eq!(b.median(), Some(3.0));
    }

    #[test]
    fn baseline_median_odd_count() {
        let mut b = Baseline::new(10);
        b.push(1.0);
        b.push(2.0);
        b.push(3.0);
        assert_eq!(b.median(), Some(2.0));
    }

    #[test]
    fn baseline_median_even_count() {
        let mut b = Baseline::new(10);
        b.push(1.0);
        b.push(2.0);
        b.push(3.0);
        b.push(4.0);
        assert_eq!(b.median(), Some(2.5));
    }

    #[test]
    fn baseline_std_dev_zero_when_all_same() {
        let mut b = Baseline::new(5);
        for _ in 0..5 {
            b.push(50.0);
        }
        assert_eq!(b.std_dev(), Some(0.0));
    }

    #[test]
    fn baseline_is_anomalous_within_threshold() {
        let mut b = Baseline::new(10);
        // 9 samples around 50, then test value 55 against 3-sigma
        for _ in 0..9 {
            b.push(50.0);
        }
        b.push(51.0);
        // std_dev is small but value 55 is many sigmas away
        assert!(b.is_anomalous(55.0, 3.0));
        // value at exactly the median is not anomalous
        assert!(!b.is_anomalous(50.0, 3.0));
    }

    #[test]
    fn baseline_is_anomalous_zero_stddev_treats_any_diff_as_anomaly() {
        let mut b = Baseline::new(5);
        for _ in 0..5 {
            b.push(50.0);
        }
        assert!(b.is_anomalous(50.001, 3.0));
        assert!(!b.is_anomalous(50.0, 3.0));
    }

    #[test]
    fn baseline_has_sufficient_history_at_threshold() {
        let mut b = Baseline::new(200);
        for _ in 0..(BASELINE_SUFFICIENT_THRESHOLD - 1) {
            b.push(1.0);
        }
        assert!(!b.has_sufficient_history());
        b.push(1.0); // exactly at threshold
        assert!(b.has_sufficient_history());
    }

    // ── parse_smartctl_json ───────────────────────────────────────────

    #[test]
    fn parse_smartctl_json_extracts_ata_attrs() {
        let body = r#"{
            "power_on_time": {"hours": 1234},
            "ata_smart_attributes": {
                "table": [
                    {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 7}},
                    {"id": 177, "name": "Wear_Leveling_Count", "raw": {"value": 90}},
                    {"id": 194, "name": "Temperature_Celsius", "raw": {"value": 42}}
                ]
            }
        }"#;
        let attrs = parse_smartctl_json(body).unwrap();
        assert_eq!(attrs.power_on_hours, Some(1234));
        assert_eq!(attrs.reallocated_sectors, Some(7));
        assert_eq!(attrs.wear_leveling_count, Some(90));
        assert_eq!(attrs.temperature_celsius, Some(42.0));
        assert_eq!(attrs.fidelity, Fidelity::Subprocess);
    }

    #[test]
    fn parse_smartctl_json_extracts_nvme_pct_used() {
        let body = r#"{"nvme_smart_health_information_log": {"percentage_used": 30}}"#;
        let attrs = parse_smartctl_json(body).unwrap();
        assert_eq!(attrs.percentage_used, Some(30));
    }

    #[test]
    fn parse_smartctl_json_tolerates_missing_fields() {
        let body = r#"{"smartctl": {"version": "x"}}"#;
        let attrs = parse_smartctl_json(body).unwrap();
        assert!(attrs.power_on_hours.is_none());
        assert!(attrs.reallocated_sectors.is_none());
    }

    #[test]
    fn parse_smartctl_json_errors_on_malformed() {
        assert!(parse_smartctl_json("not json").is_err());
    }

    #[test]
    fn parse_smartctl_json_falls_back_to_temperature_current() {
        let body = r#"{"temperature": {"current": 38}}"#;
        let attrs = parse_smartctl_json(body).unwrap();
        assert_eq!(attrs.temperature_celsius, Some(38.0));
    }

    // ── parse_proc_status_for_rss ─────────────────────────────────────

    #[test]
    fn parse_proc_status_for_rss_extracts_kb() {
        let body = "Name:\tfirefox\nState:\tS (sleeping)\nVmRSS:\t  524288 kB\nVmSize:\t1048576 kB\n";
        assert_eq!(parse_proc_status_for_rss(body), Some(524288));
    }

    #[test]
    fn parse_proc_status_for_rss_returns_none_when_absent() {
        let body = "Name:\tkthread\nVmSize:\t0 kB\n";
        assert_eq!(parse_proc_status_for_rss(body), None);
    }

    // ── parse_journalctl_json_lines ───────────────────────────────────

    #[test]
    fn journalctl_parser_extracts_unit_and_message() {
        let body = r#"{"__REALTIME_TIMESTAMP":"1700000000000000","_SYSTEMD_UNIT":"foo.service","MESSAGE":"hello"}"#;
        let entries = parse_journalctl_json_lines(body);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].unit, "foo.service");
        assert_eq!(entries[0].message, "hello");
        assert_eq!(entries[0].timestamp_usec, 1_700_000_000_000_000);
    }

    #[test]
    fn journalctl_parser_skips_malformed_lines() {
        let body = "garbage line\n\
                    {\"__REALTIME_TIMESTAMP\":\"1\",\"_SYSTEMD_UNIT\":\"x\",\"MESSAGE\":\"ok\"}\n\
                    not json either\n";
        let entries = parse_journalctl_json_lines(body);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "ok");
    }

    #[test]
    fn journalctl_parser_falls_back_for_unit() {
        let body = r#"{"__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"kernel","MESSAGE":"hi"}"#;
        let entries = parse_journalctl_json_lines(body);
        assert_eq!(entries[0].unit, "kernel");
    }

    #[test]
    fn is_crash_entry_detects_coredump_message_id() {
        let entry = JournalEntry {
            timestamp_usec: 0,
            unit: "x".into(),
            message: "process exited".into(),
            priority: None,
            message_id: Some(COREDUMP_MESSAGE_ID.to_string()),
        };
        assert!(is_crash_entry(&entry));
    }

    #[test]
    fn is_crash_entry_detects_oom_killer_message() {
        let entry = JournalEntry {
            timestamp_usec: 0,
            unit: "x".into(),
            message: "Out of memory: invoked oom-killer for foo".into(),
            priority: None,
            message_id: None,
        };
        assert!(is_crash_entry(&entry));
    }

    #[test]
    fn is_crash_entry_negative_for_normal_log() {
        let entry = JournalEntry {
            timestamp_usec: 0,
            unit: "x".into(),
            message: "task started normally".into(),
            priority: None,
            message_id: None,
        };
        assert!(!is_crash_entry(&entry));
    }

    // ── parse_dpkg_query_lines ────────────────────────────────────────

    #[test]
    fn parse_dpkg_query_lines_typical_output() {
        let body = "aardvark-dns\t1.4.0-5\nadduser\t3.137ubuntu1\nzsh\t5.9-6ubuntu2\n";
        let pkgs = parse_dpkg_query_lines(body);
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs[0], ("aardvark-dns".to_string(), "1.4.0-5".to_string()));
        assert_eq!(pkgs[2], ("zsh".to_string(), "5.9-6ubuntu2".to_string()));
    }

    #[test]
    fn parse_dpkg_query_lines_skips_malformed() {
        let body = "ok\t1.0\nno-tab-here\n\nanother\t2.0\n";
        let pkgs = parse_dpkg_query_lines(body);
        assert_eq!(pkgs.len(), 2);
    }

    // ── DiskHealthMonitor ─────────────────────────────────────────────

    #[test]
    fn list_block_devices_filters_loops_and_rams() {
        let tmp = TempDir::new().unwrap();
        let block = tmp.path().join("block");
        for n in &["loop0", "loop1", "ram0", "sda", "sdb", "dm-0", "sr0", "nvme0n1"] {
            fs::create_dir_all(block.join(n)).unwrap();
        }
        let mon = DiskHealthMonitor::with_sys_root(tmp.path().to_path_buf());
        let devs = mon.list_block_devices().unwrap();
        assert_eq!(devs, vec!["nvme0n1".to_string(), "sda".to_string(), "sdb".to_string()]);
    }

    #[test]
    fn list_block_devices_handles_missing_dir() {
        let tmp = TempDir::new().unwrap();
        let mon = DiskHealthMonitor::with_sys_root(tmp.path().to_path_buf());
        assert_eq!(mon.list_block_devices().unwrap(), Vec::<String>::new());
    }

    #[test]
    fn evaluate_high_reallocated_sectors_triggers_critical() {
        let mon = DiskHealthMonitor::new();
        let mut attrs = SmartAttrs {
            reallocated_sectors: Some(150),
            fidelity: Fidelity::Subprocess,
            ..Default::default()
        };
        let findings = mon.evaluate("sda", &attrs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].component, "disk:/dev/sda");
        assert_eq!(findings[0].fidelity, Fidelity::Subprocess);

        // Below emergency threshold but nonzero → Warning
        attrs.reallocated_sectors = Some(5);
        let findings = mon.evaluate("sda", &attrs);
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn evaluate_high_nvme_wear_triggers_emergency() {
        let mon = DiskHealthMonitor::new();
        let attrs = SmartAttrs {
            percentage_used: Some(95),
            fidelity: Fidelity::Subprocess,
            ..Default::default()
        };
        let findings = mon.evaluate("nvme0n1", &attrs);
        assert_eq!(findings[0].severity, Severity::Emergency);
        assert!(findings[0].message.contains("95"));
    }

    #[test]
    fn evaluate_clean_disk_yields_no_findings() {
        let mon = DiskHealthMonitor::new();
        let attrs = SmartAttrs {
            reallocated_sectors: Some(0),
            percentage_used: Some(5),
            fidelity: Fidelity::Subprocess,
            ..Default::default()
        };
        let findings = mon.evaluate("sda", &attrs);
        assert!(findings.is_empty());
    }

    #[test]
    fn evaluate_fidelity_propagates_to_findings() {
        let mon = DiskHealthMonitor::new();
        let attrs = SmartAttrs {
            reallocated_sectors: Some(50),
            fidelity: Fidelity::Direct,
            ..Default::default()
        };
        let findings = mon.evaluate("sda", &attrs);
        assert_eq!(findings[0].fidelity, Fidelity::Direct);
    }

    // ── ProcessMemoryMonitor ──────────────────────────────────────────

    #[test]
    fn process_memory_monitor_classifies_monotonic_climb_as_leak() {
        let mut m = ProcessMemoryMonitor::new();
        let pid = 42;
        for kb in [100, 110, 120, 130, 140, 150] {
            m.record_sample(pid, "leaky", kb);
        }
        assert!(m.is_leak_candidate(pid));
        let findings = m.check();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(findings[0].component.contains("leaky"));
    }

    #[test]
    fn process_memory_monitor_climbing_then_flat_not_leak() {
        let mut m = ProcessMemoryMonitor::new();
        let pid = 42;
        // climb then plateau — first/last delta < 10%
        for kb in [100, 102, 104, 105, 105, 105] {
            m.record_sample(pid, "stable", kb);
        }
        assert!(!m.is_leak_candidate(pid));
    }

    #[test]
    fn process_memory_monitor_decreasing_not_leak() {
        let mut m = ProcessMemoryMonitor::new();
        let pid = 42;
        for kb in [200, 200, 200, 199, 200, 200] {
            m.record_sample(pid, "freed", kb);
        }
        assert!(!m.is_leak_candidate(pid));
    }

    #[test]
    fn process_memory_monitor_insufficient_samples_returns_no_finding() {
        let mut m = ProcessMemoryMonitor::new();
        for kb in [100, 200, 300, 400, 500] {
            m.record_sample(7, "early", kb);
        }
        assert!(!m.is_leak_candidate(7));
        assert!(m.check().is_empty());
    }

    // ── CrashMonitor ──────────────────────────────────────────────────

    #[test]
    fn crash_monitor_aggregates_per_unit() {
        let mon = CrashMonitor::new();
        let entries = vec![
            JournalEntry {
                timestamp_usec: 1,
                unit: "alpha.service".into(),
                message: "Segmentation fault".into(),
                priority: Some(3),
                message_id: None,
            },
            JournalEntry {
                timestamp_usec: 2,
                unit: "alpha.service".into(),
                message: "core-dump".into(),
                priority: Some(3),
                message_id: None,
            },
            JournalEntry {
                timestamp_usec: 3,
                unit: "beta.service".into(),
                message: "Out of memory: oom-killer".into(),
                priority: Some(3),
                message_id: None,
            },
            JournalEntry {
                timestamp_usec: 4,
                unit: "ignored".into(),
                message: "normal startup".into(),
                priority: Some(6),
                message_id: None,
            },
        ];
        let findings = mon.aggregate(&entries);
        assert_eq!(findings.len(), 2);
        // sort is by component, so alpha first, beta second
        assert!(findings[0].component.contains("alpha"));
        assert!(findings[0].message.contains("2 crash"));
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(findings[1].component.contains("beta"));
        assert_eq!(findings[1].severity, Severity::Info);
    }

    #[test]
    fn crash_monitor_high_crash_count_critical() {
        let mon = CrashMonitor::new();
        let entries: Vec<JournalEntry> = (0..6)
            .map(|i| JournalEntry {
                timestamp_usec: i,
                unit: "z.service".into(),
                message: "Segmentation fault".into(),
                priority: None,
                message_id: None,
            })
            .collect();
        let findings = mon.aggregate(&entries);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    // ── DependencyMonitor ─────────────────────────────────────────────

    #[test]
    fn dependency_monitor_flags_known_vulnerable() {
        let mut db = KnownVulnerableDatabase::new();
        db.add("openssl", "1.0.1-broken");
        let mon = DependencyMonitor {
            known_vulnerable: db,
        };
        let installed = vec![
            ("openssl".to_string(), "1.0.1-broken".to_string()),
            ("safe-pkg".to_string(), "2.0".to_string()),
        ];
        let findings = mon.evaluate(&installed);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].component.contains("openssl"));
    }

    #[test]
    fn dependency_monitor_unknown_package_not_flagged() {
        let mon = DependencyMonitor::new();
        let installed = vec![("foo".to_string(), "1.0".to_string())];
        assert!(mon.evaluate(&installed).is_empty());
    }

    #[test]
    fn dependency_monitor_same_pkg_different_version_not_flagged() {
        let mut db = KnownVulnerableDatabase::new();
        db.add("openssl", "1.0.1-broken");
        let mon = DependencyMonitor {
            known_vulnerable: db,
        };
        let installed = vec![("openssl".to_string(), "1.0.2-fixed".to_string())];
        assert!(mon.evaluate(&installed).is_empty());
    }

    #[test]
    fn known_vulnerable_database_independent_packages() {
        let mut db = KnownVulnerableDatabase::new();
        db.add("a", "1");
        db.add("b", "1");
        assert!(db.is_vulnerable("a", "1"));
        assert!(db.is_vulnerable("b", "1"));
        assert!(!db.is_vulnerable("a", "2"));
        assert!(!db.is_vulnerable("c", "1"));
    }
}

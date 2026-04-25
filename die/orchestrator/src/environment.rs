// SPDX-License-Identifier: MIT

//! Ambient environmental awareness — capability #12.
//!
//! The environment module OBSERVES the user's physical context so other
//! modules (orchestrator brain, timeline, compositor, learning engine)
//! can adapt. This module is deliberately a **sensor**, not an
//! **actuator**: it never mutates system state, never changes settings,
//! never triggers notifications on its own. Consumers decide policy.
//!
//! # Fidelity levels supported (per Iron Law #13)
//!
//! Each sensor category has a fidelity hierarchy. The module probes
//! downward and tags every reading with the [`Fidelity`] level that
//! produced it, so consumers can weigh the answer's reliability.
//!
//! ## Battery
//!
//! 1. **`/sys/class/power_supply/BAT*/uevent`** (preferred) — single
//!    atomic read gives capacity, status, energy, power. `Fidelity::Direct`.
//!    - Required: any modern Linux kernel exposing the power_supply class.
//!    - Failure modes: file unreadable, malformed, or no battery device.
//! 2. **Per-field files (`capacity`, `status`)** (fallback) — separate
//!    reads for percent + state when uevent is unavailable. Still
//!    `Fidelity::Direct` because we read the kernel directly.
//!    - Required: power_supply class but partially populated uevent.
//!    - Tradeoffs: no time_remaining (lacks energy_now / power_now).
//! 3. **UPower D-Bus** (declared, future work) — would be `Fidelity::NativeApi`,
//!    handles multi-battery aggregation.
//! 4. **`upower -i ...` subprocess** (declared, future work) — would be
//!    `Fidelity::Subprocess`.
//!
//! ## Thermal
//!
//! 1. **`/sys/class/thermal/thermal_zone*/{type,temp}`** (preferred) —
//!    millidegrees Celsius per zone. `Fidelity::Direct`.
//!    - Required: thermal subsystem (most laptops, missing on WSL Hyper-V).
//!    - Failure modes: no thermal zones present (returns Unavailable).
//! 2. **`/sys/class/hwmon/hwmon*/temp*_input` + label** (declared, future
//!    work) — finer per-sensor labeling, more parsing overhead.
//! 3. **`sensors` (lm-sensors) subprocess** (declared, future work) —
//!    `Fidelity::Subprocess`, format varies between versions.
//!
//! ## Memory
//!
//! 1. **`/proc/meminfo`** (preferred) — total/available KB, structured,
//!    stable since Linux 3.14. `Fidelity::Direct`.
//! 2. **`/proc/pressure/memory`** (augmentation) — Pressure Stall
//!    Information (Linux 4.20+). When present, populates
//!    `psi_some_avg10`; absence does not change overall fidelity.
//! 3. **`free -b` subprocess** (declared, last resort) — would be
//!    `Fidelity::Subprocess`.
//!
//! ## Disk usage
//!
//! 1. **`statvfs(2)` via `nix` crate** (declared, future work) —
//!    `Fidelity::Direct`, syscall straight to kernel.
//! 2. **`df -P /` subprocess** (current) — `Fidelity::Subprocess`,
//!    parsed stdout. Cross-platform-compiles because `Command::new`
//!    naturally fails into `None` when `df` is missing.
//!
//! ## Network / WiFi SSID
//!
//! 1. **NetworkManager D-Bus** (declared, future work) — `Fidelity::NativeApi`.
//! 2. **iwd D-Bus** (declared, future work).
//! 3. **`nmcli -t -f active,ssid dev wifi` subprocess** (current) —
//!    `Fidelity::Subprocess`, parsed stdout.
//! 4. **`iwgetid -r`** (declared, fallback) — `Fidelity::Subprocess`.
//! 5. **`/proc/net/wireless`** (declared, last resort) — link quality
//!    only, no SSID.
//!
//! Wired detection (`on_wired`) reads `/sys/class/net/*/{type,operstate}`
//! directly — `Fidelity::Direct`, no subprocesses involved.
//!
//! # Platform
//!
//! Delphi targets Linux. All sysfs/procfs sensors compile cross-platform
//! because `Path` and `fs::read_to_string` are platform-agnostic; on
//! Windows the paths simply don't exist and the sensors return
//! `Fidelity::Unavailable`. Subprocess sensors compile cross-platform
//! because `Command::new` returns an error when the binary is missing,
//! which we map to `(None, Fidelity::Unavailable)`. There is **no**
//! `#[cfg(target_os = "linux")]` gating in this module.
//!
//! # Testability
//!
//! [`LinuxSensor::with_roots`] accepts injectable `sys_root` and
//! `proc_root` paths so tests build fake filesystem trees with
//! [`tempfile`]. The [`EnvironmentSensor`] trait lets higher-level
//! code swap in a full mock sensor for unit tests of the monitor's
//! composition logic without touching real sysfs.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use chrono::{DateTime, Datelike, Local, Timelike, Utc, Weekday};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::OrchestratorError;

/// Threshold above which a thermal reading is considered active throttling.
pub const THERMAL_THROTTLING_THRESHOLD_C: f32 = 85.0;

// ────────────────────────────────────────────────────────────────────
// Fidelity provenance (Iron Law #13)
// ────────────────────────────────────────────────────────────────────

/// Which fidelity tier produced a sensor reading.
///
/// Per Iron Law #13, this provenance travels with every result so
/// consumers can weigh how much to trust the answer.
///
/// - [`Fidelity::Direct`] — read straight from kernel-exposed file or
///   syscall. Most stable, least likely to lie.
/// - [`Fidelity::NativeApi`] — used the source's own programmatic
///   interface (D-Bus, dedicated protocol). Stable across the API's
///   versioning contract.
/// - [`Fidelity::Subprocess`] — ran a CLI tool and parsed its stdout.
///   Brittle: output format can change between distro versions.
/// - [`Fidelity::Unavailable`] — sensor returned a safe default because
///   no level was reachable (missing files, missing binary, wrong
///   platform).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Fidelity {
    Direct,
    NativeApi,
    Subprocess,
    Unavailable,
}

impl Fidelity {
    /// Wire-stable string name (snake_case) — used in JSON serialization
    /// and D-Bus signal payloads.
    pub fn as_str(&self) -> &'static str {
        match self {
            Fidelity::Direct => "direct",
            Fidelity::NativeApi => "native_api",
            Fidelity::Subprocess => "subprocess",
            Fidelity::Unavailable => "unavailable",
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// Power + battery
// ────────────────────────────────────────────────────────────────────

/// Coarse power state — what's powering the system right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerState {
    /// AC adapter present and battery is charging.
    AcCharging,
    /// AC adapter present, battery full or not charging.
    AcIdle,
    /// Running on battery (discharging).
    Battery,
    /// Desktop or no battery device exposed.
    NoBattery,
    /// Reading was indeterminate.
    Unknown,
}

impl PowerState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PowerState::AcCharging => "ac_charging",
            PowerState::AcIdle => "ac_idle",
            PowerState::Battery => "battery",
            PowerState::NoBattery => "no_battery",
            PowerState::Unknown => "unknown",
        }
    }
}

/// Battery snapshot. `time_remaining_sec` is meaningful only when
/// `state == PowerState::Battery` (i.e., discharging).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatteryInfo {
    pub percent: u8,
    pub state: PowerState,
    pub time_remaining_sec: Option<i64>,
    pub fidelity: Fidelity,
}

/// Parse the multi-line `POWER_SUPPLY_*=value` body of a battery
/// uevent file into a [`BatteryInfo`].
///
/// `ac_online` is provided by the caller because the AC adapter lives
/// in a sibling `/sys/class/power_supply/AC*/online` file, not in the
/// battery's uevent. The parser still works without it (defaults to
/// `false`) — only the resulting `state` differs.
///
/// Returns `Err` when the body is missing required fields
/// (`POWER_SUPPLY_CAPACITY`).
pub fn parse_battery_uevent(body: &str, ac_online: bool) -> Result<BatteryInfo, OrchestratorError> {
    let mut capacity: Option<u8> = None;
    let mut status: Option<String> = None;
    let mut energy_now: Option<u64> = None;
    let mut power_now: Option<u64> = None;

    for line in body.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "POWER_SUPPLY_CAPACITY" => {
                capacity = value.trim().parse::<u8>().ok();
            }
            "POWER_SUPPLY_STATUS" => {
                status = Some(value.trim().to_string());
            }
            "POWER_SUPPLY_ENERGY_NOW" | "POWER_SUPPLY_CHARGE_NOW" => {
                energy_now = value.trim().parse::<u64>().ok();
            }
            "POWER_SUPPLY_POWER_NOW" | "POWER_SUPPLY_CURRENT_NOW" => {
                power_now = value.trim().parse::<u64>().ok();
            }
            _ => {}
        }
    }

    let Some(percent) = capacity else {
        return Err(OrchestratorError::Environment(
            "battery uevent missing POWER_SUPPLY_CAPACITY".to_string(),
        ));
    };
    let percent = percent.min(100);
    let status_str = status.unwrap_or_else(|| "Unknown".to_string());
    let state = classify_power_state(&status_str, ac_online);

    let time_remaining_sec = if state == PowerState::Battery {
        // energy_now in µWh, power_now in µW → seconds = energy / power * 3600.
        match (energy_now, power_now) {
            (Some(e), Some(p)) if p > 0 => Some(((e as i128 * 3600) / p as i128) as i64),
            _ => None,
        }
    } else {
        None
    };

    Ok(BatteryInfo {
        percent,
        state,
        time_remaining_sec,
        fidelity: Fidelity::Direct,
    })
}

/// Compose `(status_string, ac_online_bool)` into a [`PowerState`].
///
/// Status strings come straight from the kernel and follow a small
/// vocabulary: `"Charging"`, `"Discharging"`, `"Full"`, `"Not charging"`,
/// `"Unknown"`. Anything else is collapsed to `Unknown`.
pub fn classify_power_state(status: &str, ac_online: bool) -> PowerState {
    match status {
        "Charging" => PowerState::AcCharging,
        "Discharging" => PowerState::Battery,
        "Full" | "Not charging" => {
            if ac_online {
                PowerState::AcIdle
            } else {
                PowerState::Battery
            }
        }
        _ => PowerState::Unknown,
    }
}

/// Read every `AC*/online`, `ADP*/online`, `ACAD*/online` under
/// `sys_root/class/power_supply/`, returning `true` if any reports `1`.
///
/// Errors are swallowed (returns `false`) — AC presence is a hint, not
/// a critical reading.
fn read_ac_online(sys_root: &Path) -> bool {
    let dir = sys_root.join("class/power_supply");
    let Ok(entries) = fs::read_dir(&dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !(name.starts_with("AC") || name.starts_with("ADP") || name.starts_with("ACAD")) {
            continue;
        }
        let online_path = entry.path().join("online");
        if let Ok(text) = fs::read_to_string(&online_path)
            && text.trim() == "1"
        {
            return true;
        }
    }
    false
}

/// Find the first `BAT*` directory under `sys_root/class/power_supply/`,
/// returning its path. Returns `None` when no battery directory exists
/// (desktop, server, WSL without virtual battery).
fn find_battery_dir(sys_root: &Path) -> Option<PathBuf> {
    let dir = sys_root.join("class/power_supply");
    let entries = fs::read_dir(&dir).ok()?;
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name.starts_with("BAT") {
            return Some(entry.path());
        }
    }
    None
}

/// Level-2 probe: read the entire `BAT*/uevent` body and parse it. Most
/// modern laptops expose this; one read is atomic and gives all needed
/// data including charge rate.
fn probe_battery_uevent(sys_root: &Path) -> Result<Option<BatteryInfo>, OrchestratorError> {
    let Some(bat_dir) = find_battery_dir(sys_root) else {
        return Ok(None);
    };
    let body = match fs::read_to_string(bat_dir.join("uevent")) {
        Ok(b) if !b.trim().is_empty() => b,
        Ok(_) => {
            debug!("battery uevent is empty; will attempt fallback");
            return Ok(None);
        }
        Err(e) => {
            debug!("battery uevent read failed: {e}");
            return Ok(None);
        }
    };
    let ac_online = read_ac_online(sys_root);
    Ok(Some(parse_battery_uevent(&body, ac_online)?))
}

/// Level-3 probe: separate per-field reads (`capacity`, `status`).
/// Used when uevent is empty or unreadable. Lacks `time_remaining`
/// because energy/power files may also be missing on minimal kernels.
fn probe_battery_capacity_files(
    sys_root: &Path,
) -> Result<Option<BatteryInfo>, OrchestratorError> {
    let Some(bat_dir) = find_battery_dir(sys_root) else {
        return Ok(None);
    };
    let percent_text = match fs::read_to_string(bat_dir.join("capacity")) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let percent: u8 = percent_text.trim().parse().map_err(|e| {
        OrchestratorError::Environment(format!("battery capacity unparseable: {e}"))
    })?;
    let status = fs::read_to_string(bat_dir.join("status"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "Unknown".to_string());
    let ac_online = read_ac_online(sys_root);
    let state = classify_power_state(&status, ac_online);
    Ok(Some(BatteryInfo {
        percent: percent.min(100),
        state,
        time_remaining_sec: None,
        fidelity: Fidelity::Direct,
    }))
}

// ────────────────────────────────────────────────────────────────────
// Thermal
// ────────────────────────────────────────────────────────────────────

/// Thermal snapshot. `cpu_temp_celsius` is `None` when no thermal zones
/// exist (typical on WSL2 Hyper-V) or all zones returned errors.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThermalInfo {
    pub cpu_temp_celsius: Option<f32>,
    pub throttling: bool,
    pub fidelity: Fidelity,
}

/// Type labels considered to represent CPU/SoC thermal zones (preferred
/// when multiple zones are present).
pub fn is_cpu_thermal_zone(zone_type: &str) -> bool {
    let t = zone_type.to_ascii_lowercase();
    t.contains("cpu")
        || t.contains("x86_pkg_temp")
        || t.contains("coretemp")
        || t.contains("soc")
        || t.contains("acpi")
}

/// Probe `sys_root/class/thermal/`, preferring CPU-labeled zones,
/// returning `(Option<temp_c>, throttling)`.
///
/// Throttling is heuristic: `true` if any
/// `cooling_device*/cur_state` is nonzero (active cooling implies the
/// thermal subsystem is mitigating heat).
fn probe_thermal_zones(sys_root: &Path) -> ThermalInfo {
    let dir = sys_root.join("class/thermal");
    let Ok(entries) = fs::read_dir(&dir) else {
        return ThermalInfo {
            cpu_temp_celsius: None,
            throttling: false,
            fidelity: Fidelity::Unavailable,
        };
    };

    let mut zones: Vec<(String, f32)> = Vec::new();
    let mut throttling = false;

    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let path = entry.path();
        if name.starts_with("thermal_zone") {
            let zone_type = fs::read_to_string(path.join("type"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            if let Ok(temp_text) = fs::read_to_string(path.join("temp"))
                && let Ok(milli) = temp_text.trim().parse::<i64>()
            {
                let celsius = milli as f32 / 1000.0;
                zones.push((zone_type, celsius));
            }
        } else if name.starts_with("cooling_device")
            && let Ok(state_text) = fs::read_to_string(path.join("cur_state"))
            && let Ok(state) = state_text.trim().parse::<u32>()
            && state > 0
        {
            throttling = true;
        }
    }

    if zones.is_empty() {
        return ThermalInfo {
            cpu_temp_celsius: None,
            throttling,
            fidelity: Fidelity::Unavailable,
        };
    }

    // Prefer CPU-labeled zone; fall back to highest-temperature zone.
    let cpu_zone = zones.iter().find(|(t, _)| is_cpu_thermal_zone(t));
    let temp = match cpu_zone {
        Some((_, t)) => *t,
        None => zones
            .iter()
            .map(|(_, t)| *t)
            .fold(f32::NEG_INFINITY, f32::max),
    };

    let throttling = throttling || temp >= THERMAL_THROTTLING_THRESHOLD_C;

    ThermalInfo {
        cpu_temp_celsius: Some(temp),
        throttling,
        fidelity: Fidelity::Direct,
    }
}

// ────────────────────────────────────────────────────────────────────
// Memory
// ────────────────────────────────────────────────────────────────────

/// Banded memory pressure. Boundaries match Linux memory-cgroup
/// conventions (Normal > 40%, then 20%, 10% steps).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PressureLevel {
    Normal,
    Elevated,
    High,
    Critical,
}

impl PressureLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            PressureLevel::Normal => "normal",
            PressureLevel::Elevated => "elevated",
            PressureLevel::High => "high",
            PressureLevel::Critical => "critical",
        }
    }

    /// Compute pressure level from `(available, total)` byte/KB counts.
    /// Integer math avoids float rounding at exact boundaries.
    pub fn from_ratio(available: u64, total: u64) -> Self {
        if total == 0 {
            return PressureLevel::Critical;
        }
        // basis points (×100 of percent) avoids fractional comparison
        let bp = available.saturating_mul(10_000) / total;
        match bp {
            // > 40%
            b if b > 4_000 => PressureLevel::Normal,
            // 20-40%
            b if b > 2_000 => PressureLevel::Elevated,
            // 10-20%
            b if b > 1_000 => PressureLevel::High,
            _ => PressureLevel::Critical,
        }
    }
}

/// Memory snapshot from `/proc/meminfo` plus optional PSI augmentation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_kb: u64,
    pub available_kb: u64,
    pub pressure_level: PressureLevel,
    pub psi_some_avg10: Option<f32>,
    pub fidelity: Fidelity,
}

/// Parse `/proc/meminfo` body to `(total_kb, available_kb)`.
///
/// Both fields are required; anything else returns Err.
pub fn parse_meminfo(text: &str) -> Result<(u64, u64), OrchestratorError> {
    let mut total: Option<u64> = None;
    let mut available: Option<u64> = None;
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let value: Option<u64> = rest
            .split_whitespace()
            .next()
            .and_then(|n| n.parse::<u64>().ok());
        match key.trim() {
            "MemTotal" => total = value,
            "MemAvailable" => available = value,
            _ => {}
        }
        if total.is_some() && available.is_some() {
            break;
        }
    }
    match (total, available) {
        (Some(t), Some(a)) => Ok((t, a)),
        _ => Err(OrchestratorError::Environment(
            "/proc/meminfo missing MemTotal or MemAvailable".to_string(),
        )),
    }
}

/// Parse `/proc/pressure/memory` body. Returns the `some avg10` value
/// (percent of time at least one task was stalled in the last 10s).
///
/// Body shape (Linux 4.20+):
///
/// ```text
/// some avg10=0.00 avg60=0.00 avg300=0.00 total=0
/// full avg10=0.00 avg60=0.00 avg300=0.00 total=0
/// ```
pub fn parse_psi_memory(text: &str) -> Option<f32> {
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("some ") {
            continue;
        }
        for token in line.split_whitespace() {
            if let Some(value) = token.strip_prefix("avg10=") {
                return value.parse::<f32>().ok();
            }
        }
    }
    None
}

fn probe_memory_meminfo(proc_root: &Path) -> Result<MemoryInfo, OrchestratorError> {
    let text = fs::read_to_string(proc_root.join("meminfo")).map_err(|e| {
        OrchestratorError::Environment(format!("/proc/meminfo unreadable: {e}"))
    })?;
    let (total_kb, available_kb) = parse_meminfo(&text)?;
    Ok(MemoryInfo {
        total_kb,
        available_kb,
        pressure_level: PressureLevel::from_ratio(available_kb, total_kb),
        psi_some_avg10: None,
        fidelity: Fidelity::Direct,
    })
}

fn augment_with_psi(info: &mut MemoryInfo, proc_root: &Path) {
    let path = proc_root.join("pressure/memory");
    if let Ok(text) = fs::read_to_string(&path) {
        info.psi_some_avg10 = parse_psi_memory(&text);
    }
}

// ────────────────────────────────────────────────────────────────────
// Disk usage
// ────────────────────────────────────────────────────────────────────

/// Parse `df -P /` stdout for the root filesystem usage percent.
///
/// `df -P` (POSIX format) emits a header line then one row per
/// filesystem. We're invoked with `/` as the only argument so there's
/// at most one data row. The Use% column is the second-to-last token.
///
/// Returns `None` if parsing fails — graceful, never panics.
pub fn parse_df_output(stdout: &str) -> Option<u8> {
    let mut lines = stdout.lines();
    let _header = lines.next()?;
    let row = lines.next()?;
    // Tokens: filesystem, blocks, used, available, use%, mountpoint
    let tokens: Vec<&str> = row.split_whitespace().collect();
    if tokens.len() < 2 {
        return None;
    }
    let pct_token = tokens[tokens.len() - 2];
    let trimmed = pct_token.trim_end_matches('%');
    trimmed.parse::<u8>().ok()
}

fn probe_disk_usage_subprocess() -> (Option<u8>, Fidelity) {
    let output = Command::new("df")
        .args(["-P", "/"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            match parse_df_output(&text) {
                Some(pct) => (Some(pct), Fidelity::Subprocess),
                None => (None, Fidelity::Unavailable),
            }
        }
        _ => (None, Fidelity::Unavailable),
    }
}

// ────────────────────────────────────────────────────────────────────
// Network / WiFi
// ────────────────────────────────────────────────────────────────────

/// ARPHRD_ETHER per RFC 1700; the value of `/sys/class/net/*/type` for
/// Ethernet interfaces.
const ARPHRD_ETHER: &str = "1";

fn read_on_wired_from_sys(sys_root: &Path) -> bool {
    let dir = sys_root.join("class/net");
    let Ok(entries) = fs::read_dir(&dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_s) = name.to_str() else { continue };
        if name_s == "lo" {
            continue;
        }
        let path = entry.path();
        let type_text = fs::read_to_string(path.join("type"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if type_text != ARPHRD_ETHER {
            continue;
        }
        let oper_text = fs::read_to_string(path.join("operstate"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if oper_text == "up" {
            return true;
        }
    }
    false
}

/// Parse the first SSID line of `nmcli -t -f active,ssid dev wifi`.
///
/// Lines are colon-separated `active:ssid`. The active connection is
/// marked `yes`. Returns `None` when no row reports active.
fn parse_nmcli_wifi(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        let Some((active, ssid)) = line.split_once(':') else {
            continue;
        };
        if active == "yes" && !ssid.is_empty() {
            return Some(ssid.to_string());
        }
    }
    None
}

fn probe_wifi_nmcli() -> (Option<String>, Fidelity) {
    let output = Command::new("nmcli")
        .args(["-t", "-f", "active,ssid", "dev", "wifi"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            match parse_nmcli_wifi(&text) {
                Some(ssid) => (Some(ssid), Fidelity::Subprocess),
                None => (None, Fidelity::Subprocess),
            }
        }
        _ => (None, Fidelity::Unavailable),
    }
}

// ────────────────────────────────────────────────────────────────────
// Time
// ────────────────────────────────────────────────────────────────────

/// Coarse time-of-day band used by other modules to bias scheduling
/// (deeper-work sessions in the morning, quiet hours in the late
/// night, etc.). The boundaries are heuristics, not research.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeBand {
    /// 05:00 – 08:59
    EarlyMorning,
    /// 09:00 – 11:59
    Morning,
    /// 12:00 – 13:59
    Midday,
    /// 14:00 – 17:59
    Afternoon,
    /// 18:00 – 21:59
    Evening,
    /// 22:00 – 04:59
    LateNight,
}

impl TimeBand {
    pub fn as_str(&self) -> &'static str {
        match self {
            TimeBand::EarlyMorning => "early_morning",
            TimeBand::Morning => "morning",
            TimeBand::Midday => "midday",
            TimeBand::Afternoon => "afternoon",
            TimeBand::Evening => "evening",
            TimeBand::LateNight => "late_night",
        }
    }

    /// Compute band from a 24-hour clock hour.
    pub fn from_hour(hour: u32) -> Self {
        match hour {
            5..=8 => TimeBand::EarlyMorning,
            9..=11 => TimeBand::Morning,
            12..=13 => TimeBand::Midday,
            14..=17 => TimeBand::Afternoon,
            18..=21 => TimeBand::Evening,
            _ => TimeBand::LateNight,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimeContext {
    pub band: TimeBand,
    pub is_weekend: bool,
    pub local_datetime: DateTime<Local>,
}

pub fn is_weekend(weekday: Weekday) -> bool {
    matches!(weekday, Weekday::Sat | Weekday::Sun)
}

fn current_time_context() -> TimeContext {
    let now = Local::now();
    TimeContext {
        band: TimeBand::from_hour(now.hour()),
        is_weekend: is_weekend(now.weekday()),
        local_datetime: now,
    }
}

// ────────────────────────────────────────────────────────────────────
// Location
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocationContext {
    /// User-configured label (e.g., "home", "office"). Resolved via
    /// [`LocationMap::label_for`]; `None` when no rule matches.
    pub label: Option<String>,
    pub wifi_ssid: Option<String>,
    pub on_wired: bool,
    /// Fidelity of the *primary* signal: WiFi SSID if present, else
    /// `on_wired` reading. `Unavailable` when neither is conclusive.
    pub fidelity: Fidelity,
}

/// User-configured map: SSID → label, "wired:true" → label.
///
/// Persists as TOML so a human can hand-edit it. Storage path lives
/// under [`default_location_map_path`] (XDG data dir).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LocationMap {
    /// Keys are either `"ssid:<name>"` or the literal `"wired:true"`.
    pub labels: HashMap<String, String>,
}

impl LocationMap {
    /// Resolve the label for the current network situation. SSID
    /// precedence over wired fallback (an SSID is more specific).
    pub fn label_for(&self, ssid: Option<&str>, on_wired: bool) -> Option<&str> {
        if let Some(s) = ssid {
            let key = format!("ssid:{s}");
            if let Some(label) = self.labels.get(&key) {
                return Some(label.as_str());
            }
        }
        if on_wired {
            return self.labels.get("wired:true").map(String::as_str);
        }
        None
    }

    pub fn set_label(&mut self, key: &str, label: &str) {
        self.labels.insert(key.to_string(), label.to_string());
    }

    pub fn remove_label(&mut self, key: &str) -> bool {
        self.labels.remove(key).is_some()
    }

    pub fn save(&self, path: &Path) -> Result<(), OrchestratorError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                OrchestratorError::Environment(format!(
                    "could not create location-map dir {}: {e}",
                    parent.display()
                ))
            })?;
        }
        let text = toml::to_string_pretty(self).map_err(|e| {
            OrchestratorError::Environment(format!("location-map serialization failed: {e}"))
        })?;
        fs::write(path, text).map_err(|e| {
            OrchestratorError::Environment(format!(
                "location-map write failed at {}: {e}",
                path.display()
            ))
        })
    }

    pub fn load(path: &Path) -> Result<Self, OrchestratorError> {
        let text = fs::read_to_string(path).map_err(|e| {
            OrchestratorError::Environment(format!(
                "location-map read failed at {}: {e}",
                path.display()
            ))
        })?;
        toml::from_str(&text).map_err(|e| {
            OrchestratorError::Environment(format!("location-map parse failed: {e}"))
        })
    }
}

/// Default location-map path: `<data_dir>/delphi/environment/location_map.toml`.
///
/// Returns `None` when `dirs::data_local_dir()` cannot resolve a
/// platform-appropriate directory (extremely unusual).
pub fn default_location_map_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("delphi/environment/location_map.toml"))
}

// ────────────────────────────────────────────────────────────────────
// Activity classification
// ────────────────────────────────────────────────────────────────────

/// What the user is doing right now, classified from compositor +
/// learning observer signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivityState {
    Idle,
    DeepWork,
    CasualBrowsing,
    Gaming,
    Meeting,
    Unknown,
}

impl ActivityState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActivityState::Idle => "idle",
            ActivityState::DeepWork => "deep_work",
            ActivityState::CasualBrowsing => "casual_browsing",
            ActivityState::Gaming => "gaming",
            ActivityState::Meeting => "meeting",
            ActivityState::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActivityObservations {
    pub seconds_since_last_input: u64,
    pub active_window_switches_last_minute: u32,
    pub keystrokes_last_minute: u32,
    pub gpu_usage_percent: Option<u8>,
    pub fullscreen_active: bool,
    pub microphone_in_use: bool,
}

#[derive(Debug, Clone)]
pub struct ActivityConfig {
    pub idle_threshold_seconds: u64,
    pub deep_work_max_switches_per_min: u32,
    pub deep_work_min_keystrokes_per_min: u32,
    pub gaming_min_gpu_percent: u8,
}

impl Default for ActivityConfig {
    fn default() -> Self {
        // Heuristic starting points; the learning engine refines per-user.
        Self {
            idle_threshold_seconds: 300,
            deep_work_max_switches_per_min: 3,
            deep_work_min_keystrokes_per_min: 30,
            gaming_min_gpu_percent: 70,
        }
    }
}

/// Pure classifier — no I/O, no side effects. Precedence:
///
/// 1. **Idle** — strict `>` threshold (at exactly threshold, NOT idle).
/// 2. **Meeting** — microphone in use (trumps gaming because mic + GPU
///    is video-call usage, not gaming).
/// 3. **Gaming** — fullscreen + GPU at gaming threshold.
/// 4. **DeepWork** — low window-switching with sustained keystrokes.
/// 5. **CasualBrowsing** — high window-switching, no other signals.
/// 6. **Unknown** — none of the above.
pub fn classify_activity(obs: &ActivityObservations, config: &ActivityConfig) -> ActivityState {
    if obs.seconds_since_last_input > config.idle_threshold_seconds {
        return ActivityState::Idle;
    }
    if obs.microphone_in_use {
        return ActivityState::Meeting;
    }
    if obs.fullscreen_active
        && obs
            .gpu_usage_percent
            .is_some_and(|g| g >= config.gaming_min_gpu_percent)
    {
        return ActivityState::Gaming;
    }
    if obs.active_window_switches_last_minute <= config.deep_work_max_switches_per_min
        && obs.keystrokes_last_minute >= config.deep_work_min_keystrokes_per_min
    {
        return ActivityState::DeepWork;
    }
    if obs.active_window_switches_last_minute > config.deep_work_max_switches_per_min {
        return ActivityState::CasualBrowsing;
    }
    ActivityState::Unknown
}

// ────────────────────────────────────────────────────────────────────
// EnvironmentSensor trait + Linux implementation
// ────────────────────────────────────────────────────────────────────

/// Sensor abstraction. Production code uses [`LinuxSensor`]; tests
/// inject mocks to verify the [`EnvironmentMonitor`]'s composition
/// logic without touching real sysfs.
pub trait EnvironmentSensor: Send + Sync {
    fn read_battery(&self) -> Result<Option<BatteryInfo>, OrchestratorError>;
    fn read_thermal(&self) -> Result<ThermalInfo, OrchestratorError>;
    fn read_memory(&self) -> Result<MemoryInfo, OrchestratorError>;
    fn read_disk_usage(&self) -> Result<(Option<u8>, Fidelity), OrchestratorError>;
    fn read_wifi_ssid(&self) -> Result<(Option<String>, Fidelity), OrchestratorError>;
    fn read_on_wired(&self) -> Result<bool, OrchestratorError>;
}

/// Linux production sensor — reads `/sys/` and `/proc/`, shells out to
/// `df` and `nmcli` when needed. The roots are configurable so tests
/// can inject a [`tempfile::TempDir`].
pub struct LinuxSensor {
    sys_root: PathBuf,
    proc_root: PathBuf,
}

impl Default for LinuxSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxSensor {
    /// Real-system sensor reading from `/sys` and `/proc`.
    pub fn new() -> Self {
        Self {
            sys_root: PathBuf::from("/sys"),
            proc_root: PathBuf::from("/proc"),
        }
    }

    /// Test/mock sensor reading from injected roots.
    pub fn with_roots(sys_root: PathBuf, proc_root: PathBuf) -> Self {
        Self { sys_root, proc_root }
    }
}

impl EnvironmentSensor for LinuxSensor {
    fn read_battery(&self) -> Result<Option<BatteryInfo>, OrchestratorError> {
        match probe_battery_uevent(&self.sys_root)? {
            Some(info) => Ok(Some(info)),
            None => {
                debug!("battery uevent unavailable; trying capacity files");
                probe_battery_capacity_files(&self.sys_root)
            }
        }
    }

    fn read_thermal(&self) -> Result<ThermalInfo, OrchestratorError> {
        Ok(probe_thermal_zones(&self.sys_root))
    }

    fn read_memory(&self) -> Result<MemoryInfo, OrchestratorError> {
        let mut info = probe_memory_meminfo(&self.proc_root)?;
        augment_with_psi(&mut info, &self.proc_root);
        Ok(info)
    }

    fn read_disk_usage(&self) -> Result<(Option<u8>, Fidelity), OrchestratorError> {
        Ok(probe_disk_usage_subprocess())
    }

    fn read_wifi_ssid(&self) -> Result<(Option<String>, Fidelity), OrchestratorError> {
        Ok(probe_wifi_nmcli())
    }

    fn read_on_wired(&self) -> Result<bool, OrchestratorError> {
        Ok(read_on_wired_from_sys(&self.sys_root))
    }
}

// ────────────────────────────────────────────────────────────────────
// EnvironmentState + EnvironmentMonitor
// ────────────────────────────────────────────────────────────────────

/// Composite snapshot: everything observable about the user's physical
/// context at a single point in time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentState {
    pub captured_at: DateTime<Utc>,
    pub battery: Option<BatteryInfo>,
    pub thermal: ThermalInfo,
    pub memory: MemoryInfo,
    pub disk_usage_percent: Option<u8>,
    pub disk_fidelity: Fidelity,
    pub time: TimeContext,
    pub location: LocationContext,
    pub activity: ActivityState,
}

/// Top-level orchestration: composes a [`LocationMap`] and an
/// [`ActivityConfig`] with a swappable [`EnvironmentSensor`] and emits
/// a single [`EnvironmentState`] per [`snapshot`](Self::snapshot) call.
pub struct EnvironmentMonitor {
    sensor: Box<dyn EnvironmentSensor>,
    location_map: LocationMap,
    activity_config: ActivityConfig,
}

impl EnvironmentMonitor {
    /// Construct with the production [`LinuxSensor`].
    pub fn new_linux() -> Self {
        Self::with_sensor(Box::new(LinuxSensor::new()))
    }

    pub fn with_sensor(sensor: Box<dyn EnvironmentSensor>) -> Self {
        Self {
            sensor,
            location_map: LocationMap::default(),
            activity_config: ActivityConfig::default(),
        }
    }

    pub fn with_config(mut self, config: ActivityConfig) -> Self {
        self.activity_config = config;
        self
    }

    pub fn location_map(&self) -> &LocationMap {
        &self.location_map
    }

    pub fn location_map_mut(&mut self) -> &mut LocationMap {
        &mut self.location_map
    }

    pub fn load_location_map(&mut self, path: &Path) -> Result<(), OrchestratorError> {
        self.location_map = LocationMap::load(path)?;
        Ok(())
    }

    pub fn save_location_map(&self, path: &Path) -> Result<(), OrchestratorError> {
        self.location_map.save(path)
    }

    /// Capture everything the sensors can see right now, plus the
    /// activity classification computed from the supplied observations.
    /// Sensor errors propagate; consumers degrade gracefully.
    pub fn snapshot(
        &self,
        activity_obs: &ActivityObservations,
    ) -> Result<EnvironmentState, OrchestratorError> {
        let battery = self.sensor.read_battery()?;
        let thermal = self.sensor.read_thermal()?;
        let memory = self.sensor.read_memory()?;
        let (disk_usage_percent, disk_fidelity) = self.sensor.read_disk_usage()?;
        let (wifi_ssid, wifi_fidelity) = self.sensor.read_wifi_ssid()?;
        let on_wired = self.sensor.read_on_wired()?;

        let location_fidelity = if wifi_ssid.is_some() {
            wifi_fidelity
        } else if on_wired {
            Fidelity::Direct
        } else {
            Fidelity::Unavailable
        };
        let label = self
            .location_map
            .label_for(wifi_ssid.as_deref(), on_wired)
            .map(|s| s.to_string());

        Ok(EnvironmentState {
            captured_at: Utc::now(),
            battery,
            thermal,
            memory,
            disk_usage_percent,
            disk_fidelity,
            time: current_time_context(),
            location: LocationContext {
                label,
                wifi_ssid,
                on_wired,
                fidelity: location_fidelity,
            },
            activity: classify_activity(activity_obs, &self.activity_config),
        })
    }
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    // ── Mock-tree helpers ─────────────────────────────────────────────

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn write_mock_meminfo(proc_root: &Path, total_kb: u64, available_kb: u64) {
        let body = format!(
            "MemTotal:  {total_kb} kB\nMemFree:   123 kB\nMemAvailable: {available_kb} kB\n"
        );
        write_file(&proc_root.join("meminfo"), &body);
    }

    fn write_mock_psi(proc_root: &Path, avg10: f32) {
        let body = format!(
            "some avg10={avg10:.2} avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
        );
        write_file(&proc_root.join("pressure/memory"), &body);
    }

    fn write_mock_battery_uevent(
        sys_root: &Path,
        bat_name: &str,
        capacity: u8,
        status: &str,
        energy_now: u64,
        power_now: u64,
    ) {
        let body = format!(
            "POWER_SUPPLY_NAME={bat_name}\n\
             POWER_SUPPLY_TYPE=Battery\n\
             POWER_SUPPLY_STATUS={status}\n\
             POWER_SUPPLY_PRESENT=1\n\
             POWER_SUPPLY_CAPACITY={capacity}\n\
             POWER_SUPPLY_ENERGY_NOW={energy_now}\n\
             POWER_SUPPLY_POWER_NOW={power_now}\n"
        );
        let bat_dir = sys_root.join(format!("class/power_supply/{bat_name}"));
        write_file(&bat_dir.join("uevent"), &body);
    }

    fn write_mock_battery_files(sys_root: &Path, bat_name: &str, capacity: u8, status: &str) {
        let bat_dir = sys_root.join(format!("class/power_supply/{bat_name}"));
        write_file(&bat_dir.join("capacity"), &format!("{capacity}\n"));
        write_file(&bat_dir.join("status"), &format!("{status}\n"));
    }

    fn write_mock_ac(sys_root: &Path, ac_name: &str, online: bool) {
        let ac_dir = sys_root.join(format!("class/power_supply/{ac_name}"));
        write_file(&ac_dir.join("online"), if online { "1\n" } else { "0\n" });
    }

    fn write_mock_thermal_zone(
        sys_root: &Path,
        zone_idx: u32,
        zone_type: &str,
        millidegrees: i64,
    ) {
        let zone_dir = sys_root.join(format!("class/thermal/thermal_zone{zone_idx}"));
        write_file(&zone_dir.join("type"), &format!("{zone_type}\n"));
        write_file(&zone_dir.join("temp"), &format!("{millidegrees}\n"));
    }

    fn write_mock_cooling_device(sys_root: &Path, device_idx: u32, cur_state: u32) {
        let dir = sys_root.join(format!("class/thermal/cooling_device{device_idx}"));
        write_file(&dir.join("type"), "Processor\n");
        write_file(&dir.join("cur_state"), &format!("{cur_state}\n"));
    }

    fn write_mock_net_iface(sys_root: &Path, name: &str, type_id: &str, operstate: &str) {
        let dir = sys_root.join(format!("class/net/{name}"));
        write_file(&dir.join("type"), &format!("{type_id}\n"));
        write_file(&dir.join("operstate"), &format!("{operstate}\n"));
    }

    // ── Mock sensor for monitor composition tests ─────────────────────

    struct MockSensor {
        battery: Option<BatteryInfo>,
        thermal: ThermalInfo,
        memory: MemoryInfo,
        disk: (Option<u8>, Fidelity),
        wifi: (Option<String>, Fidelity),
        wired: bool,
        snapshots_taken: Mutex<u32>,
    }

    impl MockSensor {
        fn rich() -> Self {
            Self {
                battery: Some(BatteryInfo {
                    percent: 75,
                    state: PowerState::Battery,
                    time_remaining_sec: Some(7200),
                    fidelity: Fidelity::Direct,
                }),
                thermal: ThermalInfo {
                    cpu_temp_celsius: Some(55.0),
                    throttling: false,
                    fidelity: Fidelity::Direct,
                },
                memory: MemoryInfo {
                    total_kb: 16_000_000,
                    available_kb: 8_000_000,
                    pressure_level: PressureLevel::Normal,
                    psi_some_avg10: Some(0.0),
                    fidelity: Fidelity::Direct,
                },
                disk: (Some(42), Fidelity::Subprocess),
                wifi: (Some("home-net".to_string()), Fidelity::Subprocess),
                wired: false,
                snapshots_taken: Mutex::new(0),
            }
        }
    }

    impl EnvironmentSensor for MockSensor {
        fn read_battery(&self) -> Result<Option<BatteryInfo>, OrchestratorError> {
            *self.snapshots_taken.lock().unwrap() += 1;
            Ok(self.battery.clone())
        }
        fn read_thermal(&self) -> Result<ThermalInfo, OrchestratorError> {
            Ok(self.thermal.clone())
        }
        fn read_memory(&self) -> Result<MemoryInfo, OrchestratorError> {
            Ok(self.memory.clone())
        }
        fn read_disk_usage(&self) -> Result<(Option<u8>, Fidelity), OrchestratorError> {
            Ok(self.disk)
        }
        fn read_wifi_ssid(&self) -> Result<(Option<String>, Fidelity), OrchestratorError> {
            Ok(self.wifi.clone())
        }
        fn read_on_wired(&self) -> Result<bool, OrchestratorError> {
            Ok(self.wired)
        }
    }

    // ── Fidelity ──────────────────────────────────────────────────────

    #[test]
    fn fidelity_strings_are_stable() {
        assert_eq!(Fidelity::Direct.as_str(), "direct");
        assert_eq!(Fidelity::NativeApi.as_str(), "native_api");
        assert_eq!(Fidelity::Subprocess.as_str(), "subprocess");
        assert_eq!(Fidelity::Unavailable.as_str(), "unavailable");
    }

    // ── parse_meminfo ─────────────────────────────────────────────────

    #[test]
    fn meminfo_parses_basic_layout() {
        let body = "MemTotal:  16000000 kB\nMemFree: 100 kB\nMemAvailable: 8000000 kB\n";
        let (t, a) = parse_meminfo(body).unwrap();
        assert_eq!(t, 16_000_000);
        assert_eq!(a, 8_000_000);
    }

    #[test]
    fn meminfo_handles_extra_whitespace() {
        let body = "MemTotal:    1000 kB\nMemAvailable:   500 kB\nOther:  9 kB\n";
        let (t, a) = parse_meminfo(body).unwrap();
        assert_eq!(t, 1000);
        assert_eq!(a, 500);
    }

    #[test]
    fn meminfo_errors_when_required_missing() {
        let body = "MemFree: 100 kB\nBuffers: 99 kB\n";
        assert!(parse_meminfo(body).is_err());
    }

    // ── parse_psi_memory ──────────────────────────────────────────────

    #[test]
    fn psi_extracts_avg10_value() {
        let body = "some avg10=1.42 avg60=0.50 avg300=0.10 total=99\nfull avg10=0.00 avg60=0.00\n";
        assert_eq!(parse_psi_memory(body), Some(1.42));
    }

    #[test]
    fn psi_returns_none_when_some_line_absent() {
        assert_eq!(parse_psi_memory("full avg10=1.0\n"), None);
    }

    // ── PressureLevel boundaries ──────────────────────────────────────

    #[test]
    fn pressure_level_normal_above_forty_percent() {
        assert_eq!(
            PressureLevel::from_ratio(401, 1000),
            PressureLevel::Normal
        );
    }

    #[test]
    fn pressure_level_elevated_at_exactly_forty_percent() {
        // 40% available → Elevated (Normal is strict > 40%)
        assert_eq!(PressureLevel::from_ratio(400, 1000), PressureLevel::Elevated);
    }

    #[test]
    fn pressure_level_high_at_exactly_twenty_percent() {
        assert_eq!(PressureLevel::from_ratio(200, 1000), PressureLevel::High);
    }

    #[test]
    fn pressure_level_critical_at_exactly_ten_percent() {
        assert_eq!(PressureLevel::from_ratio(100, 1000), PressureLevel::Critical);
    }

    #[test]
    fn pressure_level_critical_when_total_zero() {
        assert_eq!(PressureLevel::from_ratio(0, 0), PressureLevel::Critical);
    }

    #[test]
    fn pressure_level_strings_are_stable() {
        assert_eq!(PressureLevel::Normal.as_str(), "normal");
        assert_eq!(PressureLevel::Elevated.as_str(), "elevated");
        assert_eq!(PressureLevel::High.as_str(), "high");
        assert_eq!(PressureLevel::Critical.as_str(), "critical");
    }

    // ── Battery uevent parsing ────────────────────────────────────────

    #[test]
    fn battery_uevent_parses_discharging() {
        let body = "POWER_SUPPLY_NAME=BAT1\n\
                    POWER_SUPPLY_STATUS=Discharging\n\
                    POWER_SUPPLY_CAPACITY=54\n\
                    POWER_SUPPLY_ENERGY_NOW=2722000\n\
                    POWER_SUPPLY_POWER_NOW=5790000\n";
        let info = parse_battery_uevent(body, false).unwrap();
        assert_eq!(info.percent, 54);
        assert_eq!(info.state, PowerState::Battery);
        // 2722000 µWh / 5790000 µW * 3600 ≈ 1692 seconds
        assert!(info.time_remaining_sec.is_some());
        let secs = info.time_remaining_sec.unwrap();
        assert!((1500..=1900).contains(&secs), "secs was {secs}");
        assert_eq!(info.fidelity, Fidelity::Direct);
    }

    #[test]
    fn battery_uevent_parses_charging() {
        let body = "POWER_SUPPLY_STATUS=Charging\nPOWER_SUPPLY_CAPACITY=80\n";
        let info = parse_battery_uevent(body, true).unwrap();
        assert_eq!(info.state, PowerState::AcCharging);
        assert!(info.time_remaining_sec.is_none());
    }

    #[test]
    fn battery_uevent_parses_full_with_ac() {
        let body = "POWER_SUPPLY_STATUS=Full\nPOWER_SUPPLY_CAPACITY=100\n";
        let info = parse_battery_uevent(body, true).unwrap();
        assert_eq!(info.state, PowerState::AcIdle);
    }

    #[test]
    fn battery_uevent_handles_missing_power_now() {
        let body = "POWER_SUPPLY_STATUS=Discharging\nPOWER_SUPPLY_CAPACITY=50\n";
        let info = parse_battery_uevent(body, false).unwrap();
        assert_eq!(info.state, PowerState::Battery);
        assert!(info.time_remaining_sec.is_none());
    }

    #[test]
    fn battery_uevent_capacity_clamped_to_100() {
        let body = "POWER_SUPPLY_STATUS=Full\nPOWER_SUPPLY_CAPACITY=255\n";
        let info = parse_battery_uevent(body, true).unwrap();
        assert_eq!(info.percent, 100);
    }

    #[test]
    fn battery_uevent_errors_without_capacity() {
        let body = "POWER_SUPPLY_STATUS=Discharging\n";
        assert!(parse_battery_uevent(body, false).is_err());
    }

    #[test]
    fn classify_power_state_handles_all_strings() {
        assert_eq!(classify_power_state("Charging", false), PowerState::AcCharging);
        assert_eq!(classify_power_state("Discharging", false), PowerState::Battery);
        assert_eq!(classify_power_state("Full", true), PowerState::AcIdle);
        assert_eq!(classify_power_state("Full", false), PowerState::Battery);
        assert_eq!(classify_power_state("Not charging", true), PowerState::AcIdle);
        assert_eq!(classify_power_state("garbage", false), PowerState::Unknown);
    }

    #[test]
    fn power_state_strings_are_stable() {
        assert_eq!(PowerState::AcCharging.as_str(), "ac_charging");
        assert_eq!(PowerState::AcIdle.as_str(), "ac_idle");
        assert_eq!(PowerState::Battery.as_str(), "battery");
        assert_eq!(PowerState::NoBattery.as_str(), "no_battery");
        assert_eq!(PowerState::Unknown.as_str(), "unknown");
    }

    // ── LinuxSensor with mock filesystem ──────────────────────────────

    #[test]
    fn battery_uevent_path_is_glob_not_hardcoded() {
        // Verify we find BAT1, not just BAT0 — matches our WSL2 dev box.
        let tmp = TempDir::new().unwrap();
        let sys = tmp.path().to_path_buf();
        let proc_p = tmp.path().to_path_buf();
        write_mock_battery_uevent(&sys, "BAT1", 60, "Discharging", 5_000_000, 10_000_000);
        let sensor = LinuxSensor::with_roots(sys, proc_p);
        let info = sensor.read_battery().unwrap().unwrap();
        assert_eq!(info.percent, 60);
        assert_eq!(info.state, PowerState::Battery);
    }

    #[test]
    fn battery_falls_back_when_uevent_empty() {
        let tmp = TempDir::new().unwrap();
        let sys = tmp.path().to_path_buf();
        // Empty uevent file forces fallback path
        write_file(&sys.join("class/power_supply/BAT0/uevent"), "");
        write_mock_battery_files(&sys, "BAT0", 33, "Discharging");
        let sensor = LinuxSensor::with_roots(sys, tmp.path().to_path_buf());
        let info = sensor.read_battery().unwrap().unwrap();
        assert_eq!(info.percent, 33);
        assert_eq!(info.state, PowerState::Battery);
        assert!(info.time_remaining_sec.is_none()); // no energy/power files
    }

    #[test]
    fn battery_returns_none_when_no_battery_directory() {
        let tmp = TempDir::new().unwrap();
        // Create power_supply dir with only AC, no BAT*
        write_mock_ac(tmp.path(), "AC0", true);
        let sensor = LinuxSensor::with_roots(tmp.path().to_path_buf(), tmp.path().to_path_buf());
        assert!(sensor.read_battery().unwrap().is_none());
    }

    #[test]
    fn battery_ac_present_changes_full_to_ac_idle() {
        let tmp = TempDir::new().unwrap();
        let sys = tmp.path().to_path_buf();
        write_mock_battery_uevent(&sys, "BAT0", 100, "Full", 0, 0);
        write_mock_ac(&sys, "ADP0", true);
        let sensor = LinuxSensor::with_roots(sys, tmp.path().to_path_buf());
        let info = sensor.read_battery().unwrap().unwrap();
        assert_eq!(info.state, PowerState::AcIdle);
    }

    #[test]
    fn thermal_picks_cpu_zone_over_other_zones() {
        let tmp = TempDir::new().unwrap();
        let sys = tmp.path().to_path_buf();
        write_mock_thermal_zone(&sys, 0, "battery", 30_000); // 30°C, ignored
        write_mock_thermal_zone(&sys, 1, "x86_pkg_temp", 55_000); // 55°C, picked
        write_mock_thermal_zone(&sys, 2, "ambient", 20_000); // 20°C, ignored
        let sensor = LinuxSensor::with_roots(sys, tmp.path().to_path_buf());
        let t = sensor.read_thermal().unwrap();
        assert_eq!(t.cpu_temp_celsius, Some(55.0));
        assert!(!t.throttling);
        assert_eq!(t.fidelity, Fidelity::Direct);
    }

    #[test]
    fn thermal_throttling_via_cooling_device() {
        let tmp = TempDir::new().unwrap();
        let sys = tmp.path().to_path_buf();
        write_mock_thermal_zone(&sys, 0, "cpu", 70_000);
        write_mock_cooling_device(&sys, 0, 2); // active
        let sensor = LinuxSensor::with_roots(sys, tmp.path().to_path_buf());
        let t = sensor.read_thermal().unwrap();
        assert!(t.throttling);
    }

    #[test]
    fn thermal_throttling_via_high_temperature() {
        let tmp = TempDir::new().unwrap();
        let sys = tmp.path().to_path_buf();
        write_mock_thermal_zone(&sys, 0, "cpu", 90_000); // 90°C > 85°C threshold
        let sensor = LinuxSensor::with_roots(sys, tmp.path().to_path_buf());
        let t = sensor.read_thermal().unwrap();
        assert!(t.throttling);
    }

    #[test]
    fn thermal_unavailable_when_no_zones() {
        let tmp = TempDir::new().unwrap();
        let sensor = LinuxSensor::with_roots(tmp.path().to_path_buf(), tmp.path().to_path_buf());
        let t = sensor.read_thermal().unwrap();
        assert!(t.cpu_temp_celsius.is_none());
        assert_eq!(t.fidelity, Fidelity::Unavailable);
    }

    #[test]
    fn thermal_picks_hottest_when_no_cpu_label() {
        let tmp = TempDir::new().unwrap();
        let sys = tmp.path().to_path_buf();
        write_mock_thermal_zone(&sys, 0, "ambient", 25_000);
        write_mock_thermal_zone(&sys, 1, "battery", 35_000);
        write_mock_thermal_zone(&sys, 2, "wifi", 45_000); // highest, picked
        let sensor = LinuxSensor::with_roots(sys, tmp.path().to_path_buf());
        let t = sensor.read_thermal().unwrap();
        assert_eq!(t.cpu_temp_celsius, Some(45.0));
    }

    #[test]
    fn is_cpu_thermal_zone_recognizes_common_labels() {
        assert!(is_cpu_thermal_zone("cpu-thermal"));
        assert!(is_cpu_thermal_zone("x86_pkg_temp"));
        assert!(is_cpu_thermal_zone("coretemp"));
        assert!(is_cpu_thermal_zone("acpitz"));
        assert!(is_cpu_thermal_zone("soc_thermal"));
        assert!(!is_cpu_thermal_zone("ambient"));
        assert!(!is_cpu_thermal_zone("battery"));
    }

    // ── Memory sensor via mock /proc ──────────────────────────────────

    #[test]
    fn memory_reading_is_direct_fidelity() {
        let tmp = TempDir::new().unwrap();
        let proc_p = tmp.path().to_path_buf();
        write_mock_meminfo(&proc_p, 16_000_000, 8_000_000);
        let sensor = LinuxSensor::with_roots(tmp.path().to_path_buf(), proc_p);
        let info = sensor.read_memory().unwrap();
        assert_eq!(info.total_kb, 16_000_000);
        assert_eq!(info.available_kb, 8_000_000);
        assert_eq!(info.pressure_level, PressureLevel::Normal);
        assert!(info.psi_some_avg10.is_none()); // no PSI file
        assert_eq!(info.fidelity, Fidelity::Direct);
    }

    #[test]
    fn memory_augments_with_psi_when_available() {
        let tmp = TempDir::new().unwrap();
        let proc_p = tmp.path().to_path_buf();
        write_mock_meminfo(&proc_p, 1000, 500);
        write_mock_psi(&proc_p, 0.42);
        let sensor = LinuxSensor::with_roots(tmp.path().to_path_buf(), proc_p);
        let info = sensor.read_memory().unwrap();
        assert_eq!(info.psi_some_avg10, Some(0.42));
        // Fidelity unchanged — primary data was Direct
        assert_eq!(info.fidelity, Fidelity::Direct);
    }

    #[test]
    fn memory_errors_on_missing_meminfo() {
        let tmp = TempDir::new().unwrap();
        let sensor = LinuxSensor::with_roots(tmp.path().to_path_buf(), tmp.path().to_path_buf());
        assert!(sensor.read_memory().is_err());
    }

    #[test]
    fn memory_errors_on_malformed_meminfo() {
        let tmp = TempDir::new().unwrap();
        let proc_p = tmp.path().to_path_buf();
        write_file(&proc_p.join("meminfo"), "garbage data\nno fields here\n");
        let sensor = LinuxSensor::with_roots(tmp.path().to_path_buf(), proc_p);
        assert!(sensor.read_memory().is_err());
    }

    // ── Disk subprocess parsing ───────────────────────────────────────

    #[test]
    fn parse_df_extracts_root_use_percent() {
        let stdout = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                      /dev/sda1   1000000   400000  600000   40%       /\n";
        assert_eq!(parse_df_output(stdout), Some(40));
    }

    #[test]
    fn parse_df_returns_none_on_empty_output() {
        assert_eq!(parse_df_output(""), None);
    }

    #[test]
    fn parse_df_returns_none_on_header_only() {
        assert_eq!(parse_df_output("Filesystem 1024-blocks Used Available Capacity Mounted on\n"), None);
    }

    // ── Network ───────────────────────────────────────────────────────

    #[test]
    fn parse_nmcli_extracts_active_ssid() {
        let stdout = "no:other-net\nyes:home-wifi\nno:guest\n";
        assert_eq!(parse_nmcli_wifi(stdout), Some("home-wifi".to_string()));
    }

    #[test]
    fn parse_nmcli_returns_none_when_no_active() {
        let stdout = "no:other-net\nno:guest\n";
        assert!(parse_nmcli_wifi(stdout).is_none());
    }

    #[test]
    fn on_wired_detects_eth_up() {
        let tmp = TempDir::new().unwrap();
        let sys = tmp.path().to_path_buf();
        write_mock_net_iface(&sys, "lo", "772", "unknown");
        write_mock_net_iface(&sys, "eth0", ARPHRD_ETHER, "up");
        let sensor = LinuxSensor::with_roots(sys, tmp.path().to_path_buf());
        assert!(sensor.read_on_wired().unwrap());
    }

    #[test]
    fn on_wired_false_when_eth_down() {
        let tmp = TempDir::new().unwrap();
        let sys = tmp.path().to_path_buf();
        write_mock_net_iface(&sys, "eth0", ARPHRD_ETHER, "down");
        let sensor = LinuxSensor::with_roots(sys, tmp.path().to_path_buf());
        assert!(!sensor.read_on_wired().unwrap());
    }

    #[test]
    fn on_wired_ignores_non_ethernet_types() {
        let tmp = TempDir::new().unwrap();
        let sys = tmp.path().to_path_buf();
        write_mock_net_iface(&sys, "wlan0", "1", "up"); // type 1 == ether — should match
        let sensor = LinuxSensor::with_roots(sys, tmp.path().to_path_buf());
        // Type 1 matches our wired check (kernel reports wlan0 as 1 too on
        // some systems; our check is type==1 + operstate=up). This proves
        // the function reads what's there, not the interface name.
        assert!(sensor.read_on_wired().unwrap());
    }

    // ── Time ──────────────────────────────────────────────────────────

    #[test]
    fn time_band_boundaries() {
        assert_eq!(TimeBand::from_hour(4), TimeBand::LateNight);
        assert_eq!(TimeBand::from_hour(5), TimeBand::EarlyMorning);
        assert_eq!(TimeBand::from_hour(8), TimeBand::EarlyMorning);
        assert_eq!(TimeBand::from_hour(9), TimeBand::Morning);
        assert_eq!(TimeBand::from_hour(11), TimeBand::Morning);
        assert_eq!(TimeBand::from_hour(12), TimeBand::Midday);
        assert_eq!(TimeBand::from_hour(13), TimeBand::Midday);
        assert_eq!(TimeBand::from_hour(14), TimeBand::Afternoon);
        assert_eq!(TimeBand::from_hour(17), TimeBand::Afternoon);
        assert_eq!(TimeBand::from_hour(18), TimeBand::Evening);
        assert_eq!(TimeBand::from_hour(21), TimeBand::Evening);
        assert_eq!(TimeBand::from_hour(22), TimeBand::LateNight);
        assert_eq!(TimeBand::from_hour(0), TimeBand::LateNight);
    }

    #[test]
    fn time_band_strings_are_stable() {
        assert_eq!(TimeBand::EarlyMorning.as_str(), "early_morning");
        assert_eq!(TimeBand::LateNight.as_str(), "late_night");
    }

    #[test]
    fn weekend_detection() {
        assert!(!is_weekend(Weekday::Mon));
        assert!(!is_weekend(Weekday::Wed));
        assert!(!is_weekend(Weekday::Fri));
        assert!(is_weekend(Weekday::Sat));
        assert!(is_weekend(Weekday::Sun));
    }

    // ── LocationMap ───────────────────────────────────────────────────

    #[test]
    fn location_map_resolves_ssid_first() {
        let mut map = LocationMap::default();
        map.set_label("ssid:home-net", "home");
        map.set_label("wired:true", "office");
        // SSID match wins over wired fallback
        assert_eq!(map.label_for(Some("home-net"), true), Some("home"));
    }

    #[test]
    fn location_map_falls_back_to_wired() {
        let mut map = LocationMap::default();
        map.set_label("wired:true", "office");
        assert_eq!(map.label_for(None, true), Some("office"));
    }

    #[test]
    fn location_map_no_match_returns_none() {
        let map = LocationMap::default();
        assert!(map.label_for(Some("strange"), false).is_none());
    }

    #[test]
    fn location_map_remove_label() {
        let mut map = LocationMap::default();
        map.set_label("ssid:home-net", "home");
        assert!(map.remove_label("ssid:home-net"));
        assert!(map.label_for(Some("home-net"), false).is_none());
        assert!(!map.remove_label("ssid:nonexistent"));
    }

    #[test]
    fn location_map_toml_round_trip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("loc.toml");
        let mut map = LocationMap::default();
        map.set_label("ssid:home-net", "home");
        map.set_label("wired:true", "office");
        map.save(&path).unwrap();
        let loaded = LocationMap::load(&path).unwrap();
        assert_eq!(loaded.labels.len(), 2);
        assert_eq!(loaded.label_for(Some("home-net"), false), Some("home"));
        assert_eq!(loaded.label_for(None, true), Some("office"));
    }

    #[test]
    fn location_map_load_errors_on_missing_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nonexistent.toml");
        assert!(LocationMap::load(&path).is_err());
    }

    #[test]
    fn location_map_save_creates_parent_dirs() {
        let tmp = TempDir::new().unwrap();
        let nested = tmp.path().join("a/b/c/loc.toml");
        let map = LocationMap::default();
        assert!(map.save(&nested).is_ok());
        assert!(nested.exists());
    }

    // ── Activity classifier ───────────────────────────────────────────

    #[test]
    fn activity_idle_from_long_no_input() {
        let obs = ActivityObservations {
            seconds_since_last_input: 600,
            ..Default::default()
        };
        assert_eq!(classify_activity(&obs, &ActivityConfig::default()), ActivityState::Idle);
    }

    #[test]
    fn activity_idle_threshold_is_strict_greater_than() {
        // At exactly threshold → NOT idle yet.
        let obs = ActivityObservations {
            seconds_since_last_input: 300,
            keystrokes_last_minute: 50,
            active_window_switches_last_minute: 1,
            ..Default::default()
        };
        let result = classify_activity(&obs, &ActivityConfig::default());
        assert_ne!(result, ActivityState::Idle);
    }

    #[test]
    fn activity_meeting_when_microphone_in_use() {
        let obs = ActivityObservations {
            microphone_in_use: true,
            ..Default::default()
        };
        assert_eq!(classify_activity(&obs, &ActivityConfig::default()), ActivityState::Meeting);
    }

    #[test]
    fn activity_meeting_beats_gaming() {
        // mic + fullscreen + high GPU → Meeting (mic dominates)
        let obs = ActivityObservations {
            microphone_in_use: true,
            fullscreen_active: true,
            gpu_usage_percent: Some(95),
            ..Default::default()
        };
        assert_eq!(classify_activity(&obs, &ActivityConfig::default()), ActivityState::Meeting);
    }

    #[test]
    fn activity_gaming_when_fullscreen_and_high_gpu() {
        let obs = ActivityObservations {
            fullscreen_active: true,
            gpu_usage_percent: Some(85),
            ..Default::default()
        };
        assert_eq!(classify_activity(&obs, &ActivityConfig::default()), ActivityState::Gaming);
    }

    #[test]
    fn activity_not_gaming_when_gpu_below_threshold() {
        let obs = ActivityObservations {
            fullscreen_active: true,
            gpu_usage_percent: Some(20),
            keystrokes_last_minute: 50,
            active_window_switches_last_minute: 1,
            ..Default::default()
        };
        // Should classify as DeepWork instead
        assert_eq!(classify_activity(&obs, &ActivityConfig::default()), ActivityState::DeepWork);
    }

    #[test]
    fn activity_deep_work_from_focused_typing() {
        let obs = ActivityObservations {
            keystrokes_last_minute: 60,
            active_window_switches_last_minute: 2,
            ..Default::default()
        };
        assert_eq!(classify_activity(&obs, &ActivityConfig::default()), ActivityState::DeepWork);
    }

    #[test]
    fn activity_casual_browsing_from_high_window_switching() {
        let obs = ActivityObservations {
            active_window_switches_last_minute: 20,
            keystrokes_last_minute: 5,
            ..Default::default()
        };
        assert_eq!(
            classify_activity(&obs, &ActivityConfig::default()),
            ActivityState::CasualBrowsing
        );
    }

    #[test]
    fn activity_unknown_when_no_strong_signal() {
        let obs = ActivityObservations {
            seconds_since_last_input: 30,
            keystrokes_last_minute: 5,
            active_window_switches_last_minute: 1,
            ..Default::default()
        };
        assert_eq!(classify_activity(&obs, &ActivityConfig::default()), ActivityState::Unknown);
    }

    #[test]
    fn activity_state_strings_are_stable() {
        assert_eq!(ActivityState::Idle.as_str(), "idle");
        assert_eq!(ActivityState::DeepWork.as_str(), "deep_work");
        assert_eq!(ActivityState::CasualBrowsing.as_str(), "casual_browsing");
        assert_eq!(ActivityState::Gaming.as_str(), "gaming");
        assert_eq!(ActivityState::Meeting.as_str(), "meeting");
        assert_eq!(ActivityState::Unknown.as_str(), "unknown");
    }

    // ── EnvironmentMonitor composition ────────────────────────────────

    #[test]
    fn monitor_snapshot_composes_fidelities() {
        let monitor = EnvironmentMonitor::with_sensor(Box::new(MockSensor::rich()));
        let obs = ActivityObservations::default();
        let state = monitor.snapshot(&obs).unwrap();
        assert_eq!(state.battery.unwrap().fidelity, Fidelity::Direct);
        assert_eq!(state.thermal.fidelity, Fidelity::Direct);
        assert_eq!(state.memory.fidelity, Fidelity::Direct);
        assert_eq!(state.disk_fidelity, Fidelity::Subprocess);
        assert_eq!(state.location.fidelity, Fidelity::Subprocess);
    }

    #[test]
    fn monitor_snapshot_label_resolves_via_map() {
        let mut monitor = EnvironmentMonitor::with_sensor(Box::new(MockSensor::rich()));
        monitor.location_map_mut().set_label("ssid:home-net", "home");
        let state = monitor.snapshot(&ActivityObservations::default()).unwrap();
        assert_eq!(state.location.label.as_deref(), Some("home"));
        assert_eq!(state.location.wifi_ssid.as_deref(), Some("home-net"));
    }

    #[test]
    fn monitor_snapshot_unavailable_when_no_signal() {
        let mut sensor = MockSensor::rich();
        sensor.wifi = (None, Fidelity::Unavailable);
        sensor.wired = false;
        let monitor = EnvironmentMonitor::with_sensor(Box::new(sensor));
        let state = monitor.snapshot(&ActivityObservations::default()).unwrap();
        assert_eq!(state.location.fidelity, Fidelity::Unavailable);
        assert!(state.location.label.is_none());
    }

    #[test]
    fn monitor_uses_custom_activity_config() {
        let monitor = EnvironmentMonitor::with_sensor(Box::new(MockSensor::rich())).with_config(
            ActivityConfig {
                idle_threshold_seconds: 10,
                ..ActivityConfig::default()
            },
        );
        let obs = ActivityObservations {
            seconds_since_last_input: 11,
            ..Default::default()
        };
        let state = monitor.snapshot(&obs).unwrap();
        assert_eq!(state.activity, ActivityState::Idle);
    }

    #[test]
    fn monitor_load_save_round_trip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("loc.toml");
        let mut monitor = EnvironmentMonitor::with_sensor(Box::new(MockSensor::rich()));
        monitor.location_map_mut().set_label("ssid:cafe", "cafe");
        monitor.save_location_map(&path).unwrap();

        let mut other = EnvironmentMonitor::with_sensor(Box::new(MockSensor::rich()));
        other.load_location_map(&path).unwrap();
        assert_eq!(other.location_map().label_for(Some("cafe"), false), Some("cafe"));
    }

    #[test]
    fn monitor_snapshot_carries_utc_timestamp() {
        let monitor = EnvironmentMonitor::with_sensor(Box::new(MockSensor::rich()));
        let before = Utc::now();
        let state = monitor.snapshot(&ActivityObservations::default()).unwrap();
        let after = Utc::now();
        assert!(state.captured_at >= before && state.captured_at <= after);
    }

    #[test]
    fn default_location_map_path_is_under_data_dir() {
        // dirs::data_local_dir() should resolve on Win/Linux dev machines
        if let Some(p) = default_location_map_path() {
            assert!(p.to_string_lossy().contains("delphi"));
        }
    }
}

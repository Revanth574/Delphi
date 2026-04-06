// SPDX-License-Identifier: MIT

//! Hardware detection for model selection.
//!
//! Reads system information to determine available RAM, GPU presence,
//! and GPU memory. This drives the model selection logic from the spec
//! (Section 2.3.1).

use std::path::Path;

use tracing::info;

/// Detected hardware profile.
///
/// # Examples
///
/// ```
/// use die_inference::hardware::HardwareProfile;
///
/// let profile = HardwareProfile {
///     total_ram_mb: 16384,
///     available_ram_mb: 12000,
///     gpu: None,
///     cpu_cores: 8,
/// };
/// assert!(profile.total_ram_mb > 0);
/// ```
#[derive(Debug, Clone)]
pub struct HardwareProfile {
    /// Total system RAM in megabytes.
    pub total_ram_mb: u64,
    /// Available system RAM in megabytes.
    pub available_ram_mb: u64,
    /// Detected GPU (if any).
    pub gpu: Option<GpuInfo>,
    /// Number of CPU cores.
    pub cpu_cores: usize,
}

/// GPU information.
///
/// # Examples
///
/// ```
/// use die_inference::hardware::GpuInfo;
///
/// let gpu = GpuInfo {
///     vendor: "NVIDIA".to_string(),
///     name: "RTX 3060".to_string(),
///     vram_mb: 6144,
/// };
/// assert_eq!(gpu.vendor, "NVIDIA");
/// ```
#[derive(Debug, Clone)]
pub struct GpuInfo {
    /// GPU vendor (NVIDIA, AMD, Intel).
    pub vendor: String,
    /// GPU model name.
    pub name: String,
    /// GPU VRAM in megabytes.
    pub vram_mb: u64,
}

/// Recommended model parameters based on hardware.
///
/// # Examples
///
/// ```
/// use die_inference::hardware::ModelRecommendation;
///
/// let rec = ModelRecommendation {
///     max_params_b: 7,
///     gpu_layers: 0,
///     context_size: 2048,
///     description: "7B model, CPU only".to_string(),
/// };
/// assert_eq!(rec.max_params_b, 7);
/// ```
#[derive(Debug, Clone)]
pub struct ModelRecommendation {
    /// Maximum model size in billions of parameters.
    pub max_params_b: u32,
    /// Number of layers to offload to GPU (0 = CPU only).
    pub gpu_layers: u32,
    /// Recommended context window size.
    pub context_size: u32,
    /// Human-readable description of the recommendation.
    pub description: String,
}

/// Detect hardware capabilities.
///
/// Reads `/proc/meminfo` for RAM and checks for GPU presence
/// via `/proc/driver/nvidia`, `/sys/class/drm`, and `nvidia-smi`.
///
/// # Examples
///
/// ```
/// use die_inference::hardware::detect;
///
/// let profile = detect();
/// assert!(profile.cpu_cores > 0);
/// ```
#[must_use]
pub fn detect() -> HardwareProfile {
    let (total_ram_mb, available_ram_mb) = read_meminfo();
    let gpu = detect_gpu();
    let cpu_cores = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);

    let profile = HardwareProfile {
        total_ram_mb,
        available_ram_mb,
        gpu,
        cpu_cores,
    };

    info!(
        total_ram_mb = profile.total_ram_mb,
        available_ram_mb = profile.available_ram_mb,
        cpu_cores = profile.cpu_cores,
        gpu = ?profile.gpu.as_ref().map(|g| &g.name),
        "hardware detected"
    );

    profile
}

/// Recommend model parameters based on hardware.
///
/// Implements the selection logic from the spec:
/// - <4GB: 1-3B model, warn about limited capability
/// - 4-8GB: 3-7B model (4-bit quantized)
/// - 8-16GB: 7-13B model
/// - 16GB+: 13B+ model
///
/// # Examples
///
/// ```
/// use die_inference::hardware::{HardwareProfile, recommend_model};
///
/// let profile = HardwareProfile {
///     total_ram_mb: 8192,
///     available_ram_mb: 6000,
///     gpu: None,
///     cpu_cores: 4,
/// };
/// let rec = recommend_model(&profile);
/// assert!(rec.max_params_b >= 3);
/// ```
#[must_use]
pub fn recommend_model(profile: &HardwareProfile) -> ModelRecommendation {
    let ram_gb = profile.total_ram_mb / 1024;

    let (max_params_b, context_size, base_desc) = if ram_gb < 4 {
        (3, 1024, "1-3B model (limited RAM)")
    } else if ram_gb < 8 {
        (7, 2048, "3-7B 4-bit quantized model")
    } else if ram_gb < 16 {
        (13, 4096, "7-13B model")
    } else {
        (30, 8192, "13B+ model")
    };

    // GPU offloading: if we have a GPU, offload layers proportional to VRAM.
    let gpu_layers = profile
        .gpu
        .as_ref()
        .map(|gpu| {
            // Rough heuristic: ~200MB per layer for 7B model.
            let layers = (gpu.vram_mb / 200).min(40);
            layers as u32
        })
        .unwrap_or(0);

    let description = if gpu_layers > 0 {
        let gpu_name = profile
            .gpu
            .as_ref()
            .map(|g| g.name.as_str())
            .unwrap_or("unknown GPU");
        format!("{base_desc} with {gpu_layers} GPU layers on {gpu_name}")
    } else {
        format!("{base_desc}, CPU only")
    };

    let rec = ModelRecommendation {
        max_params_b,
        gpu_layers,
        context_size,
        description: description.clone(),
    };

    info!(
        max_params_b,
        gpu_layers,
        context_size,
        description,
        "model recommendation"
    );

    rec
}

/// Read memory info from `/proc/meminfo`.
fn read_meminfo() -> (u64, u64) {
    read_meminfo_from_path("/proc/meminfo")
}

/// Read memory info from a given path (testable).
fn read_meminfo_from_path(path: &str) -> (u64, u64) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return (0, 0),
    };

    let mut total_kb = 0u64;
    let mut available_kb = 0u64;

    for line in content.lines() {
        if let Some(val) = line.strip_prefix("MemTotal:") {
            total_kb = parse_meminfo_value(val);
        } else if let Some(val) = line.strip_prefix("MemAvailable:") {
            available_kb = parse_meminfo_value(val);
        }
    }

    (total_kb / 1024, available_kb / 1024)
}

/// Parse a `/proc/meminfo` value like "  16384000 kB".
fn parse_meminfo_value(val: &str) -> u64 {
    val.split_whitespace()
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Detect GPU presence.
fn detect_gpu() -> Option<GpuInfo> {
    // Try NVIDIA first.
    if Path::new("/proc/driver/nvidia").exists() {
        return Some(GpuInfo {
            vendor: "NVIDIA".to_string(),
            name: read_nvidia_name().unwrap_or_else(|| "NVIDIA GPU".to_string()),
            vram_mb: read_nvidia_vram().unwrap_or(0),
        });
    }

    // Try AMD via /sys/class/drm.
    if let Some(amd) = detect_amd_gpu() {
        return Some(amd);
    }

    None
}

/// Read NVIDIA GPU name from nvidia-smi or proc.
fn read_nvidia_name() -> Option<String> {
    std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=name", "--format=csv,noheader,nounits"])
        .output()
        .ok()
        .and_then(|out| {
            String::from_utf8(out.stdout)
                .ok()
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty())
}

/// Read NVIDIA VRAM from nvidia-smi.
fn read_nvidia_vram() -> Option<u64> {
    std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=memory.total", "--format=csv,noheader,nounits"])
        .output()
        .ok()
        .and_then(|out| {
            String::from_utf8(out.stdout)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
        })
}

/// Detect AMD GPU via /sys/class/drm.
fn detect_amd_gpu() -> Option<GpuInfo> {
    let drm_path = Path::new("/sys/class/drm");
    if !drm_path.exists() {
        return None;
    }

    let entries = std::fs::read_dir(drm_path).ok()?;
    for entry in entries.flatten() {
        let vendor_path = entry.path().join("device/vendor");
        if let Ok(vendor) = std::fs::read_to_string(&vendor_path) {
            // AMD vendor ID = 0x1002.
            if vendor.trim() == "0x1002" {
                return Some(GpuInfo {
                    vendor: "AMD".to_string(),
                    name: "AMD GPU".to_string(),
                    vram_mb: 0, // Would need more parsing for VRAM.
                });
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn detect_returns_valid_profile() {
        let profile = detect();
        assert!(profile.cpu_cores > 0);
    }

    #[test]
    fn parse_meminfo_value_handles_whitespace() {
        assert_eq!(parse_meminfo_value("  16384000 kB"), 16_384_000);
        assert_eq!(parse_meminfo_value("0 kB"), 0);
    }

    #[test]
    fn read_meminfo_from_fake_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meminfo");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "MemTotal:       16384000 kB").unwrap();
        writeln!(f, "MemFree:         4096000 kB").unwrap();
        writeln!(f, "MemAvailable:   12288000 kB").unwrap();

        let (total, avail) = read_meminfo_from_path(path.to_str().unwrap());
        assert_eq!(total, 16_000); // 16384000 / 1024
        assert_eq!(avail, 12_000); // 12288000 / 1024
    }

    #[test]
    fn read_meminfo_missing_file_returns_zero() {
        let (total, avail) = read_meminfo_from_path("/nonexistent/path");
        assert_eq!(total, 0);
        assert_eq!(avail, 0);
    }

    #[test]
    fn recommend_low_ram() {
        let profile = HardwareProfile {
            total_ram_mb: 3072,
            available_ram_mb: 2000,
            gpu: None,
            cpu_cores: 2,
        };
        let rec = recommend_model(&profile);
        assert_eq!(rec.max_params_b, 3);
        assert_eq!(rec.gpu_layers, 0);
    }

    #[test]
    fn recommend_medium_ram() {
        // 6GB falls into 4-8GB bracket → max 7B model.
        let profile = HardwareProfile {
            total_ram_mb: 6144,
            available_ram_mb: 4000,
            gpu: None,
            cpu_cores: 4,
        };
        let rec = recommend_model(&profile);
        assert_eq!(rec.max_params_b, 7);
    }

    #[test]
    fn recommend_8gb_gets_larger_model() {
        // 8GB exactly → falls into 8-16GB bracket → max 13B model.
        let profile = HardwareProfile {
            total_ram_mb: 8192,
            available_ram_mb: 6000,
            gpu: None,
            cpu_cores: 4,
        };
        let rec = recommend_model(&profile);
        assert_eq!(rec.max_params_b, 13);
    }

    #[test]
    fn recommend_high_ram_with_gpu() {
        let profile = HardwareProfile {
            total_ram_mb: 32768,
            available_ram_mb: 28000,
            gpu: Some(GpuInfo {
                vendor: "NVIDIA".to_string(),
                name: "RTX 4090".to_string(),
                vram_mb: 24576,
            }),
            cpu_cores: 16,
        };
        let rec = recommend_model(&profile);
        assert_eq!(rec.max_params_b, 30);
        assert!(rec.gpu_layers > 0);
        assert!(rec.description.contains("RTX 4090"));
    }
}

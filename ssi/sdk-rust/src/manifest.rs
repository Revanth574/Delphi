// SPDX-License-Identifier: MIT

//! SSI manifest types.
//!
//! A manifest describes an application's capabilities as discovered by
//! the auto-generation scanners. Capabilities include confidence scores
//! because auto-generated manifests are APPROXIMATIONS — per CLAUDE.md
//! Section 4, the confidence score must be presented to the user.
//!
//! # Trust Model
//!
//! SSI never trusts app-reported capabilities. Every capability in a
//! manifest was discovered via scanning and has a confidence score
//! indicating how reliable the discovery was.

use serde::{Deserialize, Serialize};

/// An SSI manifest describing an application's capabilities.
///
/// # Examples
///
/// ```
/// use ssi::manifest::SsiManifest;
///
/// let manifest = SsiManifest::new("org.gnome.TextEditor", "Text Editor");
/// assert_eq!(manifest.app_id, "org.gnome.TextEditor");
/// assert!(manifest.capabilities.is_empty());
/// assert_eq!(manifest.overall_confidence(), 0.0);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsiManifest {
    /// Application identifier (reverse-DNS format).
    pub app_id: String,
    /// Human-readable application name.
    pub app_name: String,
    /// Discovered capabilities.
    pub capabilities: Vec<Capability>,
    /// Unix timestamp when this manifest was generated.
    pub generated_at: i64,
}

impl SsiManifest {
    /// Create a new empty manifest for an application.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::manifest::SsiManifest;
    ///
    /// let manifest = SsiManifest::new("org.firefox.Firefox", "Firefox");
    /// assert_eq!(manifest.app_name, "Firefox");
    /// ```
    #[must_use]
    pub fn new(app_id: &str, app_name: &str) -> Self {
        let generated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        Self {
            app_id: app_id.to_string(),
            app_name: app_name.to_string(),
            capabilities: Vec::new(),
            generated_at,
        }
    }

    /// Add a capability to the manifest.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::manifest::{SsiManifest, Capability, CapabilitySource};
    ///
    /// let mut manifest = SsiManifest::new("org.app", "App");
    /// manifest.add_capability(Capability {
    ///     name: "file.open".to_string(),
    ///     description: "Open a file".to_string(),
    ///     parameters: vec![],
    ///     confidence: 0.9,
    ///     source: CapabilitySource::Desktop,
    ///     offline_support: true,
    /// });
    /// assert_eq!(manifest.capabilities.len(), 1);
    /// ```
    pub fn add_capability(&mut self, capability: Capability) {
        self.capabilities.push(capability);
    }

    /// Overall confidence across all capabilities.
    ///
    /// Returns the mean confidence score. Returns 0.0 for empty manifests.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::manifest::{SsiManifest, Capability, CapabilitySource};
    ///
    /// let mut manifest = SsiManifest::new("org.app", "App");
    /// manifest.add_capability(Capability {
    ///     name: "cap1".to_string(),
    ///     description: "test".to_string(),
    ///     parameters: vec![],
    ///     confidence: 0.8,
    ///     source: CapabilitySource::Dbus,
    ///     offline_support: true,
    /// });
    /// manifest.add_capability(Capability {
    ///     name: "cap2".to_string(),
    ///     description: "test".to_string(),
    ///     parameters: vec![],
    ///     confidence: 0.6,
    ///     source: CapabilitySource::AtSpi,
    ///     offline_support: false,
    /// });
    /// // (0.8 + 0.6) / 2 = 0.7
    /// assert!((manifest.overall_confidence() - 0.7).abs() < 0.001);
    /// ```
    #[must_use]
    pub fn overall_confidence(&self) -> f64 {
        if self.capabilities.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.capabilities.iter().map(|c| c.confidence).sum();
        sum / self.capabilities.len() as f64
    }

    /// Number of high-confidence capabilities (>= 0.7).
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::manifest::{SsiManifest, Capability, CapabilitySource};
    ///
    /// let mut manifest = SsiManifest::new("org.app", "App");
    /// manifest.add_capability(Capability {
    ///     name: "high".to_string(),
    ///     description: "test".to_string(),
    ///     parameters: vec![],
    ///     confidence: 0.9,
    ///     source: CapabilitySource::Desktop,
    ///     offline_support: true,
    /// });
    /// manifest.add_capability(Capability {
    ///     name: "low".to_string(),
    ///     description: "test".to_string(),
    ///     parameters: vec![],
    ///     confidence: 0.3,
    ///     source: CapabilitySource::AtSpi,
    ///     offline_support: false,
    /// });
    /// assert_eq!(manifest.high_confidence_count(), 1);
    /// ```
    #[must_use]
    pub fn high_confidence_count(&self) -> usize {
        self.capabilities
            .iter()
            .filter(|c| c.confidence >= 0.7)
            .count()
    }
}

/// A single discovered capability.
///
/// # Examples
///
/// ```
/// use ssi::manifest::{Capability, CapabilitySource, Parameter};
///
/// let cap = Capability {
///     name: "image.adjust_brightness".to_string(),
///     description: "Adjust image brightness".to_string(),
///     parameters: vec![
///         Parameter {
///             name: "level".to_string(),
///             param_type: "f64".to_string(),
///             required: true,
///             description: "Brightness level 0.0-1.0".to_string(),
///         },
///     ],
///     confidence: 0.85,
///     source: CapabilitySource::AtSpi,
///     offline_support: true,
/// };
/// assert!(cap.is_high_confidence());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    /// Capability name (dot-separated namespace).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Parameters this capability accepts.
    pub parameters: Vec<Parameter>,
    /// Confidence score (0.0–1.0) — how reliable the discovery was.
    pub confidence: f64,
    /// Where this capability was discovered.
    pub source: CapabilitySource,
    /// Whether this capability works offline.
    pub offline_support: bool,
}

impl Capability {
    /// Whether this capability has high confidence (>= 0.7).
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::manifest::{Capability, CapabilitySource};
    ///
    /// let high = Capability {
    ///     name: "test".to_string(),
    ///     description: "test".to_string(),
    ///     parameters: vec![],
    ///     confidence: 0.9,
    ///     source: CapabilitySource::Desktop,
    ///     offline_support: true,
    /// };
    /// assert!(high.is_high_confidence());
    /// ```
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.7
    }
}

/// A parameter for a capability.
///
/// # Examples
///
/// ```
/// use ssi::manifest::Parameter;
///
/// let param = Parameter {
///     name: "path".to_string(),
///     param_type: "String".to_string(),
///     required: true,
///     description: "File path to open".to_string(),
/// };
/// assert!(param.required);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    /// Parameter name.
    pub name: String,
    /// Type description (e.g., "String", "f64", "bool").
    pub param_type: String,
    /// Whether this parameter is required.
    pub required: bool,
    /// Human-readable description.
    pub description: String,
}

/// Where a capability was discovered.
///
/// # Examples
///
/// ```
/// use ssi::manifest::CapabilitySource;
///
/// let source = CapabilitySource::AtSpi;
/// assert_eq!(source.as_str(), "at-spi");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilitySource {
    /// Discovered via AT-SPI accessibility tree.
    AtSpi,
    /// Discovered via D-Bus introspection.
    Dbus,
    /// Discovered from .desktop entry file.
    Desktop,
    /// Manually created by the user.
    Manual,
}

impl CapabilitySource {
    /// String representation.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::manifest::CapabilitySource;
    ///
    /// assert_eq!(CapabilitySource::Dbus.as_str(), "dbus");
    /// assert_eq!(CapabilitySource::Manual.as_str(), "manual");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AtSpi => "at-spi",
            Self::Dbus => "dbus",
            Self::Desktop => "desktop",
            Self::Manual => "manual",
        }
    }

    /// Base confidence for this source type.
    ///
    /// Desktop entries are most reliable (explicit declarations),
    /// D-Bus introspection is reliable (structured API), AT-SPI
    /// is least reliable (inferred from UI structure).
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::manifest::CapabilitySource;
    ///
    /// assert!(CapabilitySource::Desktop.base_confidence()
    ///     > CapabilitySource::AtSpi.base_confidence());
    /// ```
    #[must_use]
    pub fn base_confidence(&self) -> f64 {
        match self {
            Self::Desktop => 0.9,
            Self::Dbus => 0.8,
            Self::AtSpi => 0.6,
            Self::Manual => 1.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_manifest_is_empty() {
        let m = SsiManifest::new("org.app", "App");
        assert!(m.capabilities.is_empty());
        assert_eq!(m.overall_confidence(), 0.0);
        assert!(m.generated_at > 0);
    }

    #[test]
    fn add_capability_grows_manifest() {
        let mut m = SsiManifest::new("org.app", "App");
        m.add_capability(Capability {
            name: "test".into(),
            description: "test cap".into(),
            parameters: vec![],
            confidence: 0.8,
            source: CapabilitySource::Desktop,
            offline_support: true,
        });
        assert_eq!(m.capabilities.len(), 1);
    }

    #[test]
    fn overall_confidence_mean() {
        let mut m = SsiManifest::new("org.app", "App");
        m.add_capability(Capability {
            name: "a".into(),
            description: "".into(),
            parameters: vec![],
            confidence: 0.8,
            source: CapabilitySource::Dbus,
            offline_support: true,
        });
        m.add_capability(Capability {
            name: "b".into(),
            description: "".into(),
            parameters: vec![],
            confidence: 0.6,
            source: CapabilitySource::AtSpi,
            offline_support: false,
        });
        assert!((m.overall_confidence() - 0.7).abs() < 0.001);
    }

    #[test]
    fn high_confidence_filter() {
        let mut m = SsiManifest::new("org.app", "App");
        m.add_capability(Capability {
            name: "high".into(),
            description: "".into(),
            parameters: vec![],
            confidence: 0.9,
            source: CapabilitySource::Desktop,
            offline_support: true,
        });
        m.add_capability(Capability {
            name: "low".into(),
            description: "".into(),
            parameters: vec![],
            confidence: 0.3,
            source: CapabilitySource::AtSpi,
            offline_support: false,
        });
        assert_eq!(m.high_confidence_count(), 1);
    }

    #[test]
    fn capability_confidence_check() {
        let cap = Capability {
            name: "test".into(),
            description: "".into(),
            parameters: vec![],
            confidence: 0.5,
            source: CapabilitySource::Dbus,
            offline_support: true,
        };
        assert!(!cap.is_high_confidence());
    }

    #[test]
    fn capability_source_strings() {
        assert_eq!(CapabilitySource::AtSpi.as_str(), "at-spi");
        assert_eq!(CapabilitySource::Dbus.as_str(), "dbus");
        assert_eq!(CapabilitySource::Desktop.as_str(), "desktop");
        assert_eq!(CapabilitySource::Manual.as_str(), "manual");
    }

    #[test]
    fn base_confidence_ordering() {
        assert!(CapabilitySource::Manual.base_confidence()
            > CapabilitySource::Desktop.base_confidence());
        assert!(CapabilitySource::Desktop.base_confidence()
            > CapabilitySource::Dbus.base_confidence());
        assert!(CapabilitySource::Dbus.base_confidence()
            > CapabilitySource::AtSpi.base_confidence());
    }

    #[test]
    fn manifest_serialization_roundtrip() {
        let mut m = SsiManifest::new("org.test", "Test");
        m.add_capability(Capability {
            name: "file.open".into(),
            description: "Open files".into(),
            parameters: vec![Parameter {
                name: "path".into(),
                param_type: "String".into(),
                required: true,
                description: "File path".into(),
            }],
            confidence: 0.85,
            source: CapabilitySource::Desktop,
            offline_support: true,
        });
        let json = serde_json::to_string(&m).unwrap();
        let deserialized: SsiManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.app_id, "org.test");
        assert_eq!(deserialized.capabilities.len(), 1);
    }

    #[test]
    fn parameter_fields() {
        let p = Parameter {
            name: "level".into(),
            param_type: "f64".into(),
            required: false,
            description: "Brightness level".into(),
        };
        assert!(!p.required);
        assert_eq!(p.param_type, "f64");
    }
}

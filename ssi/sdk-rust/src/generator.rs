// SPDX-License-Identifier: MIT

//! Manifest generator — combines scanner results into SSI manifests.
//!
//! The generator runs all configured scanners against an application
//! and merges the results into a single manifest with confidence
//! scores.
//!
//! # Performance Budget
//!
//! SSI app scan per app: **< 2 seconds** (CLAUDE.md Section 9).

use tracing::{info, warn};

use crate::error::SsiError;
use crate::manifest::SsiManifest;
use crate::scanner::Scanner;

/// Generates SSI manifests by running multiple scanners.
///
/// # Examples
///
/// ```
/// use ssi::generator::ManifestGenerator;
/// use ssi::scanner::{DesktopEntryScanner, DbusScanner};
///
/// let mut mg =ManifestGenerator::new();
/// mg.add_scanner(Box::new(DesktopEntryScanner::new()));
/// mg.add_scanner(Box::new(DbusScanner::new()));
/// assert_eq!(mg.scanner_count(), 2);
/// ```
pub struct ManifestGenerator {
    /// Registered scanners.
    scanners: Vec<Box<dyn Scanner>>,
}

impl ManifestGenerator {
    /// Create a new generator with no scanners.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::generator::ManifestGenerator;
    ///
    /// let mg =ManifestGenerator::new();
    /// assert_eq!(mg.scanner_count(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            scanners: Vec::new(),
        }
    }

    /// Create a generator with all default scanners.
    ///
    /// Includes: `DesktopEntryScanner`, `DbusScanner`, `AtSpiScanner`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::generator::ManifestGenerator;
    ///
    /// let mg =ManifestGenerator::with_defaults();
    /// assert_eq!(mg.scanner_count(), 3);
    /// ```
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut mg = Self::new();
        mg.add_scanner(Box::new(crate::scanner::DesktopEntryScanner::new()));
        mg.add_scanner(Box::new(crate::scanner::DbusScanner::new()));
        mg.add_scanner(Box::new(crate::scanner::AtSpiScanner::new()));
        mg
    }

    /// Add a scanner to the generator.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::generator::ManifestGenerator;
    /// use ssi::scanner::DesktopEntryScanner;
    ///
    /// let mut mg =ManifestGenerator::new();
    /// mg.add_scanner(Box::new(DesktopEntryScanner::new()));
    /// assert_eq!(mg.scanner_count(), 1);
    /// ```
    pub fn add_scanner(&mut self, scanner: Box<dyn Scanner>) {
        self.scanners.push(scanner);
    }

    /// Number of registered scanners.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::generator::ManifestGenerator;
    ///
    /// let mg =ManifestGenerator::new();
    /// assert_eq!(mg.scanner_count(), 0);
    /// ```
    #[must_use]
    pub fn scanner_count(&self) -> usize {
        self.scanners.len()
    }

    /// Generate a manifest for an application.
    ///
    /// Runs all scanners and merges results. Individual scanner
    /// failures are logged but don't abort the generation — this is
    /// graceful degradation.
    ///
    /// # Errors
    ///
    /// Returns an error only if the app_id is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::generator::ManifestGenerator;
    /// use ssi::scanner::DbusScanner;
    ///
    /// let mut mg =ManifestGenerator::new();
    /// mg.add_scanner(Box::new(DbusScanner::new()));
    /// let manifest = mg.generate("org.test.App", "Test App").unwrap();
    /// assert_eq!(manifest.app_id, "org.test.App");
    /// ```
    pub fn generate(
        &self,
        app_id: &str,
        app_name: &str,
    ) -> Result<SsiManifest, SsiError> {
        if app_id.is_empty() {
            return Err(SsiError::ManifestValidation(
                "app_id cannot be empty".to_string(),
            ));
        }

        info!(
            app_id,
            app_name,
            scanners = self.scanners.len(),
            "generating SSI manifest"
        );

        let mut manifest = SsiManifest::new(app_id, app_name);

        for scanner in &self.scanners {
            match scanner.scan(app_id) {
                Ok(capabilities) => {
                    info!(
                        scanner = scanner.name(),
                        count = capabilities.len(),
                        "scanner returned capabilities"
                    );
                    for cap in capabilities {
                        manifest.add_capability(cap);
                    }
                }
                Err(e) => {
                    // Graceful degradation: log and continue.
                    warn!(
                        scanner = scanner.name(),
                        error = %e,
                        "scanner failed — continuing with other scanners"
                    );
                }
            }
        }

        info!(
            app_id,
            capabilities = manifest.capabilities.len(),
            confidence = format!("{:.1}%", manifest.overall_confidence() * 100.0),
            "manifest generated"
        );

        Ok(manifest)
    }

    /// Generate manifests for multiple applications.
    ///
    /// Returns a list of (app_id, Result) pairs. Failures for
    /// individual apps don't affect others.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::generator::ManifestGenerator;
    ///
    /// let mg =ManifestGenerator::new();
    /// let apps = vec![
    ///     ("org.a", "App A"),
    ///     ("org.b", "App B"),
    /// ];
    /// let results = mg.generate_batch(&apps);
    /// assert_eq!(results.len(), 2);
    /// ```
    #[must_use]
    pub fn generate_batch(
        &self,
        apps: &[(&str, &str)],
    ) -> Vec<(String, Result<SsiManifest, SsiError>)> {
        apps.iter()
            .map(|(id, name)| {
                let result = self.generate(id, name);
                (id.to_string(), result)
            })
            .collect()
    }
}

impl Default for ManifestGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::CapabilitySource;

    #[test]
    fn new_generator_empty() {
        let mg =ManifestGenerator::new();
        assert_eq!(mg.scanner_count(), 0);
    }

    #[test]
    fn default_generator() {
        let mg =ManifestGenerator::default();
        assert_eq!(mg.scanner_count(), 0);
    }

    #[test]
    fn with_defaults_has_three_scanners() {
        let mg =ManifestGenerator::with_defaults();
        assert_eq!(mg.scanner_count(), 3);
    }

    #[test]
    fn add_scanner_increments_count() {
        let mut mg =ManifestGenerator::new();
        mg.add_scanner(Box::new(crate::scanner::DesktopEntryScanner::new()));
        assert_eq!(mg.scanner_count(), 1);
    }

    #[test]
    fn generate_empty_app_id_fails() {
        let mg =ManifestGenerator::new();
        let result = mg.generate("", "App");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn generate_no_scanners_returns_empty_manifest() {
        let mg =ManifestGenerator::new();
        let manifest = mg.generate("org.test", "Test").unwrap();
        assert_eq!(manifest.app_id, "org.test");
        assert!(manifest.capabilities.is_empty());
    }

    #[test]
    fn generate_with_dbus_scanner() {
        let mut mg =ManifestGenerator::new();
        mg.add_scanner(Box::new(crate::scanner::DbusScanner::new()));

        let manifest = mg.generate("org.test", "Test App").unwrap();
        assert_eq!(manifest.app_id, "org.test");
        // D-Bus scanner returns empty without a real bus.
        assert!(manifest.capabilities.is_empty());
    }

    #[test]
    fn generate_graceful_on_scanner_failure() {
        // AT-SPI scanner fails, but generation still succeeds.
        let mg =ManifestGenerator::with_defaults();
        let manifest = mg.generate("org.test.App", "Test").unwrap();
        assert_eq!(manifest.app_id, "org.test.App");
        // Some scanners may fail, but the manifest is still valid.
    }

    #[test]
    fn generate_batch_processes_all_apps() {
        let mg =ManifestGenerator::new();
        let apps = vec![
            ("org.a", "App A"),
            ("org.b", "App B"),
            ("org.c", "App C"),
        ];
        let results = mg.generate_batch(&apps);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|(_, r)| r.is_ok()));
    }

    #[test]
    fn generate_batch_empty_id_fails() {
        let mg =ManifestGenerator::new();
        let apps = vec![("org.ok", "OK"), ("", "Bad")];
        let results = mg.generate_batch(&apps);
        assert!(results[0].1.is_ok());
        assert!(results[1].1.is_err());
    }

    /// Mock scanner for testing the generator pipeline.
    struct MockScanner {
        caps: Vec<crate::manifest::Capability>,
    }

    impl Scanner for MockScanner {
        fn name(&self) -> &str {
            "mock"
        }

        fn scan(&self, _app_id: &str) -> Result<Vec<crate::manifest::Capability>, SsiError> {
            Ok(self.caps.clone())
        }
    }

    #[test]
    fn generate_with_mock_scanner() {
        let mut mg =ManifestGenerator::new();
        mg.add_scanner(Box::new(MockScanner {
            caps: vec![
                crate::manifest::Capability {
                    name: "test.cap".to_string(),
                    description: "A test capability".to_string(),
                    parameters: vec![],
                    confidence: 0.85,
                    source: CapabilitySource::Manual,
                    offline_support: true,
                },
            ],
        }));

        let manifest = mg.generate("org.test", "Test").unwrap();
        assert_eq!(manifest.capabilities.len(), 1);
        assert_eq!(manifest.capabilities[0].name, "test.cap");
        assert!((manifest.overall_confidence() - 0.85).abs() < 0.001);
    }

    #[test]
    fn generate_merges_multiple_scanners() {
        let mut mg =ManifestGenerator::new();

        mg.add_scanner(Box::new(MockScanner {
            caps: vec![crate::manifest::Capability {
                name: "from.scanner1".to_string(),
                description: "test".to_string(),
                parameters: vec![],
                confidence: 0.9,
                source: CapabilitySource::Desktop,
                offline_support: true,
            }],
        }));

        mg.add_scanner(Box::new(MockScanner {
            caps: vec![crate::manifest::Capability {
                name: "from.scanner2".to_string(),
                description: "test".to_string(),
                parameters: vec![],
                confidence: 0.7,
                source: CapabilitySource::Dbus,
                offline_support: true,
            }],
        }));

        let manifest = mg.generate("org.multi", "Multi").unwrap();
        assert_eq!(manifest.capabilities.len(), 2);
        assert!((manifest.overall_confidence() - 0.8).abs() < 0.001);
    }
}

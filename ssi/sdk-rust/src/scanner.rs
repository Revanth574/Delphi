// SPDX-License-Identifier: MIT

//! Application scanners for SSI auto-generation.
//!
//! Three scanner types discover capabilities from running applications:
//!
//! 1. **DesktopEntryScanner** — reads `.desktop` files for declared actions
//! 2. **DbusScanner** — introspects D-Bus interfaces for available methods
//! 3. **AtSpiScanner** — reads AT-SPI accessibility trees for UI actions
//!
//! # Boundaries (CLAUDE.md Section 4)
//!
//! - SSI auto-generation MUST NOT execute discovered capabilities
//! - SSI MUST NOT scan apps in Focus mode
//! - SSI manifests are approximations — confidence scores are mandatory

use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::error::SsiError;
use crate::manifest::{Capability, CapabilitySource, Parameter};

/// Trait for application capability scanners.
///
/// Each scanner implementation discovers capabilities from a different
/// source and assigns confidence scores based on the reliability of
/// that source.
///
/// # Examples
///
/// ```
/// use ssi::scanner::{Scanner, DesktopEntryScanner};
///
/// let scanner = DesktopEntryScanner::new();
/// assert_eq!(scanner.name(), "desktop-entry");
/// ```
pub trait Scanner: Send + Sync {
    /// Human-readable name of this scanner.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::scanner::{Scanner, DbusScanner};
    ///
    /// let scanner = DbusScanner::new();
    /// assert_eq!(scanner.name(), "dbus-introspection");
    /// ```
    fn name(&self) -> &str;

    /// Scan an application and return discovered capabilities.
    ///
    /// # Errors
    ///
    /// Returns an error if the scan fails (e.g., app not found,
    /// accessibility tree unavailable).
    fn scan(&self, app_id: &str) -> Result<Vec<Capability>, SsiError>;
}

/// Scans `.desktop` entry files for application capabilities.
///
/// Desktop entries contain structured information about application
/// actions (open, new-window, etc.) and MIME types. This is the
/// most reliable auto-generation source because desktop entries are
/// explicit declarations.
///
/// # Examples
///
/// ```
/// use ssi::scanner::{Scanner, DesktopEntryScanner};
///
/// let scanner = DesktopEntryScanner::new();
/// assert_eq!(scanner.source(), ssi::manifest::CapabilitySource::Desktop);
/// ```
pub struct DesktopEntryScanner {
    /// Directories to search for .desktop files.
    search_paths: Vec<PathBuf>,
}

impl DesktopEntryScanner {
    /// Create a new scanner with standard XDG paths.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::scanner::DesktopEntryScanner;
    ///
    /// let scanner = DesktopEntryScanner::new();
    /// assert!(!scanner.search_paths().is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        let mut search_paths = Vec::new();

        // Standard XDG application directories.
        search_paths.push(PathBuf::from("/usr/share/applications"));
        search_paths.push(PathBuf::from("/usr/local/share/applications"));

        if let Some(home) = dirs::home_dir() {
            search_paths.push(home.join(".local/share/applications"));
        }

        if let Some(data_dir) = dirs::data_dir() {
            search_paths.push(data_dir.join("applications"));
        }

        Self { search_paths }
    }

    /// Create a scanner with custom search paths (for testing).
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::scanner::DesktopEntryScanner;
    /// use std::path::PathBuf;
    ///
    /// let scanner = DesktopEntryScanner::with_paths(vec![
    ///     PathBuf::from("/tmp/test-apps"),
    /// ]);
    /// assert_eq!(scanner.search_paths().len(), 1);
    /// ```
    #[must_use]
    pub fn with_paths(search_paths: Vec<PathBuf>) -> Self {
        Self { search_paths }
    }

    /// Get the configured search paths.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::scanner::DesktopEntryScanner;
    ///
    /// let scanner = DesktopEntryScanner::new();
    /// assert!(scanner.search_paths().iter().any(|p| p.ends_with("applications")));
    /// ```
    #[must_use]
    pub fn search_paths(&self) -> &[PathBuf] {
        &self.search_paths
    }

    /// The capability source for this scanner.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::scanner::DesktopEntryScanner;
    /// use ssi::manifest::CapabilitySource;
    ///
    /// let scanner = DesktopEntryScanner::new();
    /// assert_eq!(scanner.source(), CapabilitySource::Desktop);
    /// ```
    #[must_use]
    pub fn source(&self) -> CapabilitySource {
        CapabilitySource::Desktop
    }

    /// Find the .desktop file for an app ID.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::scanner::DesktopEntryScanner;
    /// use std::path::PathBuf;
    ///
    /// let scanner = DesktopEntryScanner::with_paths(vec![
    ///     PathBuf::from("/nonexistent"),
    /// ]);
    /// assert!(scanner.find_desktop_file("org.test.App").is_none());
    /// ```
    #[must_use]
    pub fn find_desktop_file(&self, app_id: &str) -> Option<PathBuf> {
        let filename = format!("{app_id}.desktop");
        for dir in &self.search_paths {
            let path = dir.join(&filename);
            if path.exists() {
                return Some(path);
            }
        }
        None
    }

    /// Parse a .desktop file and extract capabilities.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::scanner::DesktopEntryScanner;
    ///
    /// let scanner = DesktopEntryScanner::new();
    /// // Will fail because file doesn't exist — graceful degradation
    /// let result = scanner.parse_desktop_file(std::path::Path::new("/nonexistent.desktop"));
    /// assert!(result.is_err());
    /// ```
    pub fn parse_desktop_file(&self, path: &Path) -> Result<Vec<Capability>, SsiError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            SsiError::DispatchFailed(format!("failed to read {}: {e}", path.display()))
        })?;

        let mut capabilities = Vec::new();
        let base_confidence = CapabilitySource::Desktop.base_confidence();

        // Parse [Desktop Entry] section for main action.
        if let Some(name) = extract_desktop_field(&content, "Name") {
            if let Some(exec) = extract_desktop_field(&content, "Exec") {
                capabilities.push(Capability {
                    name: "app.launch".to_string(),
                    description: format!("Launch {name}"),
                    parameters: vec![],
                    confidence: base_confidence,
                    source: CapabilitySource::Desktop,
                    offline_support: !exec.contains("http"),
                });
            }

            // Parse MimeType for file handling capabilities.
            if let Some(mime_types) = extract_desktop_field(&content, "MimeType") {
                for mime in mime_types.split(';').filter(|s| !s.is_empty()) {
                    capabilities.push(Capability {
                        name: format!("file.open.{}", mime.replace('/', ".")),
                        description: format!("{name} can open {mime} files"),
                        parameters: vec![Parameter {
                            name: "path".to_string(),
                            param_type: "String".to_string(),
                            required: true,
                            description: "File path to open".to_string(),
                        }],
                        confidence: base_confidence,
                        source: CapabilitySource::Desktop,
                        offline_support: true,
                    });
                }
            }
        }

        // Parse [Desktop Action *] sections.
        for action_name in extract_desktop_actions(&content) {
            let section = format!("[Desktop Action {action_name}]");
            if let Some(section_start) = content.find(&section) {
                let section_content = &content[section_start..];
                if let Some(name) = extract_desktop_field(section_content, "Name") {
                    capabilities.push(Capability {
                        name: format!("app.action.{}", action_name.to_lowercase()),
                        description: name.to_string(),
                        parameters: vec![],
                        confidence: base_confidence * 0.95,
                        source: CapabilitySource::Desktop,
                        offline_support: true,
                    });
                }
            }
        }

        Ok(capabilities)
    }
}

impl Default for DesktopEntryScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner for DesktopEntryScanner {
    fn name(&self) -> &str {
        "desktop-entry"
    }

    fn scan(&self, app_id: &str) -> Result<Vec<Capability>, SsiError> {
        info!(app_id, scanner = "desktop-entry", "scanning application");

        match self.find_desktop_file(app_id) {
            Some(path) => self.parse_desktop_file(&path),
            None => {
                warn!(app_id, "no .desktop file found");
                Ok(Vec::new())
            }
        }
    }
}

/// Scans D-Bus interfaces for available methods.
///
/// D-Bus introspection reveals the structured API an application
/// exposes. Each method becomes a potential capability with
/// parameter information.
///
/// # Examples
///
/// ```
/// use ssi::scanner::{Scanner, DbusScanner};
///
/// let scanner = DbusScanner::new();
/// assert_eq!(scanner.name(), "dbus-introspection");
/// ```
pub struct DbusScanner {
    /// D-Bus bus type to introspect.
    session_bus: bool,
}

impl DbusScanner {
    /// Create a new D-Bus scanner for the session bus.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::scanner::DbusScanner;
    ///
    /// let scanner = DbusScanner::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { session_bus: true }
    }

    /// Whether this scanner targets the session bus.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::scanner::DbusScanner;
    ///
    /// let scanner = DbusScanner::new();
    /// assert!(scanner.is_session_bus());
    /// ```
    #[must_use]
    pub fn is_session_bus(&self) -> bool {
        self.session_bus
    }

    /// Parse D-Bus introspection XML to extract capabilities.
    ///
    /// This is a simplified parser that extracts method names and
    /// parameter signatures. A full implementation would use a proper
    /// XML parser.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::scanner::DbusScanner;
    ///
    /// let scanner = DbusScanner::new();
    /// let xml = r#"
    ///   <interface name="org.example.Player">
    ///     <method name="Play"/>
    ///     <method name="Pause"/>
    ///   </interface>
    /// "#;
    /// let caps = scanner.parse_introspection(xml, "org.example.Player");
    /// assert_eq!(caps.len(), 2);
    /// assert!(caps[0].name.contains("Play"));
    /// ```
    #[must_use]
    pub fn parse_introspection(&self, xml: &str, interface: &str) -> Vec<Capability> {
        let mut capabilities = Vec::new();
        let base_confidence = CapabilitySource::Dbus.base_confidence();

        // Simple XML method extraction (real implementation would use xml-rs).
        for line in xml.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("<method name=\"")
                && let Some(name) = extract_xml_attr(trimmed, "name")
            {
                capabilities.push(Capability {
                    name: format!("{interface}.{name}"),
                    description: format!("D-Bus method: {name}"),
                    parameters: vec![],
                    confidence: base_confidence,
                    source: CapabilitySource::Dbus,
                    offline_support: true,
                });
            }
        }

        capabilities
    }
}

impl Default for DbusScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner for DbusScanner {
    fn name(&self) -> &str {
        "dbus-introspection"
    }

    fn scan(&self, app_id: &str) -> Result<Vec<Capability>, SsiError> {
        info!(app_id, scanner = "dbus-introspection", "scanning D-Bus interface");

        // In a real implementation, this would call:
        //   zbus::Connection::session() → introspect(app_id)
        // For Phase 2, we return an empty list (graceful degradation).
        // The actual D-Bus connection requires a running D-Bus daemon.
        warn!(
            app_id,
            "D-Bus introspection requires a running session bus — returning empty"
        );
        Ok(Vec::new())
    }
}

/// Scans AT-SPI accessibility trees for UI actions.
///
/// The AT-SPI (Assistive Technology Service Provider Interface)
/// provides a tree of UI elements with their roles and actions.
/// This is the least reliable source but discovers capabilities
/// that aren't explicitly declared anywhere.
///
/// # Examples
///
/// ```
/// use ssi::scanner::{Scanner, AtSpiScanner};
///
/// let scanner = AtSpiScanner::new();
/// assert_eq!(scanner.name(), "at-spi");
/// ```
pub struct AtSpiScanner {
    /// Maximum depth to traverse in the accessibility tree.
    max_depth: u32,
}

impl AtSpiScanner {
    /// Create a new AT-SPI scanner with default depth (5).
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::scanner::AtSpiScanner;
    ///
    /// let scanner = AtSpiScanner::new();
    /// assert_eq!(scanner.max_depth(), 5);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self { max_depth: 5 }
    }

    /// Create a scanner with custom max depth.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::scanner::AtSpiScanner;
    ///
    /// let scanner = AtSpiScanner::with_depth(10);
    /// assert_eq!(scanner.max_depth(), 10);
    /// ```
    #[must_use]
    pub fn with_depth(max_depth: u32) -> Self {
        Self { max_depth }
    }

    /// Maximum tree traversal depth.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::scanner::AtSpiScanner;
    ///
    /// let scanner = AtSpiScanner::new();
    /// assert_eq!(scanner.max_depth(), 5);
    /// ```
    #[must_use]
    pub fn max_depth(&self) -> u32 {
        self.max_depth
    }

    /// Parse accessibility tree nodes into capabilities.
    ///
    /// Takes a list of (role, name, action) tuples from the AT-SPI tree.
    ///
    /// # Examples
    ///
    /// ```
    /// use ssi::scanner::AtSpiScanner;
    ///
    /// let scanner = AtSpiScanner::new();
    /// let nodes = vec![
    ///     ("push button", "Save", "click"),
    ///     ("menu item", "Open File", "click"),
    ///     ("text", "Document content", ""),
    /// ];
    /// let caps = scanner.parse_accessibility_nodes(&nodes);
    /// // Only actionable nodes become capabilities
    /// assert_eq!(caps.len(), 2);
    /// ```
    #[must_use]
    pub fn parse_accessibility_nodes(
        &self,
        nodes: &[(&str, &str, &str)],
    ) -> Vec<Capability> {
        let base_confidence = CapabilitySource::AtSpi.base_confidence();
        let mut capabilities = Vec::new();

        for (role, name, action) in nodes {
            if action.is_empty() {
                continue; // Skip non-actionable nodes.
            }

            let cap_name = format!(
                "ui.{}.{}",
                role.replace(' ', "_"),
                name.to_lowercase().replace(' ', "_"),
            );

            capabilities.push(Capability {
                name: cap_name,
                description: format!("{action} on {role} '{name}'"),
                parameters: vec![],
                confidence: base_confidence,
                source: CapabilitySource::AtSpi,
                offline_support: true,
            });
        }

        capabilities
    }
}

impl Default for AtSpiScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner for AtSpiScanner {
    fn name(&self) -> &str {
        "at-spi"
    }

    fn scan(&self, app_id: &str) -> Result<Vec<Capability>, SsiError> {
        info!(app_id, scanner = "at-spi", "scanning accessibility tree");

        // In a real implementation, this would call the atspi crate to
        // enumerate accessible objects. For Phase 2, graceful degradation.
        warn!(
            app_id,
            "AT-SPI scanning requires a running accessibility bus — returning empty"
        );
        Err(SsiError::DispatchFailed(format!(
            "Could not scan {app_id}: accessibility tree unavailable. \
             The app may not support AT-SPI. Manual manifest creation available."
        )))
    }
}

/// Extract a field value from a .desktop file section.
fn extract_desktop_field<'a>(content: &'a str, field: &str) -> Option<&'a str> {
    let prefix = format!("{field}=");
    for line in content.lines() {
        if let Some(value) = line.strip_prefix(&prefix) {
            return Some(value.trim());
        }
    }
    None
}

/// Extract action names from the Actions= field.
fn extract_desktop_actions(content: &str) -> Vec<String> {
    extract_desktop_field(content, "Actions")
        .map(|actions| {
            actions
                .split(';')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Extract an attribute value from an XML tag string.
fn extract_xml_attr<'a>(tag: &'a str, attr: &str) -> Option<&'a str> {
    let prefix = format!("{attr}=\"");
    if let Some(start) = tag.find(&prefix) {
        let value_start = start + prefix.len();
        if let Some(end) = tag[value_start..].find('"') {
            return Some(&tag[value_start..value_start + end]);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_scanner_has_default_paths() {
        let scanner = DesktopEntryScanner::new();
        assert!(!scanner.search_paths().is_empty());
        assert!(scanner.search_paths().iter().any(|p| {
            p.to_string_lossy().contains("applications")
        }));
    }

    #[test]
    fn desktop_scanner_custom_paths() {
        let scanner = DesktopEntryScanner::with_paths(vec![
            PathBuf::from("/tmp/test"),
        ]);
        assert_eq!(scanner.search_paths().len(), 1);
    }

    #[test]
    fn desktop_scanner_name() {
        let scanner = DesktopEntryScanner::new();
        assert_eq!(scanner.name(), "desktop-entry");
    }

    #[test]
    fn desktop_scanner_source() {
        let scanner = DesktopEntryScanner::new();
        assert_eq!(scanner.source(), CapabilitySource::Desktop);
    }

    #[test]
    fn desktop_find_nonexistent_file() {
        let scanner = DesktopEntryScanner::with_paths(vec![
            PathBuf::from("/nonexistent-path-xyz"),
        ]);
        assert!(scanner.find_desktop_file("org.test.App").is_none());
    }

    #[test]
    fn desktop_scan_missing_app() {
        let scanner = DesktopEntryScanner::with_paths(vec![
            PathBuf::from("/nonexistent"),
        ]);
        let result = scanner.scan("org.nonexistent.App").unwrap();
        assert!(result.is_empty()); // Graceful degradation
    }

    #[test]
    fn desktop_parse_basic_entry() {
        let content = "[Desktop Entry]\n\
                        Name=Firefox\n\
                        Exec=firefox %u\n\
                        MimeType=text/html;application/pdf;\n\
                        Actions=new-window;new-private-window;\n\
                        \n\
                        [Desktop Action new-window]\n\
                        Name=Open a New Window\n\
                        \n\
                        [Desktop Action new-private-window]\n\
                        Name=Open a New Private Window\n";

        // Write to temp file and parse.
        let dir = std::env::temp_dir().join("ssi-test-desktop");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.desktop");
        std::fs::write(&path, content).unwrap();

        let scanner = DesktopEntryScanner::new();
        let caps = scanner.parse_desktop_file(&path).unwrap();

        // Should find: app.launch + 2 MIME types + 2 actions = 5
        assert_eq!(caps.len(), 5);
        assert!(caps.iter().any(|c| c.name == "app.launch"));
        assert!(caps.iter().any(|c| c.name.contains("text.html")));
        assert!(caps.iter().any(|c| c.name.contains("new-window")));

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn desktop_parse_nonexistent_file() {
        let scanner = DesktopEntryScanner::new();
        let result = scanner.parse_desktop_file(Path::new("/no-such-file.desktop"));
        assert!(result.is_err());
    }

    #[test]
    fn dbus_scanner_name() {
        let scanner = DbusScanner::new();
        assert_eq!(scanner.name(), "dbus-introspection");
        assert!(scanner.is_session_bus());
    }

    #[test]
    fn dbus_parse_introspection_xml() {
        let scanner = DbusScanner::new();
        let xml = r#"
            <interface name="org.example.Player">
                <method name="Play"/>
                <method name="Pause"/>
                <method name="Stop"/>
            </interface>
        "#;
        let caps = scanner.parse_introspection(xml, "org.example.Player");
        assert_eq!(caps.len(), 3);
        assert!(caps.iter().any(|c| c.name.contains("Play")));
        assert!(caps.iter().any(|c| c.name.contains("Stop")));
        assert!(caps.iter().all(|c| c.source == CapabilitySource::Dbus));
    }

    #[test]
    fn dbus_scan_graceful_degradation() {
        let scanner = DbusScanner::new();
        let result = scanner.scan("org.test.App").unwrap();
        assert!(result.is_empty()); // Graceful: no bus = empty
    }

    #[test]
    fn atspi_scanner_name() {
        let scanner = AtSpiScanner::new();
        assert_eq!(scanner.name(), "at-spi");
        assert_eq!(scanner.max_depth(), 5);
    }

    #[test]
    fn atspi_custom_depth() {
        let scanner = AtSpiScanner::with_depth(10);
        assert_eq!(scanner.max_depth(), 10);
    }

    #[test]
    fn atspi_parse_nodes() {
        let scanner = AtSpiScanner::new();
        let nodes = vec![
            ("push button", "Save", "click"),
            ("menu item", "Open File", "click"),
            ("text", "Content", ""),         // No action — skipped
            ("check box", "Dark Mode", "toggle"),
        ];
        let caps = scanner.parse_accessibility_nodes(&nodes);
        assert_eq!(caps.len(), 3); // 3 actionable nodes
        assert!(caps.iter().all(|c| c.source == CapabilitySource::AtSpi));
    }

    #[test]
    fn atspi_scan_returns_error() {
        let scanner = AtSpiScanner::new();
        let result = scanner.scan("org.test.App");
        // AT-SPI requires a running bus — expect error with helpful message.
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("accessibility tree unavailable"));
    }

    #[test]
    fn extract_desktop_field_works() {
        let content = "Name=Firefox\nExec=firefox\nType=Application\n";
        assert_eq!(extract_desktop_field(content, "Name"), Some("Firefox"));
        assert_eq!(extract_desktop_field(content, "Exec"), Some("firefox"));
        assert_eq!(extract_desktop_field(content, "Missing"), None);
    }

    #[test]
    fn extract_desktop_actions_works() {
        let content = "Actions=new-window;new-tab;\n";
        let actions = extract_desktop_actions(content);
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0], "new-window");
    }

    #[test]
    fn extract_xml_attr_works() {
        assert_eq!(
            extract_xml_attr(r#"<method name="Play"/>"#, "name"),
            Some("Play"),
        );
        assert_eq!(
            extract_xml_attr(r#"<method/>"#, "name"),
            None,
        );
    }
}

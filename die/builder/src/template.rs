// SPDX-License-Identifier: MIT

//! Project templates for scaffolding.
//!
//! Templates define the initial file structure, dependencies, and
//! configuration for different project types. The builder uses these
//! to create the skeleton before AI-assisted code generation fills
//! in the logic.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::BuilderError;

/// A project template defining the initial structure.
///
/// # Examples
///
/// ```
/// use die_builder::template::ProjectTemplate;
///
/// let template = ProjectTemplate::new(
///     "react-app",
///     "React 19 application with TypeScript",
/// );
/// assert_eq!(template.name(), "react-app");
/// assert!(template.files().is_empty());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectTemplate {
    /// Template identifier.
    name: String,
    /// Human-readable description.
    description: String,
    /// Files to generate: relative path → content template.
    files: HashMap<String, String>,
    /// Required dependencies (package manager → list of packages).
    dependencies: HashMap<String, Vec<String>>,
    /// Post-scaffold commands to run.
    post_scaffold: Vec<String>,
}

impl ProjectTemplate {
    /// Create a new empty template.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::template::ProjectTemplate;
    ///
    /// let t = ProjectTemplate::new("rust-cli", "Rust CLI tool");
    /// assert_eq!(t.name(), "rust-cli");
    /// ```
    #[must_use]
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            files: HashMap::new(),
            dependencies: HashMap::new(),
            post_scaffold: Vec::new(),
        }
    }

    /// Template name.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::template::ProjectTemplate;
    ///
    /// let t = ProjectTemplate::new("test", "Test template");
    /// assert_eq!(t.name(), "test");
    /// ```
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Template description.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::template::ProjectTemplate;
    ///
    /// let t = ProjectTemplate::new("test", "A test template");
    /// assert_eq!(t.description(), "A test template");
    /// ```
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Files in this template.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::template::ProjectTemplate;
    ///
    /// let t = ProjectTemplate::new("test", "test");
    /// assert!(t.files().is_empty());
    /// ```
    #[must_use]
    pub fn files(&self) -> &HashMap<String, String> {
        &self.files
    }

    /// Add a file to the template.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::template::ProjectTemplate;
    ///
    /// let mut t = ProjectTemplate::new("test", "test");
    /// t.add_file("src/main.rs", "fn main() {}");
    /// assert_eq!(t.files().len(), 1);
    /// ```
    pub fn add_file(&mut self, path: &str, content: &str) {
        self.files.insert(path.to_string(), content.to_string());
    }

    /// Add a dependency.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::template::ProjectTemplate;
    ///
    /// let mut t = ProjectTemplate::new("test", "test");
    /// t.add_dependency("npm", "react");
    /// ```
    pub fn add_dependency(&mut self, manager: &str, package: &str) {
        self.dependencies
            .entry(manager.to_string())
            .or_default()
            .push(package.to_string());
    }

    /// Add a post-scaffold command.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::template::ProjectTemplate;
    ///
    /// let mut t = ProjectTemplate::new("test", "test");
    /// t.add_post_command("npm install");
    /// ```
    pub fn add_post_command(&mut self, command: &str) {
        self.post_scaffold.push(command.to_string());
    }

    /// Scaffold this template to an output directory.
    ///
    /// Creates all template files in the target directory. Does NOT
    /// execute any commands — that's the builder's job.
    ///
    /// # Errors
    ///
    /// Returns an error if the output directory is invalid or file
    /// creation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::template::ProjectTemplate;
    ///
    /// let mut t = ProjectTemplate::new("test", "test");
    /// t.add_file("README.md", "# Test Project");
    ///
    /// let output = std::env::temp_dir().join("builder-test-scaffold");
    /// let result = t.scaffold(&output);
    /// assert!(result.is_ok());
    ///
    /// // Cleanup.
    /// let _ = std::fs::remove_dir_all(&output);
    /// ```
    pub fn scaffold(&self, output_dir: &Path) -> Result<Vec<PathBuf>, BuilderError> {
        validate_output_dir(output_dir)?;

        std::fs::create_dir_all(output_dir).map_err(|e| BuilderError::ScaffoldFailed {
            reason: format!("cannot create directory: {e}"),
        })?;

        let mut created_files = Vec::new();

        for (rel_path, content) in &self.files {
            let full_path = output_dir.join(rel_path);
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    BuilderError::ScaffoldFailed {
                        reason: format!("cannot create {}: {e}", parent.display()),
                    }
                })?;
            }
            std::fs::write(&full_path, content).map_err(|e| {
                BuilderError::ScaffoldFailed {
                    reason: format!("cannot write {}: {e}", full_path.display()),
                }
            })?;
            created_files.push(full_path);
        }

        Ok(created_files)
    }
}

/// Validate that an output directory is safe to write to.
///
/// Per CLAUDE.md Section 4: generated projects MUST be placed in a
/// user-specified output directory — never in system directories.
///
/// # Examples
///
/// ```
/// use die_builder::template::validate_output_dir;
/// use std::path::Path;
///
/// // System directories are rejected.
/// assert!(validate_output_dir(Path::new("/usr/bin")).is_err());
/// assert!(validate_output_dir(Path::new("/etc")).is_err());
///
/// // User directories are accepted.
/// let temp = std::env::temp_dir();
/// assert!(validate_output_dir(&temp).is_ok());
/// ```
pub fn validate_output_dir(path: &Path) -> Result<(), BuilderError> {
    let path_str = path.to_string_lossy();

    let forbidden = ["/usr", "/etc", "/bin", "/sbin", "/lib", "/boot", "/sys", "/proc"];
    for prefix in &forbidden {
        if path_str.starts_with(prefix) {
            return Err(BuilderError::InvalidOutputDir {
                path: path_str.to_string(),
                reason: format!("system directory '{prefix}' is not allowed"),
            });
        }
    }

    Ok(())
}

/// Built-in template registry.
///
/// # Examples
///
/// ```
/// use die_builder::template::TemplateRegistry;
///
/// let registry = TemplateRegistry::with_builtins();
/// assert!(registry.list().len() >= 3);
/// ```
pub struct TemplateRegistry {
    templates: HashMap<String, ProjectTemplate>,
}

impl TemplateRegistry {
    /// Create an empty registry.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::template::TemplateRegistry;
    ///
    /// let registry = TemplateRegistry::new();
    /// assert!(registry.list().is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            templates: HashMap::new(),
        }
    }

    /// Create a registry with built-in templates.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::template::TemplateRegistry;
    ///
    /// let registry = TemplateRegistry::with_builtins();
    /// assert!(registry.get("rust-cli").is_some());
    /// ```
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut registry = Self::new();

        // Rust CLI template.
        let mut rust_cli = ProjectTemplate::new("rust-cli", "Rust command-line application");
        rust_cli.add_file("Cargo.toml", "[package]\nname = \"{{project_name}}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n");
        rust_cli.add_file("src/main.rs", "fn main() {\n    println!(\"Hello from {{project_name}}!\");\n}\n");
        rust_cli.add_post_command("cargo check");
        registry.register(rust_cli);

        // React app template.
        let mut react_app = ProjectTemplate::new("react-app", "React 19 TypeScript application");
        react_app.add_file("package.json", "{\n  \"name\": \"{{project_name}}\",\n  \"private\": true,\n  \"type\": \"module\",\n  \"scripts\": {\n    \"dev\": \"vite\",\n    \"build\": \"vite build\"\n  }\n}\n");
        react_app.add_file("src/App.tsx", "export default function App() {\n  return <div>Hello from {{project_name}}</div>;\n}\n");
        react_app.add_file("tsconfig.json", "{\n  \"compilerOptions\": {\n    \"strict\": true,\n    \"jsx\": \"react-jsx\"\n  }\n}\n");
        react_app.add_dependency("pnpm", "react");
        react_app.add_dependency("pnpm", "react-dom");
        react_app.add_post_command("pnpm install");
        registry.register(react_app);

        // Python API template.
        let mut python_api = ProjectTemplate::new("python-api", "Python FastAPI application");
        python_api.add_file("main.py", "from fastapi import FastAPI\n\napp = FastAPI(title=\"{{project_name}}\")\n\n@app.get(\"/\")\ndef root():\n    return {\"message\": \"Hello from {{project_name}}\"}\n");
        python_api.add_file("requirements.txt", "fastapi>=0.100.0\nuvicorn>=0.23.0\n");
        python_api.add_post_command("pip install -r requirements.txt");
        registry.register(python_api);

        registry
    }

    /// Register a template.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::template::{TemplateRegistry, ProjectTemplate};
    ///
    /// let mut registry = TemplateRegistry::new();
    /// registry.register(ProjectTemplate::new("custom", "My template"));
    /// assert!(registry.get("custom").is_some());
    /// ```
    pub fn register(&mut self, template: ProjectTemplate) {
        self.templates.insert(template.name.clone(), template);
    }

    /// Get a template by name.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::template::TemplateRegistry;
    ///
    /// let registry = TemplateRegistry::with_builtins();
    /// assert!(registry.get("rust-cli").is_some());
    /// assert!(registry.get("nonexistent").is_none());
    /// ```
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ProjectTemplate> {
        self.templates.get(name)
    }

    /// List all registered template names.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::template::TemplateRegistry;
    ///
    /// let registry = TemplateRegistry::with_builtins();
    /// let names = registry.list();
    /// assert!(names.contains(&&"rust-cli".to_string()));
    /// ```
    #[must_use]
    pub fn list(&self) -> Vec<&String> {
        self.templates.keys().collect()
    }
}

impl Default for TemplateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_creation() {
        let t = ProjectTemplate::new("test", "Test template");
        assert_eq!(t.name(), "test");
        assert_eq!(t.description(), "Test template");
        assert!(t.files().is_empty());
    }

    #[test]
    fn add_file_to_template() {
        let mut t = ProjectTemplate::new("test", "test");
        t.add_file("src/main.rs", "fn main() {}");
        assert_eq!(t.files().len(), 1);
        assert!(t.files().contains_key("src/main.rs"));
    }

    #[test]
    fn add_dependency() {
        let mut t = ProjectTemplate::new("test", "test");
        t.add_dependency("npm", "react");
        t.add_dependency("npm", "typescript");
        assert_eq!(t.dependencies["npm"].len(), 2);
    }

    #[test]
    fn add_post_command() {
        let mut t = ProjectTemplate::new("test", "test");
        t.add_post_command("npm install");
        assert_eq!(t.post_scaffold.len(), 1);
    }

    #[test]
    fn scaffold_creates_files() {
        let mut t = ProjectTemplate::new("test", "test");
        t.add_file("README.md", "# Test");
        t.add_file("src/lib.rs", "// lib");

        let output = std::env::temp_dir().join("builder-test-scaffold-1");
        let created = t.scaffold(&output).unwrap();
        assert_eq!(created.len(), 2);
        assert!(output.join("README.md").exists());
        assert!(output.join("src/lib.rs").exists());

        let _ = std::fs::remove_dir_all(&output);
    }

    #[test]
    fn validate_rejects_system_dirs() {
        assert!(validate_output_dir(Path::new("/usr/bin")).is_err());
        assert!(validate_output_dir(Path::new("/etc/config")).is_err());
        assert!(validate_output_dir(Path::new("/bin/tool")).is_err());
    }

    #[test]
    fn validate_accepts_user_dirs() {
        let temp = std::env::temp_dir();
        assert!(validate_output_dir(&temp).is_ok());

        if let Some(home) = dirs::home_dir() {
            assert!(validate_output_dir(&home.join("projects")).is_ok());
        }
    }

    #[test]
    fn registry_empty() {
        let registry = TemplateRegistry::new();
        assert!(registry.list().is_empty());
    }

    #[test]
    fn registry_builtins() {
        let registry = TemplateRegistry::with_builtins();
        assert!(registry.list().len() >= 3);
        assert!(registry.get("rust-cli").is_some());
        assert!(registry.get("react-app").is_some());
        assert!(registry.get("python-api").is_some());
    }

    #[test]
    fn registry_custom_template() {
        let mut registry = TemplateRegistry::new();
        registry.register(ProjectTemplate::new("custom", "Custom template"));
        assert!(registry.get("custom").is_some());
        assert!(registry.get("missing").is_none());
    }

    #[test]
    fn template_serialization() {
        let mut t = ProjectTemplate::new("test", "test");
        t.add_file("main.rs", "fn main() {}");
        let json = serde_json::to_string(&t).unwrap();
        let deserialized: ProjectTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name(), "test");
        assert_eq!(deserialized.files().len(), 1);
    }

    #[test]
    fn default_registry() {
        let registry = TemplateRegistry::default();
        assert!(registry.list().is_empty());
    }
}

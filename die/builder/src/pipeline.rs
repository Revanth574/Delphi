// SPDX-License-Identifier: MIT

//! Build pipeline — scaffold, generate, build, test.
//!
//! The pipeline orchestrates the full project creation flow:
//! 1. Scaffold from template
//! 2. Code generation (via inference, future phase)
//! 3. Build verification
//! 4. Test execution
//!
//! # Boundaries (CLAUDE.md Section 4)
//!
//! - MUST NOT execute generated code outside sandbox
//! - Generated projects go to user-specified output only
//! - MUST NOT install system packages without Tier 2 permission
//! - Build artifacts excluded from semantic-fs indexing

use std::path::PathBuf;

use tracing::info;

use crate::error::BuilderError;
use crate::template::{ProjectTemplate, TemplateRegistry};

/// Pipeline stage tracking.
///
/// # Examples
///
/// ```
/// use die_builder::pipeline::PipelineStage;
///
/// let stage = PipelineStage::Scaffolding;
/// assert!(!stage.is_complete());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineStage {
    /// Creating initial file structure.
    Scaffolding,
    /// AI-assisted code generation.
    Generating,
    /// Compiling/building the project.
    Building,
    /// Running tests.
    Testing,
    /// All stages complete.
    Complete,
    /// Pipeline failed at a stage.
    Failed,
}

impl PipelineStage {
    /// Whether the pipeline finished successfully.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::pipeline::PipelineStage;
    ///
    /// assert!(PipelineStage::Complete.is_complete());
    /// assert!(!PipelineStage::Building.is_complete());
    /// ```
    #[must_use]
    pub fn is_complete(&self) -> bool {
        *self == Self::Complete
    }

    /// Human-readable stage description.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::pipeline::PipelineStage;
    ///
    /// assert_eq!(PipelineStage::Scaffolding.as_str(), "scaffolding");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Scaffolding => "scaffolding",
            Self::Generating => "generating",
            Self::Building => "building",
            Self::Testing => "testing",
            Self::Complete => "complete",
            Self::Failed => "failed",
        }
    }
}

/// Result of a build pipeline run.
///
/// # Examples
///
/// ```
/// use die_builder::pipeline::{PipelineResult, PipelineStage};
///
/// let result = PipelineResult {
///     stage: PipelineStage::Complete,
///     output_dir: std::path::PathBuf::from("/tmp/project"),
///     files_created: 3,
///     errors: vec![],
/// };
/// assert!(result.is_success());
/// ```
#[derive(Debug, Clone)]
pub struct PipelineResult {
    /// Final stage reached.
    pub stage: PipelineStage,
    /// Where the project was created.
    pub output_dir: PathBuf,
    /// Number of files created.
    pub files_created: usize,
    /// Errors encountered (non-fatal may still result in success).
    pub errors: Vec<String>,
}

impl PipelineResult {
    /// Whether the pipeline completed successfully.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::pipeline::{PipelineResult, PipelineStage};
    ///
    /// let result = PipelineResult {
    ///     stage: PipelineStage::Complete,
    ///     output_dir: std::path::PathBuf::from("/tmp"),
    ///     files_created: 2,
    ///     errors: vec![],
    /// };
    /// assert!(result.is_success());
    /// ```
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.stage.is_complete()
    }
}

/// A build request specifying what to create.
///
/// # Examples
///
/// ```
/// use die_builder::pipeline::BuildRequest;
///
/// let req = BuildRequest::new("my-app", "rust-cli", "/home/user/projects/my-app");
/// assert_eq!(req.project_name, "my-app");
/// ```
#[derive(Debug, Clone)]
pub struct BuildRequest {
    /// Project name.
    pub project_name: String,
    /// Template to use.
    pub template_name: String,
    /// Output directory.
    pub output_dir: PathBuf,
    /// Optional description for AI-assisted generation.
    pub description: Option<String>,
}

impl BuildRequest {
    /// Create a new build request.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::pipeline::BuildRequest;
    ///
    /// let req = BuildRequest::new("test-app", "react-app", "/tmp/test-app");
    /// assert_eq!(req.template_name, "react-app");
    /// ```
    #[must_use]
    pub fn new(name: &str, template: &str, output: &str) -> Self {
        Self {
            project_name: name.to_string(),
            template_name: template.to_string(),
            output_dir: PathBuf::from(output),
            description: None,
        }
    }

    /// Set a project description for AI-assisted generation.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::pipeline::BuildRequest;
    ///
    /// let req = BuildRequest::new("app", "rust-cli", "/tmp/app")
    ///     .with_description("A CLI tool for managing tasks");
    /// assert!(req.description.is_some());
    /// ```
    #[must_use]
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }
}

/// The build pipeline executor.
///
/// # Examples
///
/// ```
/// use die_builder::pipeline::BuildPipeline;
///
/// let pipeline = BuildPipeline::new();
/// assert_eq!(pipeline.available_templates().len(), 3);
/// ```
pub struct BuildPipeline {
    /// Template registry.
    registry: TemplateRegistry,
    /// Maximum fix attempts per stage.
    max_attempts: u32,
}

impl BuildPipeline {
    /// Create a new pipeline with default templates.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::pipeline::BuildPipeline;
    ///
    /// let pipeline = BuildPipeline::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: TemplateRegistry::with_builtins(),
            max_attempts: 3,
        }
    }

    /// List available template names.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::pipeline::BuildPipeline;
    ///
    /// let pipeline = BuildPipeline::new();
    /// let templates = pipeline.available_templates();
    /// assert!(!templates.is_empty());
    /// ```
    #[must_use]
    pub fn available_templates(&self) -> Vec<&String> {
        self.registry.list()
    }

    /// Maximum fix attempts per failing stage.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::pipeline::BuildPipeline;
    ///
    /// let pipeline = BuildPipeline::new();
    /// assert_eq!(pipeline.max_attempts(), 3);
    /// ```
    #[must_use]
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Execute the scaffold stage only.
    ///
    /// Creates the project skeleton from a template without running
    /// build/test commands.
    ///
    /// # Errors
    ///
    /// Returns an error if the template is not found or scaffolding fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::pipeline::{BuildPipeline, BuildRequest};
    ///
    /// let pipeline = BuildPipeline::new();
    /// let output = std::env::temp_dir().join("builder-pipeline-test");
    /// let req = BuildRequest::new("test-proj", "rust-cli", &output.to_string_lossy());
    /// let result = pipeline.scaffold(&req);
    /// assert!(result.is_ok());
    ///
    /// let _ = std::fs::remove_dir_all(&output);
    /// ```
    pub fn scaffold(&self, request: &BuildRequest) -> Result<PipelineResult, BuilderError> {
        info!(
            project = %request.project_name,
            template = %request.template_name,
            output = %request.output_dir.display(),
            "starting scaffold"
        );

        let template = self.registry.get(&request.template_name).ok_or_else(|| {
            BuilderError::TemplateNotFound {
                name: request.template_name.clone(),
            }
        })?;

        let files = template.scaffold(&request.output_dir)?;

        info!(
            files = files.len(),
            "scaffold complete"
        );

        Ok(PipelineResult {
            stage: PipelineStage::Complete,
            output_dir: request.output_dir.clone(),
            files_created: files.len(),
            errors: Vec::new(),
        })
    }

    /// Register a custom template.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_builder::pipeline::BuildPipeline;
    /// use die_builder::template::ProjectTemplate;
    ///
    /// let mut pipeline = BuildPipeline::new();
    /// pipeline.add_template(ProjectTemplate::new("custom", "My template"));
    /// assert!(pipeline.available_templates().len() >= 4);
    /// ```
    pub fn add_template(&mut self, template: ProjectTemplate) {
        self.registry.register(template);
    }
}

impl Default for BuildPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_stage_properties() {
        assert!(!PipelineStage::Scaffolding.is_complete());
        assert!(!PipelineStage::Generating.is_complete());
        assert!(!PipelineStage::Building.is_complete());
        assert!(!PipelineStage::Testing.is_complete());
        assert!(PipelineStage::Complete.is_complete());
        assert!(!PipelineStage::Failed.is_complete());
    }

    #[test]
    fn pipeline_stage_strings() {
        assert_eq!(PipelineStage::Scaffolding.as_str(), "scaffolding");
        assert_eq!(PipelineStage::Complete.as_str(), "complete");
        assert_eq!(PipelineStage::Failed.as_str(), "failed");
    }

    #[test]
    fn pipeline_result_success() {
        let result = PipelineResult {
            stage: PipelineStage::Complete,
            output_dir: PathBuf::from("/tmp"),
            files_created: 3,
            errors: vec![],
        };
        assert!(result.is_success());
    }

    #[test]
    fn pipeline_result_failure() {
        let result = PipelineResult {
            stage: PipelineStage::Failed,
            output_dir: PathBuf::from("/tmp"),
            files_created: 0,
            errors: vec!["build failed".to_string()],
        };
        assert!(!result.is_success());
    }

    #[test]
    fn build_request_creation() {
        let req = BuildRequest::new("my-app", "rust-cli", "/tmp/my-app");
        assert_eq!(req.project_name, "my-app");
        assert_eq!(req.template_name, "rust-cli");
        assert!(req.description.is_none());
    }

    #[test]
    fn build_request_with_description() {
        let req = BuildRequest::new("app", "react-app", "/tmp/app")
            .with_description("A task manager");
        assert_eq!(req.description.as_deref(), Some("A task manager"));
    }

    #[test]
    fn pipeline_has_templates() {
        let pipeline = BuildPipeline::new();
        assert!(!pipeline.available_templates().is_empty());
        assert_eq!(pipeline.max_attempts(), 3);
    }

    #[test]
    fn scaffold_rust_cli() {
        let pipeline = BuildPipeline::new();
        let output = std::env::temp_dir().join("builder-test-rust-cli");
        let req = BuildRequest::new("test-proj", "rust-cli", &output.to_string_lossy());
        let result = pipeline.scaffold(&req).unwrap();
        assert!(result.is_success());
        assert!(result.files_created >= 2);
        assert!(output.join("Cargo.toml").exists());
        assert!(output.join("src/main.rs").exists());
        let _ = std::fs::remove_dir_all(&output);
    }

    #[test]
    fn scaffold_react_app() {
        let pipeline = BuildPipeline::new();
        let output = std::env::temp_dir().join("builder-test-react-app");
        let req = BuildRequest::new("test-app", "react-app", &output.to_string_lossy());
        let result = pipeline.scaffold(&req).unwrap();
        assert!(result.is_success());
        assert!(output.join("package.json").exists());
        let _ = std::fs::remove_dir_all(&output);
    }

    #[test]
    fn scaffold_unknown_template_fails() {
        let pipeline = BuildPipeline::new();
        let output = std::env::temp_dir().join("builder-test-unknown");
        let req = BuildRequest::new("app", "nonexistent", &output.to_string_lossy());
        let result = pipeline.scaffold(&req);
        assert!(result.is_err());
    }

    #[test]
    fn add_custom_template() {
        let mut pipeline = BuildPipeline::new();
        let initial_count = pipeline.available_templates().len();
        pipeline.add_template(crate::template::ProjectTemplate::new("custom", "test"));
        assert_eq!(pipeline.available_templates().len(), initial_count + 1);
    }

    #[test]
    fn default_pipeline() {
        let pipeline = BuildPipeline::default();
        assert!(!pipeline.available_templates().is_empty());
    }
}

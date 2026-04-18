// SPDX-License-Identifier: MIT

//! # DIE Builder
//!
//! Full-stack project builder for Delphi OS. Scaffolds projects from
//! templates, generates code via AI inference, builds, tests, and
//! optionally deploys.
//!
//! # Pipeline
//!
//! ```text
//! Template → Scaffold → Generate (AI) → Build → Test → Deploy
//! ```
//!
//! # Boundaries (CLAUDE.md Section 4)
//!
//! - MUST NOT execute generated code outside sandbox
//! - Generated projects go to user-specified output only
//! - MUST NOT install system packages without Tier 2 permission
//! - Build artifacts excluded from semantic-fs indexing

pub mod error;
pub mod pipeline;
pub mod template;

pub use error::BuilderError;
pub use pipeline::BuildPipeline;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn re_exports_accessible() {
        let _pipeline = BuildPipeline::new();
        let _err = BuilderError::ScaffoldFailed {
            reason: "test".to_string(),
        };
    }

    #[test]
    fn full_scaffold_integration() {
        let pipeline = BuildPipeline::new();
        let output = std::env::temp_dir().join("builder-integration-test");

        let req = pipeline::BuildRequest::new(
            "integration-test",
            "rust-cli",
            &output.to_string_lossy(),
        );

        let result = pipeline.scaffold(&req).unwrap();
        assert!(result.is_success());
        assert!(result.files_created >= 2);

        // Verify file contents were written.
        let cargo_content = std::fs::read_to_string(output.join("Cargo.toml")).unwrap();
        assert!(cargo_content.contains("{{project_name}}"));

        let _ = std::fs::remove_dir_all(&output);
    }
}

// SPDX-License-Identifier: MIT

//! Error types for the builder.
//!
//! Per CLAUDE.md Section 8: builder errors must include the attempt
//! number and a description of the fix being tried.

/// Errors produced by the builder.
///
/// # Examples
///
/// ```
/// use die_builder::BuilderError;
///
/// let err = BuilderError::ScaffoldFailed {
///     reason: "template not found".to_string(),
/// };
/// assert!(err.to_string().contains("template"));
/// ```
#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    /// Project scaffolding failed.
    #[error("scaffold failed: {reason}")]
    ScaffoldFailed {
        /// Why scaffolding failed.
        reason: String,
    },

    /// Code generation failed.
    #[error("code generation failed (attempt {attempt}/3): {reason}")]
    GenerationFailed {
        /// Current attempt number.
        attempt: u32,
        /// Why generation failed.
        reason: String,
    },

    /// Build process failed.
    #[error("build failed: {error}. Attempting fix {attempt}/3: {fix_description}")]
    BuildFailed {
        /// The build error message.
        error: String,
        /// Current fix attempt.
        attempt: u32,
        /// What fix is being tried.
        fix_description: String,
    },

    /// Test execution failed.
    #[error("tests failed: {count} failures")]
    TestsFailed {
        /// Number of failing tests.
        count: u32,
    },

    /// Output directory is invalid or inaccessible.
    #[error("invalid output directory: {path} — {reason}")]
    InvalidOutputDir {
        /// The path that was rejected.
        path: String,
        /// Why it's invalid.
        reason: String,
    },

    /// The generated code has type errors.
    #[error("generated code has {count} type errors. Feeding errors back to inference for correction")]
    TypeErrors {
        /// Number of type errors.
        count: u32,
    },

    /// Template not found.
    #[error("template not found: {name}")]
    TemplateNotFound {
        /// Template name.
        name: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_error_message() {
        let err = BuilderError::ScaffoldFailed {
            reason: "missing template".to_string(),
        };
        assert!(err.to_string().contains("missing template"));
    }

    #[test]
    fn generation_error_includes_attempt() {
        let err = BuilderError::GenerationFailed {
            attempt: 2,
            reason: "syntax error".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("attempt 2/3"));
        assert!(msg.contains("syntax error"));
    }

    #[test]
    fn build_error_includes_fix() {
        let err = BuilderError::BuildFailed {
            error: "missing dependency".to_string(),
            attempt: 1,
            fix_description: "adding missing import".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("missing dependency"));
        assert!(msg.contains("fix 1/3"));
    }

    #[test]
    fn test_failure_count() {
        let err = BuilderError::TestsFailed { count: 5 };
        assert!(err.to_string().contains("5 failures"));
    }

    #[test]
    fn invalid_output_dir() {
        let err = BuilderError::InvalidOutputDir {
            path: "/usr/bin".to_string(),
            reason: "system directory".to_string(),
        };
        assert!(err.to_string().contains("/usr/bin"));
    }

    #[test]
    fn type_errors_message() {
        let err = BuilderError::TypeErrors { count: 3 };
        assert!(err.to_string().contains("3 type errors"));
    }

    #[test]
    fn template_not_found() {
        let err = BuilderError::TemplateNotFound {
            name: "react-app".to_string(),
        };
        assert!(err.to_string().contains("react-app"));
    }
}

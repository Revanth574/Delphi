// SPDX-License-Identifier: MIT

//! Intent planning and execution.
//!
//! The planner takes a user intent, decomposes it into a sequence of
//! steps, and coordinates execution across DIE subsystems. Each step
//! is logged in the action timeline for the 24-hour undo window.
//!
//! # Design
//!
//! The planner follows a plan-execute-verify cycle:
//! 1. Decompose intent into steps
//! 2. Validate each step against security policy (fortress)
//! 3. Execute steps, using inference and semantic-fs as needed
//! 4. Log results to the action timeline
//! 5. Report completion to the shell via D-Bus

use crate::OrchestratorError;

/// The central planner that decomposes intents into executable steps.
///
/// # Examples
///
/// ```
/// use die_orchestrator::planner::Planner;
///
/// let planner = Planner::new();
/// // Planner is ready to receive intents.
/// ```
pub struct Planner {
    _initialized: bool,
}

impl Planner {
    /// Create a new planner.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::planner::Planner;
    /// let planner = Planner::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            _initialized: true,
        }
    }

    /// Plan the execution of a natural language intent.
    ///
    /// Decomposes the intent into steps and validates each against
    /// security policy.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError::Planning` if the intent cannot be
    /// decomposed into valid steps.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::planner::Planner;
    ///
    /// let planner = Planner::new();
    /// let result = planner.plan("find my tax documents from last year");
    /// // Planning requires inference backends, so this returns an error.
    /// assert!(result.is_err());
    /// ```
    pub fn plan(&self, intent: &str) -> Result<ExecutionPlan, OrchestratorError> {
        tracing::info!(intent = intent, "planning intent execution");

        Err(OrchestratorError::Planning(
            "inference backends not yet available — cannot decompose intent".to_string(),
        ))
    }
}

impl Default for Planner {
    fn default() -> Self {
        Self::new()
    }
}

/// A plan of execution steps for an intent.
///
/// Each step is a discrete operation that can be individually
/// logged, undone, and retried.
///
/// # Examples
///
/// ```
/// use die_orchestrator::planner::ExecutionPlan;
///
/// let plan = ExecutionPlan {
///     intent: "find tax documents".to_string(),
///     steps: vec!["search semantic-fs for 'tax'".to_string()],
/// };
/// assert_eq!(plan.steps.len(), 1);
/// ```
#[derive(Debug, Clone)]
pub struct ExecutionPlan {
    /// The original intent that produced this plan.
    pub intent: String,
    /// Ordered list of execution steps.
    pub steps: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planner_creates_successfully() {
        let planner = Planner::new();
        let _default = Planner::default();
        // No panic.
        let _ = planner;
    }

    #[test]
    fn plan_without_backends_returns_error() {
        let planner = Planner::new();
        let err = planner.plan("do something").unwrap_err();
        assert!(err.to_string().contains("inference backends"));
    }

    #[test]
    fn execution_plan_fields() {
        let plan = ExecutionPlan {
            intent: "organize photos".to_string(),
            steps: vec![
                "scan ~/Photos".to_string(),
                "classify by date".to_string(),
            ],
        };
        assert_eq!(plan.steps.len(), 2);
        assert!(plan.intent.contains("photos"));
    }
}

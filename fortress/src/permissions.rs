// SPDX-License-Identifier: MIT

//! Four-tier permission model for Delphi OS.
//!
//! Every AI action is checked against a permission policy before execution.
//! The four tiers represent escalating levels of user confirmation:
//!
//! | Tier | Confirmation | Examples |
//! |------|-------------|----------|
//! | Autonomous | None (AI decides) | Read files, run searches |
//! | Confirm | User clicks "OK" | Send email, delete file |
//! | Biometric | Fingerprint / face | Financial transactions, account changes |
//! | Hardware | Physical key / TPM | Full-disk decryption, factory reset |
//!
//! Permission checks are synchronous and fast (no IPC).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::FortressError;

/// The four permission tiers, ordered by escalating security.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PermissionTier {
    /// AI can proceed without user involvement.
    Autonomous = 0,
    /// AI must ask the user for confirmation.
    Confirm = 1,
    /// Requires biometric verification.
    Biometric = 2,
    /// Requires physical hardware interaction (TPM, security key).
    Hardware = 3,
}

/// The result of a permission check.
///
/// # Examples
///
/// ```
/// use fortress::permissions::{PermissionResult, PermissionTier};
///
/// let result = PermissionResult {
///     allowed: true,
///     actual_tier: PermissionTier::Autonomous,
///     reason: "read_file is autonomous by default".to_string(),
/// };
/// assert!(result.allowed);
/// ```
#[derive(Debug, Clone)]
pub struct PermissionResult {
    /// Whether the action is allowed at the requested tier.
    pub allowed: bool,
    /// The actual tier required for this action.
    pub actual_tier: PermissionTier,
    /// Explanation of the decision.
    pub reason: String,
}

/// A permission rule mapping an action pattern to a required tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRule {
    /// Action pattern (exact match or "*" suffix for prefix match).
    pub action: String,
    /// Required tier for this action.
    pub tier: PermissionTier,
}

/// Permission checker with configurable rules.
///
/// # Examples
///
/// ```
/// use fortress::permissions::{PermissionChecker, PermissionTier};
///
/// let checker = PermissionChecker::with_defaults();
/// let result = checker.check("read_file", "/home/user/doc.txt", "die-orchestrator");
/// assert!(result.allowed);
/// assert_eq!(result.actual_tier, PermissionTier::Autonomous);
/// ```
pub struct PermissionChecker {
    /// Rules ordered by specificity (most specific first).
    rules: Vec<PermissionRule>,
    /// Per-module overrides (module -> action -> tier).
    overrides: HashMap<String, HashMap<String, PermissionTier>>,
}

impl PermissionChecker {
    /// Create a checker with sensible default rules per the Delphi spec.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::permissions::PermissionChecker;
    /// let checker = PermissionChecker::with_defaults();
    /// ```
    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            rules: default_rules(),
            overrides: HashMap::new(),
        }
    }

    /// Create a checker with custom rules (for testing or TOML config).
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::permissions::{PermissionChecker, PermissionRule, PermissionTier};
    ///
    /// let rules = vec![
    ///     PermissionRule { action: "everything".to_string(), tier: PermissionTier::Hardware },
    /// ];
    /// let checker = PermissionChecker::new(rules);
    /// ```
    #[must_use]
    pub fn new(rules: Vec<PermissionRule>) -> Self {
        Self {
            rules,
            overrides: HashMap::new(),
        }
    }

    /// Add a per-module override.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::permissions::{PermissionChecker, PermissionTier};
    ///
    /// let mut checker = PermissionChecker::with_defaults();
    /// checker.add_override("untrusted-module", "read_file", PermissionTier::Confirm);
    /// ```
    pub fn add_override(&mut self, module: &str, action: &str, tier: PermissionTier) {
        self.overrides
            .entry(module.to_string())
            .or_default()
            .insert(action.to_string(), tier);
    }

    /// Check whether an action is permitted.
    ///
    /// The check considers:
    /// 1. Per-module overrides (highest priority)
    /// 2. Action-specific rules
    /// 3. Default: Confirm (if no rule matches)
    ///
    /// An action is "allowed" if its required tier is `Autonomous`.
    /// Higher tiers mean the caller must obtain user confirmation
    /// before proceeding.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::permissions::{PermissionChecker, PermissionTier};
    ///
    /// let checker = PermissionChecker::with_defaults();
    ///
    /// // Reading files is autonomous.
    /// let r = checker.check("read_file", "/doc.txt", "die-orchestrator");
    /// assert_eq!(r.actual_tier, PermissionTier::Autonomous);
    ///
    /// // Sending email requires confirmation.
    /// let r = checker.check("send_email", "user@example.com", "die-orchestrator");
    /// assert_eq!(r.actual_tier, PermissionTier::Confirm);
    ///
    /// // Financial actions require biometric.
    /// let r = checker.check("financial_transaction", "$100", "die-orchestrator");
    /// assert_eq!(r.actual_tier, PermissionTier::Biometric);
    /// ```
    #[must_use]
    pub fn check(&self, action: &str, target: &str, module: &str) -> PermissionResult {
        // 1. Check per-module overrides.
        if let Some(module_overrides) = self.overrides.get(module)
            && let Some(&tier) = module_overrides.get(action)
        {
            debug!(action, target, module, ?tier, "permission check: module override");
            return PermissionResult {
                allowed: tier == PermissionTier::Autonomous,
                actual_tier: tier,
                reason: format!("module override for {module}:{action}"),
            };
        }

        // 2. Check action rules (first match wins — rules are ordered by specificity).
        for rule in &self.rules {
            if matches_pattern(&rule.action, action) {
                debug!(action, target, module, tier = ?rule.tier, "permission check: rule match");
                return PermissionResult {
                    allowed: rule.tier == PermissionTier::Autonomous,
                    actual_tier: rule.tier,
                    reason: format!("rule: {} requires {:?}", rule.action, rule.tier),
                };
            }
        }

        // 3. Default: require confirmation.
        debug!(action, target, module, "permission check: default (Confirm)");
        PermissionResult {
            allowed: false,
            actual_tier: PermissionTier::Confirm,
            reason: "no matching rule — defaulting to Confirm".to_string(),
        }
    }

    /// Load permission overrides from a TOML config string.
    ///
    /// # Precedence and trust model (as-built)
    ///
    /// Custom rules are **prepended** ahead of the defaults, and `check` is
    /// first-match-wins — so a config rule can **override, including downgrade**,
    /// a built-in tier (e.g. map a `financial_*` action from `Biometric` down to
    /// `Autonomous`). This is acceptable **only because the config is trusted**:
    /// the sole live consumer of the policy engine is the `services` crate's
    /// `AuthGuard`, which builds the checker via `PermissionChecker::new` from
    /// its own compiled `METHOD_POLICY` and does **not** call `load_config_str`.
    /// There is no untrusted caller of this method today.
    ///
    /// # Forward requirement (fail-safe target)
    ///
    /// Before `load_config_str` is exposed to a **less-trusted** config source,
    /// it MUST be changed to **escalation-only**: a config rule may only *raise*
    /// an action's tier, never *lower* a built-in default. Allowing a downgrade
    /// is a fail-open footgun — a misconfiguration (or a tampered config) would
    /// *silently weaken* a security tier. Escalation-only fails safe: the worst
    /// case over-restricts (extra confirmation prompts), never under-protects.
    ///
    /// # Errors
    ///
    /// Returns `FortressError::Config` if the TOML is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use fortress::permissions::PermissionChecker;
    ///
    /// let mut checker = PermissionChecker::with_defaults();
    /// checker.load_config_str("[[rules]]\naction = \"custom_action\"\ntier = \"Confirm\"").unwrap();
    /// ```
    pub fn load_config_str(&mut self, toml_str: &str) -> Result<(), FortressError> {
        #[derive(Deserialize)]
        struct Config {
            #[serde(default)]
            rules: Vec<PermissionRule>,
        }

        let config: Config =
            toml::from_str(toml_str).map_err(|e| FortressError::Config(e.to_string()))?;

        // Prepend custom rules (higher priority than defaults).
        let mut new_rules = config.rules;
        new_rules.append(&mut self.rules);
        self.rules = new_rules;

        Ok(())
    }
}

/// Check if a rule pattern matches an action.
/// Supports exact match and prefix wildcard ("read_*" matches "read_file").
fn matches_pattern(pattern: &str, action: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        action.starts_with(prefix)
    } else {
        pattern == action
    }
}

/// Default permission rules per the Delphi spec.
fn default_rules() -> Vec<PermissionRule> {
    vec![
        // Autonomous — AI can do freely
        PermissionRule {
            action: "read_file".to_string(),
            tier: PermissionTier::Autonomous,
        },
        PermissionRule {
            action: "search_files".to_string(),
            tier: PermissionTier::Autonomous,
        },
        PermissionRule {
            action: "list_directory".to_string(),
            tier: PermissionTier::Autonomous,
        },
        PermissionRule {
            action: "run_inference".to_string(),
            tier: PermissionTier::Autonomous,
        },
        PermissionRule {
            action: "read_clipboard".to_string(),
            tier: PermissionTier::Autonomous,
        },
        // Confirm — need user OK
        PermissionRule {
            action: "write_file".to_string(),
            tier: PermissionTier::Confirm,
        },
        PermissionRule {
            action: "delete_file".to_string(),
            tier: PermissionTier::Confirm,
        },
        PermissionRule {
            action: "send_email".to_string(),
            tier: PermissionTier::Confirm,
        },
        PermissionRule {
            action: "send_message".to_string(),
            tier: PermissionTier::Confirm,
        },
        PermissionRule {
            action: "install_package".to_string(),
            tier: PermissionTier::Confirm,
        },
        PermissionRule {
            action: "execute_command".to_string(),
            tier: PermissionTier::Confirm,
        },
        PermissionRule {
            action: "modify_settings".to_string(),
            tier: PermissionTier::Confirm,
        },
        // Biometric — financial and account actions
        PermissionRule {
            action: "financial_*".to_string(),
            tier: PermissionTier::Biometric,
        },
        PermissionRule {
            action: "account_delete".to_string(),
            tier: PermissionTier::Biometric,
        },
        PermissionRule {
            action: "credential_export".to_string(),
            tier: PermissionTier::Biometric,
        },
        // Hardware — highest security
        PermissionRule {
            action: "disk_decrypt".to_string(),
            tier: PermissionTier::Hardware,
        },
        PermissionRule {
            action: "factory_reset".to_string(),
            tier: PermissionTier::Hardware,
        },
        PermissionRule {
            action: "tpm_*".to_string(),
            tier: PermissionTier::Hardware,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autonomous_actions_are_allowed() {
        let checker = PermissionChecker::with_defaults();
        let result = checker.check("read_file", "/doc.txt", "die");
        assert!(result.allowed);
        assert_eq!(result.actual_tier, PermissionTier::Autonomous);
    }

    #[test]
    fn confirm_actions_are_not_auto_allowed() {
        let checker = PermissionChecker::with_defaults();
        let result = checker.check("send_email", "user@example.com", "die");
        assert!(!result.allowed);
        assert_eq!(result.actual_tier, PermissionTier::Confirm);
    }

    #[test]
    fn biometric_actions_detected() {
        let checker = PermissionChecker::with_defaults();
        let result = checker.check("financial_transaction", "$100", "die");
        assert!(!result.allowed);
        assert_eq!(result.actual_tier, PermissionTier::Biometric);
    }

    #[test]
    fn hardware_actions_detected() {
        let checker = PermissionChecker::with_defaults();
        let result = checker.check("factory_reset", "system", "die");
        assert_eq!(result.actual_tier, PermissionTier::Hardware);
    }

    #[test]
    fn wildcard_pattern_matches() {
        let checker = PermissionChecker::with_defaults();
        let r = checker.check("financial_transfer", "bank", "die");
        assert_eq!(r.actual_tier, PermissionTier::Biometric);

        let r = checker.check("tpm_seal", "key", "die");
        assert_eq!(r.actual_tier, PermissionTier::Hardware);
    }

    #[test]
    fn unknown_action_defaults_to_confirm() {
        let checker = PermissionChecker::with_defaults();
        let result = checker.check("launch_missiles", "earth", "die");
        assert!(!result.allowed);
        assert_eq!(result.actual_tier, PermissionTier::Confirm);
    }

    #[test]
    fn module_override_takes_priority() {
        let mut checker = PermissionChecker::with_defaults();
        checker.add_override("untrusted", "read_file", PermissionTier::Confirm);

        // Normally autonomous, but overridden for this module.
        let r = checker.check("read_file", "/doc.txt", "untrusted");
        assert_eq!(r.actual_tier, PermissionTier::Confirm);

        // Other modules still get autonomous.
        let r = checker.check("read_file", "/doc.txt", "die");
        assert_eq!(r.actual_tier, PermissionTier::Autonomous);
    }

    #[test]
    fn tier_ordering() {
        assert!(PermissionTier::Autonomous < PermissionTier::Confirm);
        assert!(PermissionTier::Confirm < PermissionTier::Biometric);
        assert!(PermissionTier::Biometric < PermissionTier::Hardware);
    }

    #[test]
    fn load_config_adds_rules() {
        let mut checker = PermissionChecker::with_defaults();
        checker
            .load_config_str(
                r#"
[[rules]]
action = "custom_action"
tier = "Biometric"
"#,
            )
            .unwrap();

        let r = checker.check("custom_action", "target", "any");
        assert_eq!(r.actual_tier, PermissionTier::Biometric);
    }
}

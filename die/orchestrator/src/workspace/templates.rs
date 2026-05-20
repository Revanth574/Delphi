// SPDX-License-Identifier: MIT

//! The four hardcoded baseline workspace templates.
//!
//! These are the trusted fast path: compile-time-audited Rust literals
//! that need no cloud inference. Each constructor returns a
//! [`WorkspaceSpec`] with its metadata already computed, so every
//! baseline spec validates cleanly through
//! [`crate::workspace::validator::validate_spec`] (asserted by the unit
//! tests in this module).
//!
//! All four templates run only `git init --quiet` as a setup command —
//! the single universally-safe, network-free, deterministic command.
//! Language- or ecosystem-specific package-manager commands (e.g.
//! `pnpm install`, `cargo init`) are intentionally NOT baked into the
//! baselines: they require network/toolchains and would make the
//! trusted fast path environment-dependent. A caller who wants them can
//! supply a custom spec (which passes the same validator + allowlist).

use std::collections::HashMap;
use std::path::Path;

use crate::workspace::spec::{
    CalendarBlock, DirectoryEntry, EntryKind, SetupCommand, TemplateId, WorkspaceMetadata,
    WorkspaceSpec,
};

/// Parameters that customize a baseline template.
///
/// Currently only the code-project template reads a parameter
/// (`language`). Unknown keys are ignored. Construct from the D-Bus
/// `params: HashMap<String, String>` via [`TemplateParams::from_map`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TemplateParams {
    /// Programming language for the code-project template. Recognized:
    /// `"rust"` (default) and `"typescript"`. Any other value falls back
    /// to `"rust"`.
    pub language: Option<String>,
}

impl TemplateParams {
    /// Build [`TemplateParams`] from a string map (the D-Bus wire form).
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::workspace::templates::TemplateParams;
    /// use std::collections::HashMap;
    ///
    /// let mut m = HashMap::new();
    /// m.insert("language".to_string(), "typescript".to_string());
    /// let p = TemplateParams::from_map(&m);
    /// assert_eq!(p.language.as_deref(), Some("typescript"));
    /// ```
    #[must_use]
    pub fn from_map(map: &HashMap<String, String>) -> Self {
        Self {
            language: map.get("language").cloned(),
        }
    }
}

/// A standard `.gitignore` body shared by templates (build artifacts,
/// OS cruft, editor files).
const COMMON_GITIGNORE: &str = "\
# OS
.DS_Store
Thumbs.db

# Editor
.vscode/
.idea/
*.swp

# Build artifacts
/target/
node_modules/
__pycache__/
.venv/
dist/
build/
";

fn git_init_command() -> SetupCommand {
    SetupCommand {
        program: "git".to_string(),
        args: vec!["init".to_string(), "--quiet".to_string()],
        working_dir_relative: String::new(),
        description: "Initialize an empty git repository".to_string(),
    }
}

fn dir(path: &str) -> DirectoryEntry {
    DirectoryEntry {
        relative_path: path.to_string(),
        kind: EntryKind::Directory,
        content: None,
    }
}

fn file(path: &str, content: impl Into<String>) -> DirectoryEntry {
    DirectoryEntry {
        relative_path: path.to_string(),
        kind: EntryKind::File,
        content: Some(content.into()),
    }
}

/// Finalize a spec by stamping `created_at` and computing metadata so the
/// spec validates (the validator cross-checks declared vs computed
/// metadata).
fn finalize(mut spec: WorkspaceSpec, created_at: i64) -> WorkspaceSpec {
    spec.metadata.created_at = created_at;
    spec.metadata = spec.compute_metadata();
    spec
}

/// Current Unix epoch seconds, or 0 if the clock is before the epoch
/// (which cannot happen on a sane system; the fallback keeps this
/// panic-free per CLAUDE.md "no unwrap in production").
fn now_epoch() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Build the **research** baseline template.
///
/// Layout: `papers/ notes/ code/ data/ figures/` plus `README.md`,
/// `bibliography.bib`, `notes/literature-review.md`, `.gitignore`.
/// Runs `git init --quiet`. Suggests a recurring daily research-review
/// calendar block.
///
/// # Examples
///
/// ```
/// use die_orchestrator::workspace::templates::build_research_template;
/// use std::path::Path;
///
/// let spec = build_research_template("thesis", Path::new("/home/u/projects/thesis"));
/// assert_eq!(spec.name, "thesis");
/// assert!(spec.directory_tree.iter().any(|e| e.relative_path == "papers"));
/// ```
#[must_use]
pub fn build_research_template(name: &str, root: &Path) -> WorkspaceSpec {
    let readme = format!(
        "# {name}\n\nResearch workspace.\n\n## Structure\n\n\
         - `papers/` — source papers and PDFs\n\
         - `notes/` — reading notes and literature review\n\
         - `code/` — analysis scripts and experiments\n\
         - `data/` — datasets (gitignored if large)\n\
         - `figures/` — generated plots and diagrams\n"
    );
    let lit_review = format!(
        "# Literature review — {name}\n\n\
         | Source | Key claim | Relevance | Notes |\n\
         |--------|-----------|-----------|-------|\n"
    );
    let spec = WorkspaceSpec {
        name: name.to_string(),
        root_dir: root.to_path_buf(),
        template_id: TemplateId::Research,
        directory_tree: vec![
            dir("papers"),
            dir("notes"),
            dir("code"),
            dir("data"),
            dir("figures"),
            file("README.md", readme),
            file("bibliography.bib", ""),
            file("notes/literature-review.md", lit_review),
            file(".gitignore", COMMON_GITIGNORE),
        ],
        setup_commands: vec![git_init_command()],
        calendar_blocks: vec![CalendarBlock {
            title: "Daily research review".to_string(),
            duration_minutes: 30,
            suggested_time: "weekday mornings".to_string(),
            recurrence: Some("weekdays".to_string()),
        }],
        metadata: WorkspaceMetadata::default(),
    };
    finalize(spec, now_epoch())
}

/// Build the **code-project** baseline template.
///
/// Layout: `src/ tests/ docs/` plus `README.md`, `.gitignore`, and
/// language-specific scaffolding. With `language = "typescript"` it
/// emits `src/index.ts` + a `package.json` stub; otherwise (default
/// `"rust"`) it emits `src/main.rs` + a `Cargo.toml` stub. Runs
/// `git init --quiet`. Suggests a single project work-session block.
///
/// # Examples
///
/// ```
/// use die_orchestrator::workspace::templates::{build_code_project_template, TemplateParams};
/// use std::path::Path;
///
/// let p = TemplateParams { language: Some("rust".into()) };
/// let spec = build_code_project_template("cli", Path::new("/home/u/projects/cli"), &p);
/// assert!(spec.directory_tree.iter().any(|e| e.relative_path == "src/main.rs"));
/// assert!(spec.directory_tree.iter().any(|e| e.relative_path == "Cargo.toml"));
/// ```
#[must_use]
pub fn build_code_project_template(
    name: &str,
    root: &Path,
    params: &TemplateParams,
) -> WorkspaceSpec {
    let language = params.language.as_deref().unwrap_or("rust");
    let is_ts = language.eq_ignore_ascii_case("typescript")
        || language.eq_ignore_ascii_case("ts")
        || language.eq_ignore_ascii_case("javascript")
        || language.eq_ignore_ascii_case("js");

    let readme = format!("# {name}\n\nA code project.\n");

    let mut tree = vec![
        dir("src"),
        dir("tests"),
        dir("docs"),
        file("README.md", readme),
        file(".gitignore", COMMON_GITIGNORE),
    ];

    if is_ts {
        let pkg = format!(
            "{{\n  \"name\": \"{name}\",\n  \"version\": \"0.1.0\",\n  \
             \"private\": true,\n  \"type\": \"module\",\n  \
             \"scripts\": {{\n    \"build\": \"tsc\"\n  }}\n}}\n"
        );
        tree.push(file("package.json", pkg));
        tree.push(file(
            "src/index.ts",
            "export function main(): void {\n  console.log(\"hello\");\n}\n\nmain();\n",
        ));
    } else {
        let cargo = format!(
            "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n"
        );
        tree.push(file("Cargo.toml", cargo));
        tree.push(file(
            "src/main.rs",
            "fn main() {\n    println!(\"hello\");\n}\n",
        ));
    }

    let spec = WorkspaceSpec {
        name: name.to_string(),
        root_dir: root.to_path_buf(),
        template_id: TemplateId::CodeProject,
        directory_tree: tree,
        setup_commands: vec![git_init_command()],
        calendar_blocks: vec![CalendarBlock {
            title: "Project work session".to_string(),
            duration_minutes: 90,
            suggested_time: "this week".to_string(),
            recurrence: None,
        }],
        metadata: WorkspaceMetadata::default(),
    };
    finalize(spec, now_epoch())
}

/// Build the **document** baseline template.
///
/// Layout: `drafts/ references/ figures/` plus `README.md`,
/// `drafts/draft-01.md` (skeleton), `references/sources.md`,
/// `.gitignore`. Runs `git init --quiet`.
///
/// # Examples
///
/// ```
/// use die_orchestrator::workspace::templates::build_document_template;
/// use std::path::Path;
///
/// let spec = build_document_template("whitepaper", Path::new("/home/u/projects/wp"));
/// assert!(spec.directory_tree.iter().any(|e| e.relative_path == "drafts/draft-01.md"));
/// ```
#[must_use]
pub fn build_document_template(name: &str, root: &Path) -> WorkspaceSpec {
    let readme = format!("# {name}\n\nDocument workspace.\n");
    let draft = format!("# {name}\n\n_Draft 01_\n\n## Outline\n\n- \n");
    let spec = WorkspaceSpec {
        name: name.to_string(),
        root_dir: root.to_path_buf(),
        template_id: TemplateId::Document,
        directory_tree: vec![
            dir("drafts"),
            dir("references"),
            dir("figures"),
            file("README.md", readme),
            file("drafts/draft-01.md", draft),
            file("references/sources.md", "# Sources\n"),
            file(".gitignore", COMMON_GITIGNORE),
        ],
        setup_commands: vec![git_init_command()],
        calendar_blocks: vec![],
        metadata: WorkspaceMetadata::default(),
    };
    finalize(spec, now_epoch())
}

/// Build the **design** baseline template.
///
/// Layout: `assets/ exports/ mockups/ references/` plus `README.md`,
/// `.gitkeep` markers in the asset dirs, and `.gitignore`. Runs
/// `git init --quiet`.
///
/// # Examples
///
/// ```
/// use die_orchestrator::workspace::templates::build_design_template;
/// use std::path::Path;
///
/// let spec = build_design_template("brand", Path::new("/home/u/projects/brand"));
/// assert!(spec.directory_tree.iter().any(|e| e.relative_path == "mockups"));
/// ```
#[must_use]
pub fn build_design_template(name: &str, root: &Path) -> WorkspaceSpec {
    let readme = format!("# {name}\n\nDesign workspace.\n");
    let design_gitignore = format!("{COMMON_GITIGNORE}\n# Design exports\n*.psd~\n*.sketch~\n");
    let spec = WorkspaceSpec {
        name: name.to_string(),
        root_dir: root.to_path_buf(),
        template_id: TemplateId::Design,
        directory_tree: vec![
            dir("assets"),
            dir("exports"),
            dir("mockups"),
            dir("references"),
            file("README.md", readme),
            file("assets/.gitkeep", ""),
            file("exports/.gitkeep", ""),
            file("mockups/.gitkeep", ""),
            file(".gitignore", design_gitignore),
        ],
        setup_commands: vec![git_init_command()],
        calendar_blocks: vec![],
        metadata: WorkspaceMetadata::default(),
    };
    finalize(spec, now_epoch())
}

/// Dispatch to a baseline template constructor by [`TemplateId`].
///
/// Returns `None` for [`TemplateId::Custom`] (custom specs are built by
/// cloud inference, not this module). The `name`, `root`, and `params`
/// are forwarded to the matching constructor.
///
/// # Examples
///
/// ```
/// use die_orchestrator::workspace::spec::TemplateId;
/// use die_orchestrator::workspace::templates::{build_baseline, TemplateParams};
/// use std::path::Path;
///
/// let spec = build_baseline(
///     &TemplateId::Document,
///     "notes",
///     Path::new("/home/u/projects/notes"),
///     &TemplateParams::default(),
/// );
/// assert!(spec.is_some());
/// assert!(build_baseline(
///     &TemplateId::Custom { description: "x".into() },
///     "x",
///     Path::new("/home/u/projects/x"),
///     &TemplateParams::default(),
/// ).is_none());
/// ```
#[must_use]
pub fn build_baseline(
    id: &TemplateId,
    name: &str,
    root: &Path,
    params: &TemplateParams,
) -> Option<WorkspaceSpec> {
    match id {
        TemplateId::Research => Some(build_research_template(name, root)),
        TemplateId::CodeProject => Some(build_code_project_template(name, root, params)),
        TemplateId::Document => Some(build_document_template(name, root)),
        TemplateId::Design => Some(build_design_template(name, root)),
        TemplateId::Custom { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::validator::validate_spec;

    const ALLOWED: &str = "/home/u/projects";

    #[test]
    fn research_template_validates() {
        let spec = build_research_template("r", Path::new("/home/u/projects/r"));
        assert!(validate_spec(&spec, Path::new(ALLOWED)).is_ok());
        assert_eq!(spec.template_id, TemplateId::Research);
        assert_eq!(spec.setup_commands.len(), 1);
        assert_eq!(spec.calendar_blocks.len(), 1);
    }

    #[test]
    fn code_project_rust_template_validates() {
        let params = TemplateParams {
            language: Some("rust".to_string()),
        };
        let spec = build_code_project_template("c", Path::new("/home/u/projects/c"), &params);
        assert!(validate_spec(&spec, Path::new(ALLOWED)).is_ok());
        assert!(spec
            .directory_tree
            .iter()
            .any(|e| e.relative_path == "Cargo.toml"));
        assert!(spec
            .directory_tree
            .iter()
            .any(|e| e.relative_path == "src/main.rs"));
    }

    #[test]
    fn code_project_typescript_template_validates() {
        let params = TemplateParams {
            language: Some("typescript".to_string()),
        };
        let spec = build_code_project_template("c", Path::new("/home/u/projects/c"), &params);
        assert!(validate_spec(&spec, Path::new(ALLOWED)).is_ok());
        assert!(spec
            .directory_tree
            .iter()
            .any(|e| e.relative_path == "package.json"));
        assert!(spec
            .directory_tree
            .iter()
            .any(|e| e.relative_path == "src/index.ts"));
    }

    #[test]
    fn code_project_defaults_to_rust() {
        let spec = build_code_project_template(
            "c",
            Path::new("/home/u/projects/c"),
            &TemplateParams::default(),
        );
        assert!(spec
            .directory_tree
            .iter()
            .any(|e| e.relative_path == "Cargo.toml"));
    }

    #[test]
    fn document_template_validates() {
        let spec = build_document_template("d", Path::new("/home/u/projects/d"));
        assert!(validate_spec(&spec, Path::new(ALLOWED)).is_ok());
        assert_eq!(spec.template_id, TemplateId::Document);
    }

    #[test]
    fn design_template_validates() {
        let spec = build_design_template("g", Path::new("/home/u/projects/g"));
        assert!(validate_spec(&spec, Path::new(ALLOWED)).is_ok());
        assert_eq!(spec.template_id, TemplateId::Design);
        assert!(spec
            .directory_tree
            .iter()
            .any(|e| e.relative_path == "mockups/.gitkeep"));
    }

    #[test]
    fn all_baseline_templates_have_metadata_consistent() {
        let cases = [
            build_research_template("a", Path::new("/home/u/projects/a")),
            build_code_project_template(
                "b",
                Path::new("/home/u/projects/b"),
                &TemplateParams::default(),
            ),
            build_document_template("c", Path::new("/home/u/projects/c")),
            build_design_template("d", Path::new("/home/u/projects/d")),
        ];
        for spec in cases {
            let computed = spec.compute_metadata();
            assert_eq!(spec.metadata.total_file_count, computed.total_file_count);
            assert_eq!(
                spec.metadata.total_directory_count,
                computed.total_directory_count
            );
            assert_eq!(
                spec.metadata.estimated_total_size_bytes,
                computed.estimated_total_size_bytes
            );
        }
    }

    #[test]
    fn build_baseline_dispatches_all_four() {
        for id in [
            TemplateId::Research,
            TemplateId::CodeProject,
            TemplateId::Document,
            TemplateId::Design,
        ] {
            let spec = build_baseline(
                &id,
                "x",
                Path::new("/home/u/projects/x"),
                &TemplateParams::default(),
            );
            assert!(spec.is_some());
            assert!(validate_spec(&spec.unwrap(), Path::new(ALLOWED)).is_ok());
        }
    }

    #[test]
    fn build_baseline_returns_none_for_custom() {
        let spec = build_baseline(
            &TemplateId::Custom {
                description: "kanban".to_string(),
            },
            "x",
            Path::new("/home/u/projects/x"),
            &TemplateParams::default(),
        );
        assert!(spec.is_none());
    }

    #[test]
    fn template_params_from_map_reads_language() {
        let mut m = HashMap::new();
        m.insert("language".to_string(), "typescript".to_string());
        assert_eq!(
            TemplateParams::from_map(&m).language.as_deref(),
            Some("typescript")
        );
        assert_eq!(TemplateParams::from_map(&HashMap::new()).language, None);
    }
}

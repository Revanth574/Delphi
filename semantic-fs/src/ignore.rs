// SPDX-License-Identifier: MIT

//! `.delphiignore` file support.
//!
//! Provides glob-based file exclusion rules, similar to `.gitignore`.
//! The indexer loads these rules before scanning a directory tree and
//! skips any path that matches.

use std::path::Path;

use crate::SemanticFsError;

/// A set of glob patterns used to exclude files from indexing.
///
/// # Examples
///
/// ```
/// use semantic_fs::ignore::IgnoreRules;
/// use std::path::Path;
///
/// let rules = IgnoreRules::from_patterns(&["*.log", "node_modules"]);
/// assert!(rules.is_ignored(Path::new("/project/node_modules/pkg/index.js")));
/// assert!(rules.is_ignored(Path::new("/var/log/app.log")));
/// assert!(!rules.is_ignored(Path::new("/home/user/readme.md")));
/// ```
#[derive(Debug, Clone, Default)]
pub struct IgnoreRules {
    patterns: Vec<String>,
}

impl IgnoreRules {
    /// Create ignore rules from a list of glob-style patterns.
    ///
    /// Supported pattern syntax:
    /// - `*.ext` — matches files with the given extension anywhere
    /// - `dirname` — matches any path component equal to the pattern
    /// - Lines starting with `#` are comments (only relevant in file parsing)
    ///
    /// # Examples
    ///
    /// ```
    /// use semantic_fs::ignore::IgnoreRules;
    ///
    /// let rules = IgnoreRules::from_patterns(&["*.tmp", ".git", "target"]);
    /// assert_eq!(rules.len(), 3);
    /// ```
    #[must_use]
    pub fn from_patterns(patterns: &[&str]) -> Self {
        Self {
            patterns: patterns
                .iter()
                .filter(|p| !p.is_empty() && !p.starts_with('#'))
                .map(|p| (*p).to_string())
                .collect(),
        }
    }

    /// Load ignore rules from a `.delphiignore` file.
    ///
    /// Each non-empty, non-comment line is treated as a pattern.
    ///
    /// # Errors
    ///
    /// Returns `SemanticFsError::FileIo` if the file cannot be read.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use semantic_fs::ignore::IgnoreRules;
    /// use std::path::Path;
    ///
    /// let rules = IgnoreRules::from_file(Path::new(".delphiignore")).unwrap();
    /// ```
    pub fn from_file(path: &Path) -> Result<Self, SemanticFsError> {
        let content = std::fs::read_to_string(path).map_err(|e| SemanticFsError::FileIo {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;

        let patterns: Vec<String> = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(String::from)
            .collect();

        Ok(Self { patterns })
    }

    /// Check whether a path should be ignored.
    ///
    /// A path is ignored if any component matches a directory pattern
    /// or if the filename matches a glob pattern.
    ///
    /// # Examples
    ///
    /// ```
    /// use semantic_fs::ignore::IgnoreRules;
    /// use std::path::Path;
    ///
    /// let rules = IgnoreRules::from_patterns(&["*.log", ".git"]);
    /// assert!(rules.is_ignored(Path::new("app.log")));
    /// assert!(rules.is_ignored(Path::new("/repo/.git/config")));
    /// assert!(!rules.is_ignored(Path::new("main.rs")));
    /// ```
    #[must_use]
    pub fn is_ignored(&self, path: &Path) -> bool {
        for pattern in &self.patterns {
            if pattern.starts_with("*.") {
                // Extension glob: *.log matches any file ending in .log
                let ext = &pattern[1..]; // includes the dot
                if path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().ends_with(ext))
                {
                    return true;
                }
            } else {
                // Directory/filename match: any path component equals the pattern
                for component in path.components() {
                    if component.as_os_str().to_string_lossy() == *pattern {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Return the number of active patterns.
    ///
    /// # Examples
    ///
    /// ```
    /// use semantic_fs::ignore::IgnoreRules;
    /// let rules = IgnoreRules::from_patterns(&["*.log"]);
    /// assert_eq!(rules.len(), 1);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Check whether there are no patterns loaded.
    ///
    /// # Examples
    ///
    /// ```
    /// use semantic_fs::ignore::IgnoreRules;
    /// let rules = IgnoreRules::default();
    /// assert!(rules.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn empty_rules_ignore_nothing() {
        let rules = IgnoreRules::default();
        assert!(!rules.is_ignored(Path::new("anything.txt")));
        assert!(rules.is_empty());
    }

    #[test]
    fn extension_glob_matches() {
        let rules = IgnoreRules::from_patterns(&["*.log", "*.tmp"]);
        assert!(rules.is_ignored(Path::new("/var/log/app.log")));
        assert!(rules.is_ignored(Path::new("cache.tmp")));
        assert!(!rules.is_ignored(Path::new("readme.md")));
    }

    #[test]
    fn directory_pattern_matches_component() {
        let rules = IgnoreRules::from_patterns(&["node_modules", ".git"]);
        assert!(rules.is_ignored(Path::new("/project/node_modules/pkg/index.js")));
        assert!(rules.is_ignored(Path::new("/repo/.git/HEAD")));
        assert!(!rules.is_ignored(Path::new("/home/user/code/main.rs")));
    }

    #[test]
    fn comments_and_blanks_are_skipped() {
        let rules = IgnoreRules::from_patterns(&["# comment", "", "*.log"]);
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn from_file_parses_correctly() {
        let dir = std::env::temp_dir().join("delphi-ignore-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let ignore_path = dir.join(".delphiignore");
        let mut f = std::fs::File::create(&ignore_path).unwrap();
        writeln!(f, "# Delphi ignore rules").unwrap();
        writeln!(f, "*.log").unwrap();
        writeln!(f, "node_modules").unwrap();
        writeln!(f).unwrap();
        writeln!(f, "target").unwrap();

        let rules = IgnoreRules::from_file(&ignore_path).unwrap();
        assert_eq!(rules.len(), 3);
        assert!(rules.is_ignored(Path::new("debug.log")));
        assert!(rules.is_ignored(Path::new("/project/target/debug/binary")));
    }
}

// SPDX-License-Identifier: MIT

//! Pronoun and deictic reference resolution for conversation memory.
//!
//! When a user says "open it" or "summarize that file from yesterday,"
//! this module tries to figure out which concrete entity they mean by
//! walking backwards through recent messages and mining their
//! `ContextSnapshot`s and content.
//!
//! # Philosophy
//!
//! Per Iron Law #1 (user sovereignty): ambiguous references are returned
//! as `ResolutionResult::Ambiguous` rather than the resolver guessing.
//! The orchestrator is expected to surface the options and ask the user
//! which they meant, never to pick for them.
//!
//! # Strategy
//!
//! 1. Scan the query for known pronouns / deictic phrases.
//! 2. If none found → `NoReference`.
//! 3. Otherwise walk `recent_messages` newest-first, collecting
//!    candidate entities from each message's `ContextSnapshot` and
//!    content.
//! 4. If the pronoun is type-qualified ("that file", "that project")
//!    filter candidates to that type.
//! 5. Return `Resolved(entity)` for a single winner, `Ambiguous(vec)`
//!    for multiple, `Unresolvable` for none.
//!
//! # Examples
//!
//! ```
//! use die_orchestrator::conversation::{ContextSnapshot, Message, MessageRole};
//! use die_orchestrator::reference::{resolve_reference, ReferenceEntity, ResolutionResult};
//!
//! let msg = Message {
//!     id: "m1".into(),
//!     conversation_id: "c1".into(),
//!     role: MessageRole::User,
//!     content: "open /home/me/report.pdf".into(),
//!     context: Some(ContextSnapshot {
//!         active_files: vec!["/home/me/report.pdf".into()],
//!         running_apps: vec![],
//!         current_project: None,
//!         recent_actions: vec![],
//!     }),
//!     timestamp: 1000,
//! };
//! let result = resolve_reference("summarize it", &[msg]);
//! match result {
//!     ResolutionResult::Resolved(ReferenceEntity::File(p)) => {
//!         assert_eq!(p, "/home/me/report.pdf");
//!     }
//!     _ => panic!("expected Resolved(File)"),
//! }
//! ```

use crate::conversation::{Message, MessageRole};

/// A concrete entity that a pronoun might refer to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceEntity {
    /// An individual person (extracted from content by capitalization).
    Person(String),
    /// A file or document path.
    File(String),
    /// A project name.
    Project(String),
    /// A topic or concept (extracted from capitalized nouns).
    Topic(String),
}

impl ReferenceEntity {
    /// True if this entity is of the given kind marker.
    fn kind(&self) -> EntityKind {
        match self {
            Self::Person(_) => EntityKind::Person,
            Self::File(_) => EntityKind::File,
            Self::Project(_) => EntityKind::Project,
            Self::Topic(_) => EntityKind::Topic,
        }
    }
}

/// Internal marker used to apply pronoun type filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntityKind {
    Person,
    File,
    Project,
    Topic,
}

/// Outcome of attempting to resolve a reference in a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionResult {
    /// Query contained no pronouns or deictic phrases — no resolution needed.
    NoReference,
    /// Query contained a pronoun but no candidate entity was found.
    Unresolvable,
    /// Exactly one candidate entity matched.
    Resolved(ReferenceEntity),
    /// Multiple candidate entities matched — surface to user.
    Ambiguous(Vec<ReferenceEntity>),
}

/// Resolve references (pronouns, deictics) in `query` against conversation history.
///
/// `recent_messages` should be in newest-first order; this is the shape
/// returned by [`ConversationStore::recent_messages`].
///
/// # Examples
///
/// ```
/// use die_orchestrator::reference::{resolve_reference, ResolutionResult};
///
/// let result = resolve_reference("what is convergence", &[]);
/// assert_eq!(result, ResolutionResult::NoReference);
/// ```
#[must_use]
pub fn resolve_reference(query: &str, recent_messages: &[Message]) -> ResolutionResult {
    let q = query.to_lowercase();
    let kind_filter = detect_pronoun_kind(&q);
    let has_pronoun = kind_filter.is_some() || contains_generic_pronoun(&q);

    if !has_pronoun {
        return ResolutionResult::NoReference;
    }

    let mut candidates: Vec<ReferenceEntity> = Vec::new();

    for msg in recent_messages {
        let mut from_msg = extract_entities(msg);
        if let Some(kind) = kind_filter {
            from_msg.retain(|e| e.kind() == kind);
        }
        if !from_msg.is_empty() {
            candidates.extend(from_msg);
            break;
        }
    }

    dedupe(&mut candidates);

    match candidates.len() {
        0 => ResolutionResult::Unresolvable,
        1 => ResolutionResult::Resolved(candidates.into_iter().next().unwrap_or(
            ReferenceEntity::Topic("".to_string()),
        )),
        _ => ResolutionResult::Ambiguous(candidates),
    }
}

/// If the query contains a type-qualified deictic ("that file",
/// "this project", "those people"), return the corresponding kind.
fn detect_pronoun_kind(q: &str) -> Option<EntityKind> {
    const PATTERNS: &[(&str, EntityKind)] = &[
        ("that file", EntityKind::File),
        ("this file", EntityKind::File),
        ("the file", EntityKind::File),
        ("that doc", EntityKind::File),
        ("that document", EntityKind::File),
        ("that project", EntityKind::Project),
        ("this project", EntityKind::Project),
        ("the project", EntityKind::Project),
        ("that person", EntityKind::Person),
        ("that topic", EntityKind::Topic),
        ("that thing", EntityKind::Topic),
    ];
    for (pat, kind) in PATTERNS {
        if q.contains(pat) {
            return Some(*kind);
        }
    }
    None
}

/// True if the query contains a generic (type-unqualified) pronoun.
///
/// Covers nominative (he/she/they/it), accusative (him/her/them),
/// possessive (his/her/their), and demonstrative (this/that/these/those)
/// forms — all common in English conversational reference.
fn contains_generic_pronoun(q: &str) -> bool {
    const PRONOUNS: &[&str] = &[
        " it ", " it.", " it,", " it?", " it!",
        " that ", " that.", " that,", " that?", " that!",
        " this ", " this.", " this,", " this?", " this!",
        " these ", " these.", " these,", " these?", " these!",
        " those ", " those.", " those,", " those?", " those!",
        " them ", " them.", " them,", " them?", " them!",
        " they ", " they.", " they,", " they?", " they!",
        " their ", " their.", " their,", " their?", " their!",
        " he ", " he.", " he,", " he?", " he!",
        " she ", " she.", " she,", " she?", " she!",
        " her ", " her.", " her,", " her?", " her!",
        " him ", " him.", " him,", " him?", " him!",
        " his ", " his.", " his,", " his?", " his!",
    ];
    let padded = format!(" {q} ");
    PRONOUNS.iter().any(|p| padded.contains(p))
}

/// Extract candidate entities from a single message.
///
/// ContextSnapshot fields are the strongest signal; content is mined
/// via capitalization as a weaker fallback.
fn extract_entities(msg: &Message) -> Vec<ReferenceEntity> {
    let mut out = Vec::new();
    if let Some(ctx) = &msg.context {
        for f in &ctx.active_files {
            out.push(ReferenceEntity::File(f.clone()));
        }
        if let Some(p) = &ctx.current_project {
            out.push(ReferenceEntity::Project(p.clone()));
        }
    }
    // Only mine content for user messages; assistant replies are less
    // likely to contain the user's intended referent.
    if msg.role == MessageRole::User {
        out.extend(mine_capitalized_tokens(&msg.content));
    }
    out
}

/// Extract capitalized tokens from content as Person/Topic candidates.
///
/// This is a heuristic — anything Capitalized that is not a sentence
/// opener is treated as a potential entity. Delphi-style proper nouns
/// (PascalCase) are kept as Topic; ordinary capitalized words become
/// Person. The distinction is crude; the orchestrator is expected to
/// confirm with the user for ambiguous matches.
fn mine_capitalized_tokens(content: &str) -> Vec<ReferenceEntity> {
    let mut out = Vec::new();
    let mut at_sentence_start = true;
    for raw in content.split_whitespace() {
        let tok = raw.trim_matches(|c: char| !c.is_alphanumeric());
        if tok.is_empty() {
            at_sentence_start = ends_sentence(raw);
            continue;
        }
        let mut chars = tok.chars();
        let first = chars.next().unwrap_or(' ');
        let has_another_upper = chars.any(|c| c.is_uppercase());
        let is_cap = first.is_uppercase();
        if is_cap && !at_sentence_start {
            if has_another_upper {
                out.push(ReferenceEntity::Topic(tok.to_string()));
            } else {
                out.push(ReferenceEntity::Person(tok.to_string()));
            }
        }
        at_sentence_start = ends_sentence(raw);
    }
    out
}

/// True if `tok` ends with a sentence-terminator.
fn ends_sentence(tok: &str) -> bool {
    matches!(tok.chars().last(), Some('.') | Some('!') | Some('?'))
}

/// Remove duplicate entities preserving first-seen order.
fn dedupe(v: &mut Vec<ReferenceEntity>) {
    let mut seen: Vec<ReferenceEntity> = Vec::new();
    v.retain(|e| {
        if seen.contains(e) {
            false
        } else {
            seen.push(e.clone());
            true
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::{ContextSnapshot, Message, MessageRole};

    fn mk_msg(
        content: &str,
        role: MessageRole,
        ctx: Option<ContextSnapshot>,
    ) -> Message {
        Message {
            id: "m1".into(),
            conversation_id: "c1".into(),
            role,
            content: content.into(),
            context: ctx,
            timestamp: 1000,
        }
    }

    // ---- Tier 1: no pronoun ----

    #[test]
    fn no_pronoun_returns_no_reference() {
        let r = resolve_reference("explain convergence theory", &[]);
        assert_eq!(r, ResolutionResult::NoReference);
    }

    #[test]
    fn pronoun_without_history_is_unresolvable() {
        let r = resolve_reference("open it", &[]);
        assert_eq!(r, ResolutionResult::Unresolvable);
    }

    // ---- Tier 2: type-qualified deictics ----

    #[test]
    fn that_file_resolves_from_context() {
        let ctx = ContextSnapshot {
            active_files: vec!["/home/me/report.pdf".into()],
            running_apps: vec![],
            current_project: None,
            recent_actions: vec![],
        };
        let msgs = vec![mk_msg("opened it", MessageRole::User, Some(ctx))];
        let r = resolve_reference("summarize that file", &msgs);
        assert_eq!(
            r,
            ResolutionResult::Resolved(ReferenceEntity::File("/home/me/report.pdf".into()))
        );
    }

    #[test]
    fn that_project_resolves_from_context() {
        let ctx = ContextSnapshot {
            active_files: vec![],
            running_apps: vec![],
            current_project: Some("delphi".into()),
            recent_actions: vec![],
        };
        let msgs = vec![mk_msg("working", MessageRole::User, Some(ctx))];
        let r = resolve_reference("deploy that project", &msgs);
        assert_eq!(
            r,
            ResolutionResult::Resolved(ReferenceEntity::Project("delphi".into()))
        );
    }

    #[test]
    fn that_file_filters_out_projects() {
        // Context has both a project and a file; "that file" must pick the file.
        let ctx = ContextSnapshot {
            active_files: vec!["/x/y.md".into()],
            running_apps: vec![],
            current_project: Some("some-proj".into()),
            recent_actions: vec![],
        };
        let msgs = vec![mk_msg("context", MessageRole::User, Some(ctx))];
        let r = resolve_reference("open that file", &msgs);
        assert_eq!(
            r,
            ResolutionResult::Resolved(ReferenceEntity::File("/x/y.md".into()))
        );
    }

    // ---- Tier 3: generic pronouns ----

    #[test]
    fn generic_it_resolves_single_candidate() {
        let ctx = ContextSnapshot {
            active_files: vec!["/only.txt".into()],
            running_apps: vec![],
            current_project: None,
            recent_actions: vec![],
        };
        let msgs = vec![mk_msg("see it", MessageRole::User, Some(ctx))];
        let r = resolve_reference("send it", &msgs);
        assert_eq!(
            r,
            ResolutionResult::Resolved(ReferenceEntity::File("/only.txt".into()))
        );
    }

    #[test]
    fn generic_it_with_multiple_candidates_is_ambiguous() {
        let ctx = ContextSnapshot {
            active_files: vec!["/a.txt".into(), "/b.txt".into()],
            running_apps: vec![],
            current_project: Some("proj".into()),
            recent_actions: vec![],
        };
        let msgs = vec![mk_msg("context", MessageRole::User, Some(ctx))];
        let r = resolve_reference("handle it", &msgs);
        match r {
            ResolutionResult::Ambiguous(v) => {
                assert_eq!(v.len(), 3);
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    // ---- Tier 4: content mining ----

    #[test]
    fn person_extracted_from_capitalized_content() {
        let msg = mk_msg(
            "I just spoke with Alice about the design.",
            MessageRole::User,
            None,
        );
        let r = resolve_reference("tell her", &[msg]);
        // "her" is a generic pronoun; Alice is the only candidate.
        assert_eq!(
            r,
            ResolutionResult::Resolved(ReferenceEntity::Person("Alice".into()))
        );
    }

    #[test]
    fn topic_extracted_from_pascal_case() {
        let msg = mk_msg("Learning about NonIIDConvergence", MessageRole::User, None);
        let r = resolve_reference("explain it", &[msg]);
        assert_eq!(
            r,
            ResolutionResult::Resolved(ReferenceEntity::Topic("NonIIDConvergence".into()))
        );
    }

    #[test]
    fn assistant_content_is_not_mined() {
        // Assistant messages don't contribute content-mined candidates.
        let msg = mk_msg(
            "I discussed Alice's proposal.",
            MessageRole::Assistant,
            None,
        );
        let r = resolve_reference("email her", &[msg]);
        assert_eq!(r, ResolutionResult::Unresolvable);
    }

    // ---- Tier 5: traversal order and dedup ----

    #[test]
    fn newest_message_wins_over_older() {
        let older = mk_msg(
            "context",
            MessageRole::User,
            Some(ContextSnapshot {
                active_files: vec!["/old.txt".into()],
                running_apps: vec![],
                current_project: None,
                recent_actions: vec![],
            }),
        );
        let newer = mk_msg(
            "context",
            MessageRole::User,
            Some(ContextSnapshot {
                active_files: vec!["/new.txt".into()],
                running_apps: vec![],
                current_project: None,
                recent_actions: vec![],
            }),
        );
        // recent_messages is newest-first.
        let r = resolve_reference("open it", &[newer, older]);
        assert_eq!(
            r,
            ResolutionResult::Resolved(ReferenceEntity::File("/new.txt".into()))
        );
    }

    #[test]
    fn duplicate_entities_are_deduped() {
        let ctx = ContextSnapshot {
            active_files: vec!["/a.txt".into(), "/a.txt".into()],
            running_apps: vec![],
            current_project: None,
            recent_actions: vec![],
        };
        let msg = mk_msg("dup context", MessageRole::User, Some(ctx));
        let r = resolve_reference("handle it", &[msg]);
        assert_eq!(
            r,
            ResolutionResult::Resolved(ReferenceEntity::File("/a.txt".into()))
        );
    }

    // ---- Tier 6: non-triggering edge cases ----

    #[test]
    fn word_containing_it_does_not_trigger() {
        // "whitespace" contains "it" but is not a pronoun.
        let r = resolve_reference("fix the whitespace", &[]);
        assert_eq!(r, ResolutionResult::NoReference);
    }

    #[test]
    fn sentence_opener_capitalization_is_ignored() {
        // "Wednesday" opens the sentence and should not be mined.
        let msg = mk_msg("Wednesday we met.", MessageRole::User, None);
        let r = resolve_reference("discuss it", &[msg]);
        assert_eq!(r, ResolutionResult::Unresolvable);
    }
}

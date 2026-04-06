// SPDX-License-Identifier: MIT

//! # Delphi Protobuf Messages
//!
//! Auto-generated Rust types from the `.proto` definitions in the `proto/`
//! directory. All inter-module IPC in Delphi uses these types serialized
//! with Protocol Buffers per CLAUDE.md Section 3 (Cross-Language Rules).
//!
//! # Modules
//!
//! - [`inference`] — Inference requests, responses, model info, hardware profiles
//! - [`filesystem`] — Search requests/responses, index status, file events
//! - [`orchestrator`] — User intents, task plans, progress, action records
//! - [`compositor`] — Window modes, notifications
//! - [`fortress`] — Credentials, permissions, audit entries

/// Inference subsystem messages.
pub mod inference {
    include!(concat!(env!("OUT_DIR"), "/delphi.inference.rs"));
}

/// Semantic file system messages.
pub mod filesystem {
    include!(concat!(env!("OUT_DIR"), "/delphi.filesystem.rs"));
}

/// DIE orchestrator messages.
pub mod orchestrator {
    include!(concat!(env!("OUT_DIR"), "/delphi.orchestrator.rs"));
}

/// Wayland compositor messages.
pub mod compositor {
    include!(concat!(env!("OUT_DIR"), "/delphi.compositor.rs"));
}

/// Fortress security messages.
pub mod fortress {
    include!(concat!(env!("OUT_DIR"), "/delphi.fortress.rs"));
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;

    #[test]
    fn inference_request_roundtrip() {
        let req = inference::InferenceRequest {
            prompt: "What is Rust?".to_string(),
            max_tokens: 256,
            temperature: 0.7,
            tier: inference::InferenceTier::LocalSmall as i32,
            system_prompt: "You are a helpful assistant.".to_string(),
            conversation_id: "conv-001".to_string(),
        };
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();
        let decoded = inference::InferenceRequest::decode(buf.as_slice()).unwrap();
        assert_eq!(decoded.prompt, "What is Rust?");
        assert_eq!(decoded.max_tokens, 256);
    }

    #[test]
    fn search_request_roundtrip() {
        let req = filesystem::SearchRequest {
            query: "tax return 2024".to_string(),
            max_results: 10,
            file_types: vec!["pdf".to_string(), "md".to_string()],
            time_range: Some(filesystem::TimeRange {
                start: 1704067200,
                end: 1735689600,
            }),
            paths: vec![],
        };
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();
        let decoded = filesystem::SearchRequest::decode(buf.as_slice()).unwrap();
        assert_eq!(decoded.query, "tax return 2024");
        assert_eq!(decoded.file_types.len(), 2);
    }

    #[test]
    fn user_intent_roundtrip() {
        let intent = orchestrator::UserIntent {
            raw_text: "Summarize this document".to_string(),
            source: orchestrator::IntentSource::CommandBar as i32,
            conversation_id: "conv-002".to_string(),
            mode: orchestrator::UiMode::Assisted as i32,
            timestamp: 1712400000,
        };
        let mut buf = Vec::new();
        intent.encode(&mut buf).unwrap();
        let decoded = orchestrator::UserIntent::decode(buf.as_slice()).unwrap();
        assert_eq!(decoded.raw_text, "Summarize this document");
    }

    #[test]
    fn window_mode_roundtrip() {
        let mode = compositor::WindowMode {
            window_id: 42,
            mode: compositor::WindowModeType::Autonomous as i32,
        };
        let mut buf = Vec::new();
        mode.encode(&mut buf).unwrap();
        let decoded = compositor::WindowMode::decode(buf.as_slice()).unwrap();
        assert_eq!(decoded.window_id, 42);
    }

    #[test]
    fn audit_entry_roundtrip() {
        let entry = fortress::AuditEntry {
            action_id: "act-001".to_string(),
            timestamp: 1712400000,
            module: "die-orchestrator".to_string(),
            action: "read_file".to_string(),
            target: "/home/user/docs/report.pdf".to_string(),
            permission_tier: fortress::PermissionTier::Autonomous as i32,
            result: fortress::PermissionResult::Allowed as i32,
            proof_hash: vec![0u8; 32],
        };
        let mut buf = Vec::new();
        entry.encode(&mut buf).unwrap();
        let decoded = fortress::AuditEntry::decode(buf.as_slice()).unwrap();
        assert_eq!(decoded.module, "die-orchestrator");
        assert_eq!(decoded.proof_hash.len(), 32);
    }
}

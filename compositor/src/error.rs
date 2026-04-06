// SPDX-License-Identifier: MIT

//! Error types for the Delphi compositor.
//!
//! Compositor errors degrade gracefully: if the GPU backend fails,
//! the compositor falls back to software rendering before giving up.

/// Errors produced by the Delphi compositor.
///
/// # Examples
///
/// ```
/// use compositor::CompositorError;
///
/// let err = CompositorError::BackendInit("no DRM device found".to_string());
/// assert!(err.to_string().contains("DRM"));
/// ```
#[derive(Debug, thiserror::Error)]
pub enum CompositorError {
    /// Graphics backend initialization failed.
    #[error("backend initialization failed: {0}")]
    BackendInit(String),

    /// A rendering operation failed.
    #[error("rendering error: {0}")]
    Render(String),

    /// Input device handling failed.
    #[error("input error: {0}")]
    Input(String),

    /// Wayland protocol error.
    #[error("wayland protocol error: {0}")]
    Protocol(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_init_error_is_descriptive() {
        let err = CompositorError::BackendInit(
            "no DRM device found — check kernel module loading".to_string(),
        );
        assert!(err.to_string().contains("DRM"));
        assert!(err.to_string().contains("kernel module"));
    }
}

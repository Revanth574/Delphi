// SPDX-License-Identifier: MIT

//! Local model loading and inference execution.
//!
//! Wraps `llama-cpp-2` to provide model discovery, loading, and
//! text generation. Handles GGUF model files and provides streaming
//! token output.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::LlamaModel;
use llama_cpp_2::token::data_array::LlamaTokenDataArray;
use tracing::{debug, info, warn};

use crate::error::InferenceError;

/// Default model directory.
const DEFAULT_MODEL_DIR: &str = ".local/share/delphi/models";

/// Default inference timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Discovered model file on disk.
///
/// # Examples
///
/// ```
/// use die_inference::model::ModelFile;
///
/// let mf = ModelFile {
///     path: std::path::PathBuf::from("/models/qwen.gguf"),
///     filename: "qwen.gguf".to_string(),
///     size_mb: 4096,
/// };
/// assert!(mf.filename.ends_with(".gguf"));
/// ```
#[derive(Debug, Clone)]
pub struct ModelFile {
    /// Full path to the GGUF file.
    pub path: PathBuf,
    /// Filename only.
    pub filename: String,
    /// File size in megabytes.
    pub size_mb: u64,
}

/// Get the model directory path.
///
/// Uses `$HOME/.local/share/delphi/models/` by default.
///
/// # Examples
///
/// ```
/// use die_inference::model::model_dir;
///
/// let dir = model_dir();
/// assert!(dir.to_string_lossy().contains("delphi"));
/// ```
#[must_use]
pub fn model_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(DEFAULT_MODEL_DIR)
}

/// Scan the model directory for GGUF files.
///
/// Returns a list of discovered model files sorted by size (largest first).
///
/// # Examples
///
/// ```no_run
/// use die_inference::model::discover_models;
///
/// let models = discover_models(None);
/// for m in &models {
///     println!("{}: {}MB", m.filename, m.size_mb);
/// }
/// ```
#[must_use]
pub fn discover_models(dir: Option<&Path>) -> Vec<ModelFile> {
    let search_dir = dir
        .map(PathBuf::from)
        .unwrap_or_else(model_dir);

    if !search_dir.exists() {
        info!(
            path = %search_dir.display(),
            "model directory does not exist"
        );
        return Vec::new();
    }

    let mut models = Vec::new();

    let entries = match std::fs::read_dir(&search_dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(
                path = %search_dir.display(),
                error = %e,
                "failed to read model directory"
            );
            return Vec::new();
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "gguf") {
            let size_mb = entry.metadata().map(|m| m.len() / (1024 * 1024)).unwrap_or(0);
            let filename = path
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default();

            debug!(filename = %filename, size_mb, "found GGUF model");
            models.push(ModelFile {
                path,
                filename,
                size_mb,
            });
        }
    }

    // Sort largest first — we prefer the most capable model.
    models.sort_by(|a, b| b.size_mb.cmp(&a.size_mb));

    info!(
        count = models.len(),
        directory = %search_dir.display(),
        "model discovery complete"
    );

    models
}

/// A loaded LLM model ready for inference.
///
/// Wraps `llama-cpp-2`'s model and context objects.
///
/// # Examples
///
/// ```no_run
/// use die_inference::model::LocalModel;
/// use std::path::Path;
///
/// let model = LocalModel::load(Path::new("model.gguf"), 2048, 0)?;
/// let response = model.generate("Hello, world!", 128, 30)?;
/// println!("{}", response.text);
/// # Ok::<(), die_inference::error::InferenceError>(())
/// ```
pub struct LocalModel {
    /// The loaded llama.cpp model.
    model: LlamaModel,
    /// The llama.cpp backend (must stay alive).
    _backend: LlamaBackend,
    /// Context window size.
    context_size: u32,
    /// Model file path (for logging).
    model_path: PathBuf,
}

impl std::fmt::Debug for LocalModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalModel")
            .field("context_size", &self.context_size)
            .field("model_path", &self.model_path)
            .finish_non_exhaustive()
    }
}

/// Result of a text generation request.
///
/// # Examples
///
/// ```
/// use die_inference::model::GenerationResult;
///
/// let result = GenerationResult {
///     text: "Hello!".to_string(),
///     tokens_generated: 2,
///     latency_ms: 150,
///     model_name: "qwen2.5-1.5b".to_string(),
/// };
/// assert_eq!(result.tokens_generated, 2);
/// ```
#[derive(Debug, Clone)]
pub struct GenerationResult {
    /// Generated text.
    pub text: String,
    /// Number of tokens generated.
    pub tokens_generated: u32,
    /// Total generation time in milliseconds.
    pub latency_ms: u64,
    /// Name of the model that generated this.
    pub model_name: String,
}

impl LocalModel {
    /// Load a GGUF model from disk.
    ///
    /// # Arguments
    ///
    /// * `path` — Path to the `.gguf` file
    /// * `context_size` — Context window size in tokens
    /// * `gpu_layers` — Number of layers to offload to GPU (0 = CPU only)
    ///
    /// # Errors
    ///
    /// Returns `InferenceError::ModelLoad` if the file doesn't exist
    /// or if llama.cpp fails to load it.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use die_inference::model::LocalModel;
    /// use std::path::Path;
    ///
    /// let model = LocalModel::load(Path::new("model.gguf"), 2048, 0)?;
    /// # Ok::<(), die_inference::error::InferenceError>(())
    /// ```
    pub fn load(
        path: &Path,
        context_size: u32,
        gpu_layers: u32,
    ) -> Result<Self, InferenceError> {
        if !path.exists() {
            return Err(InferenceError::ModelLoad(format!(
                "model file not found: {}. \
                Download one with: curl -L \
                https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/\
                qwen2.5-1.5b-instruct-q4_k_m.gguf \
                -o {}",
                path.display(),
                model_dir().join("qwen2.5-1.5b.gguf").display()
            )));
        }

        info!(
            path = %path.display(),
            context_size,
            gpu_layers,
            "loading model"
        );

        let backend = LlamaBackend::init()
            .map_err(|e| InferenceError::ModelLoad(format!(
                "llama backend init failed: {e}"
            )))?;

        let model_params = LlamaModelParams::default()
            .with_n_gpu_layers(gpu_layers);

        let model = LlamaModel::load_from_file(&backend, path, &model_params)
            .map_err(|e| InferenceError::ModelLoad(format!(
                "failed to load {}: {e}",
                path.display()
            )))?;

        info!(
            path = %path.display(),
            "model loaded successfully"
        );

        Ok(Self {
            model,
            _backend: backend,
            context_size,
            model_path: path.to_path_buf(),
        })
    }

    /// Generate text from a prompt.
    ///
    /// # Arguments
    ///
    /// * `prompt` — The input text
    /// * `max_tokens` — Maximum number of tokens to generate
    /// * `timeout_secs` — Timeout in seconds (0 = use default of 30s)
    ///
    /// # Errors
    ///
    /// Returns `InferenceError::Timeout` if generation exceeds the timeout,
    /// or other inference errors on failure.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use die_inference::model::LocalModel;
    /// use std::path::Path;
    ///
    /// let model = LocalModel::load(Path::new("model.gguf"), 2048, 0)?;
    /// let result = model.generate("What is Rust?", 256, 30)?;
    /// println!("Generated {} tokens in {}ms", result.tokens_generated, result.latency_ms);
    /// # Ok::<(), die_inference::error::InferenceError>(())
    /// ```
    pub fn generate(
        &self,
        prompt: &str,
        max_tokens: u32,
        timeout_secs: u64,
    ) -> Result<GenerationResult, InferenceError> {
        let timeout = if timeout_secs == 0 {
            Duration::from_secs(DEFAULT_TIMEOUT_SECS)
        } else {
            Duration::from_secs(timeout_secs)
        };

        let start = Instant::now();

        // Tokenize the prompt.
        let tokens = self
            .model
            .str_to_token(prompt, llama_cpp_2::model::AddBos::Always)
            .map_err(|e| InferenceError::ModelLoad(format!(
                "tokenization failed: {e}"
            )))?;

        debug!(
            prompt_tokens = tokens.len(),
            max_tokens,
            "starting generation"
        );

        // Create a context for this generation.
        let ctx_params = LlamaContextParams::default()
            .with_n_ctx(std::num::NonZeroU32::new(self.context_size));

        let mut ctx = self
            .model
            .new_context(&self._backend, ctx_params)
            .map_err(|e| InferenceError::ModelLoad(format!(
                "context creation failed: {e}"
            )))?;

        // Process the prompt tokens.
        let mut batch = LlamaBatch::new(self.context_size as usize, 1);

        for (i, &token) in tokens.iter().enumerate() {
            let is_last = i == tokens.len() - 1;
            batch.add(token, i as i32, &[0], is_last)
                .map_err(|e| InferenceError::ModelLoad(format!(
                    "batch add failed: {e}"
                )))?;
        }

        ctx.decode(&mut batch)
            .map_err(|e| InferenceError::ModelLoad(format!(
                "prompt decode failed: {e}"
            )))?;

        // Generate tokens one at a time.
        let mut output_tokens = Vec::new();
        let mut n_cur = tokens.len();

        for _ in 0..max_tokens {
            // Check timeout.
            if start.elapsed() > timeout {
                warn!(
                    elapsed_ms = start.elapsed().as_millis() as u64,
                    timeout_ms = timeout.as_millis() as u64,
                    "inference timeout"
                );
                return Err(InferenceError::Timeout(timeout.as_millis() as u64));
            }

            // Sample the next token.
            let candidates = ctx.candidates_ith(batch.n_tokens() - 1);
            let mut candidates_data = LlamaTokenDataArray::from_iter(
                candidates,
                false,
            );
            let next_token = candidates_data.sample_token_greedy();

            // Check for end of sequence.
            if self.model.is_eog_token(next_token) {
                debug!("end of generation token received");
                break;
            }

            output_tokens.push(next_token);

            // Prepare next batch.
            batch.clear();
            batch.add(next_token, n_cur as i32, &[0], true)
                .map_err(|e| InferenceError::ModelLoad(format!(
                    "batch add failed: {e}"
                )))?;

            n_cur += 1;

            ctx.decode(&mut batch)
                .map_err(|e| InferenceError::ModelLoad(format!(
                    "decode failed: {e}"
                )))?;
        }

        // Detokenize the output.
        let mut text_bytes = Vec::new();
        for &t in &output_tokens {
            let piece = self
                .model
                .token_to_piece_bytes(t, 32, false, None)
                .map_err(|e| InferenceError::ModelLoad(format!(
                    "detokenization failed: {e}"
                )))?;
            text_bytes.extend_from_slice(&piece);
        }
        let text = String::from_utf8_lossy(&text_bytes).into_owned();

        let latency_ms = start.elapsed().as_millis() as u64;
        let model_name = self
            .model_path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".to_string());

        info!(
            tokens_generated = output_tokens.len(),
            latency_ms,
            model_name = %model_name,
            "generation complete"
        );

        Ok(GenerationResult {
            text,
            tokens_generated: output_tokens.len() as u32,
            latency_ms,
            model_name,
        })
    }

    /// Get the model file path.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use die_inference::model::LocalModel;
    /// use std::path::Path;
    ///
    /// let model = LocalModel::load(Path::new("model.gguf"), 2048, 0)?;
    /// assert!(model.path().exists());
    /// # Ok::<(), die_inference::error::InferenceError>(())
    /// ```
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.model_path
    }
}

/// Generate the actionable "no model found" error message.
///
/// # Examples
///
/// ```
/// use die_inference::model::no_model_error_message;
///
/// let msg = no_model_error_message();
/// assert!(msg.contains("curl"));
/// assert!(msg.contains("gguf"));
/// ```
#[must_use]
pub fn no_model_error_message() -> String {
    format!(
        "No GGUF model found in {}. Download one with:\n\
         curl -L https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/\
         qwen2.5-1.5b-instruct-q4_k_m.gguf \
         -o {}/qwen2.5-1.5b.gguf",
        model_dir().display(),
        model_dir().display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_dir_contains_delphi() {
        let dir = model_dir();
        assert!(dir.to_string_lossy().contains("delphi"));
        assert!(dir.to_string_lossy().contains("models"));
    }

    #[test]
    fn discover_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let models = discover_models(Some(dir.path()));
        assert!(models.is_empty());
    }

    #[test]
    fn discover_finds_gguf_files() {
        let dir = tempfile::tempdir().unwrap();

        // Create fake GGUF files.
        std::fs::write(dir.path().join("model-small.gguf"), "fake").unwrap();
        std::fs::write(dir.path().join("model-large.gguf"), "fake-large-data").unwrap();
        std::fs::write(dir.path().join("not-a-model.txt"), "ignored").unwrap();

        let models = discover_models(Some(dir.path()));
        assert_eq!(models.len(), 2);

        // Only .gguf files found.
        assert!(models.iter().all(|m| m.filename.ends_with(".gguf")));
    }

    #[test]
    fn discover_nonexistent_directory() {
        let models = discover_models(Some(Path::new("/nonexistent/path")));
        assert!(models.is_empty());
    }

    #[test]
    fn no_model_message_is_actionable() {
        let msg = no_model_error_message();
        assert!(msg.contains("curl"));
        assert!(msg.contains("gguf"));
        assert!(msg.contains("huggingface"));
    }

    #[test]
    fn load_nonexistent_model_gives_actionable_error() {
        let result = LocalModel::load(
            Path::new("/nonexistent/model.gguf"),
            2048,
            0,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found"));
        assert!(err.contains("curl"));
    }

    #[test]
    fn generation_result_fields() {
        let result = GenerationResult {
            text: "Hello!".to_string(),
            tokens_generated: 2,
            latency_ms: 150,
            model_name: "test-model".to_string(),
        };
        assert_eq!(result.tokens_generated, 2);
        assert_eq!(result.latency_ms, 150);
    }
}

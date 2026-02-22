use anyhow::{Result, Context};
use ort::{
    inputs,
    session::{Session, builder::GraphOptimizationLevel},
};
use std::sync::OnceLock;
use tokenizers::Tokenizer;
use ndarray::Array2;
use tracing::info;

pub struct ShieldEngine {
    session: Session,
    tokenizer: Tokenizer,
}

static SHIELD_ENGINE: OnceLock<ShieldEngine> = OnceLock::new();

impl ShieldEngine {
    /// Initialize the Shield AI engine from a local ONNX model file and a local
    /// HuggingFace tokenizer JSON file.
    pub fn init(model_path: &str, tokenizer_path: &str) -> Result<()> {
        info!("Loading Prompt Injection Shield model from {}", model_path);

        let session = Session::builder()?
            .with_execution_providers([
                ort::execution_providers::TensorRTExecutionProvider::default().build(),
                ort::execution_providers::CUDAExecutionProvider::default().build(),
                ort::execution_providers::CPUExecutionProvider::default().build(),
            ])?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .with_intra_threads(2)?
            .commit_from_file(model_path)
            .context("Failed to load Shield ONNX model")?;

        info!("Loading Shield tokenizer from {}", tokenizer_path);
        let tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(|e| anyhow::anyhow!("Failed to load Shield tokenizer from '{}': {}", tokenizer_path, e))?;

        let engine = ShieldEngine { session, tokenizer };
        let _ = SHIELD_ENGINE.set(engine);

        info!("Shield AI engine loaded successfully");
        Ok(())
    }

    pub fn global() -> Option<&'static ShieldEngine> {
        SHIELD_ENGINE.get()
    }

    /// Returns `true` if the text is classified as a prompt injection or jailbreak.
    pub fn is_injection(text: &str) -> Result<bool> {
        if let Some(engine) = Self::global() {
            engine.run_inference(text)
        } else {
            // If the engine isn't initialized (e.g., config turned it off), default to safe.
            Ok(false)
        }
    }

    fn run_inference(&self, text: &str) -> Result<bool> {
        // 1. Tokenize
        let encoding = self.tokenizer.encode(text, true)
            .map_err(|e| anyhow::anyhow!("Tokenization failed: {}", e))?;

        let input_ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
        let attention_mask: Vec<i64> = encoding.get_attention_mask().iter().map(|&id| id as i64).collect();
        
        let batch_size = 1;
        let seq_len = input_ids.len();

        let input_ids_array = Array2::from_shape_vec((batch_size, seq_len), input_ids)?;
        let attention_mask_array = Array2::from_shape_vec((batch_size, seq_len), attention_mask)?;

        // 2. Run inference. Some DeBERTa models do not require token_type_ids.
        // We attempt to run without token_type_ids.
        let outputs = match self.session.run(inputs![
            "input_ids" => input_ids_array.clone(),
            "attention_mask" => attention_mask_array.clone(),
        ]?) {
            Ok(o) => o,
            Err(_) => {
                // Try again with token_type_ids if required by the model graph
                let token_type_ids: Vec<i64> = encoding.get_type_ids().iter().map(|&id| id as i64).collect();
                let token_type_ids_array = Array2::from_shape_vec((batch_size, seq_len), token_type_ids)?;
                self.session.run(inputs![
                    "input_ids" => input_ids_array,
                    "attention_mask" => attention_mask_array,
                    "token_type_ids" => token_type_ids_array,
                ]?)?
            }
        };

        // 3. Extract logits. ProtectAI's deberta prompt injection model
        // has 2 output classes: [Safe, Injection].
        // We take the argmax.
        let logits = outputs["logits"].try_extract_tensor::<f32>()?;
        
        // Logits is expected to be [1, 2].
        let slice = logits.as_slice().unwrap_or(&[]);
        if slice.len() >= 2 {
            let safe_score = slice[0];
            let injection_score = slice[1];
            return Ok(injection_score > safe_score);
        }

        // Fallback if logits shape is unexpected
        Ok(false)
    }
}

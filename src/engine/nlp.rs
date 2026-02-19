use anyhow::{Result, Context};
use ort::{
    inputs,
    session::{Session, builder::GraphOptimizationLevel},
};
use std::sync::OnceLock;
use tokenizers::Tokenizer;
use ndarray::Array2;
use tracing::info;

#[derive(Debug, Clone)]
pub struct Entity {
    pub text: String,
    pub label: String,
    pub score: f32,
    pub start: usize,
    pub end: usize,
}

pub struct NlpEngine {
    session: Session,
    tokenizer: Tokenizer,
}

static NLP_ENGINE: OnceLock<NlpEngine> = OnceLock::new();

// Standard BERT NER Labels (CoNLL-2003)
// 0: O, 1: B-MISC, 2: I-MISC, 3: B-PER, 4: I-PER, 5: B-ORG, 6: I-ORG, 7: B-LOC, 8: I-LOC
const ID2LABEL: [&str; 9] = ["O", "B-MISC", "I-MISC", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-LOC", "I-LOC"];

impl NlpEngine {
    /// Initialize the NLP engine from a local ONNX model file and a local
    /// HuggingFace tokenizer JSON file.  Both files must already be present on
    /// disk — no network calls are made.
    pub fn init(model_path: &str, tokenizer_path: &str) -> Result<()> {
        info!("Loading NLP model from {}", model_path);

        let session = Session::builder()?
            .with_execution_providers([
                ort::execution_providers::TensorRTExecutionProvider::default().build(),
                ort::execution_providers::CUDAExecutionProvider::default().build(),
                ort::execution_providers::CPUExecutionProvider::default().build(),
            ])?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .with_intra_threads(4)?
            .commit_from_file(model_path)
            .context("Failed to load ONNX model")?;

        info!("Loading tokenizer from {}", tokenizer_path);
        // Load from a local file — no HuggingFace network call.
        let tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(|e| anyhow::anyhow!("Failed to load tokenizer from '{}': {}", tokenizer_path, e))?;

        let engine = NlpEngine { session, tokenizer };
        let _ = NLP_ENGINE.set(engine);

        info!("NLP engine loaded successfully");
        Ok(())
    }

    pub fn global() -> Option<&'static NlpEngine> {
        NLP_ENGINE.get()
    }

    pub fn predict(text: &str) -> Result<Vec<Entity>> {
        if let Some(engine) = Self::global() {
            engine.run_inference(text)
        } else {
            Ok(vec![])
        }
    }

    pub fn run_inference(&self, text: &str) -> Result<Vec<Entity>> {
        // 1. Tokenize
        let encoding = self.tokenizer.encode(text, true)
            .map_err(|e| anyhow::anyhow!("Tokenization failed: {}", e))?;

        let input_ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
        let attention_mask: Vec<i64> = encoding.get_attention_mask().iter().map(|&id| id as i64).collect();
        let token_type_ids: Vec<i64> = encoding.get_type_ids().iter().map(|&id| id as i64).collect();

        let batch_size = 1;
        let seq_len = input_ids.len();

        let input_ids_array = Array2::from_shape_vec((batch_size, seq_len), input_ids)?;
        let attention_mask_array = Array2::from_shape_vec((batch_size, seq_len), attention_mask)?;
        let token_type_ids_array = Array2::from_shape_vec((batch_size, seq_len), token_type_ids)?;

        // 2. Run inference
        let outputs = self.session.run(inputs![
            "input_ids" => input_ids_array,
            "attention_mask" => attention_mask_array,
            "token_type_ids" => token_type_ids_array,
        ]?)?;

        // 3. Process logits → entity spans
        let logits = outputs["logits"].try_extract_tensor::<f32>()?;
        let mut entities = Vec::new();
        let mut current_entity_start: Option<usize> = None;
        let mut current_entity_end: Option<usize> = None;
        let mut current_entity_label: Option<String> = None;

        let offsets = encoding.get_offsets();

        for (i, token_logits) in logits.view().outer_iter().nth(0).unwrap().outer_iter().enumerate() {
            let (label_idx, _score) = token_logits.iter().enumerate()
                .fold((0, f32::MIN), |(max_idx, max_val), (idx, &val)| {
                    if val > max_val { (idx, val) } else { (max_idx, max_val) }
                });

            let label = ID2LABEL.get(label_idx).unwrap_or(&"O");

            if *label == "O" {
                if let (Some(start), Some(end), Some(lbl)) =
                    (current_entity_start, current_entity_end, current_entity_label.clone())
                {
                    entities.push(Entity {
                        text: text[start..end].to_string(),
                        label: lbl,
                        score: 1.0,
                        start,
                        end,
                    });
                    current_entity_start = None;
                    current_entity_end = None;
                    current_entity_label = None;
                }
                continue;
            }

            let (start, end) = offsets[i];
            if start == end { continue; }

            if label.starts_with("B-") {
                if let (Some(s), Some(e), Some(lbl)) =
                    (current_entity_start, current_entity_end, current_entity_label.take())
                {
                    entities.push(Entity {
                        text: text[s..e].to_string(),
                        label: lbl,
                        score: 1.0,
                        start: s,
                        end: e,
                    });
                }
                current_entity_start = Some(start);
                current_entity_end = Some(end);
                current_entity_label = Some(label[2..].to_string());
            } else if label.starts_with("I-") {
                if let Some(ref lbl) = current_entity_label {
                    if lbl == &label[2..] {
                        current_entity_end = Some(end);
                    } else {
                        if let (Some(s), Some(e), Some(prev_lbl)) =
                            (current_entity_start, current_entity_end, current_entity_label.take())
                        {
                            entities.push(Entity {
                                text: text[s..e].to_string(),
                                label: prev_lbl,
                                score: 1.0,
                                start: s,
                                end: e,
                            });
                        }
                        current_entity_start = Some(start);
                        current_entity_end = Some(end);
                        current_entity_label = Some(label[2..].to_string());
                    }
                } else {
                    current_entity_start = Some(start);
                    current_entity_end = Some(end);
                    current_entity_label = Some(label[2..].to_string());
                }
            }
        }

        if let (Some(s), Some(e), Some(lbl)) =
            (current_entity_start, current_entity_end, current_entity_label.take())
        {
            entities.push(Entity {
                text: text[s..e].to_string(),
                label: lbl,
                score: 1.0,
                start: s,
                end: e,
            });
        }

        Ok(entities)
    }
}

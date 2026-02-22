use serde::{Deserialize, Serialize};
use crate::api::models::{OpenAIChatRequest, OpenAIChatMessage};
use anyhow::Result;

// --- Gemini Request Models ---

#[derive(Debug, Serialize, Deserialize)]
pub struct GeminiRequest {
    pub contents: Vec<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation_config: Option<GeminiGenerationConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GeminiContent {
    pub role: String,
    pub parts: Vec<GeminiPart>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GeminiPart {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GeminiGenerationConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
}

// --- Gemini Response Models ---

#[derive(Debug, Serialize, Deserialize)]
pub struct GeminiResponse {
    pub candidates: Option<Vec<GeminiCandidate>>,
    pub error: Option<GeminiError>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GeminiCandidate {
    pub content: GeminiContent,
    #[serde(rename = "finishReason")]
    pub finish_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GeminiError {
    pub code: i32,
    pub message: String,
    pub status: String,
}

// --- Conversion Logic ---

impl GeminiRequest {
    pub fn from_openai(req: &OpenAIChatRequest) -> Result<Self> {
        let contents = req.messages.iter().map(|msg| {
            // Map roles: user -> user, assistant -> model, system -> user (for now, or specific handling)
            // Gemini roles: "user", "model"
            let role = match msg.role.as_str() {
                "assistant" => "model",
                _ => "user", // "system" also maps to user in simple cases for Gemini 1.0, 1.5 has system_instruction
            }
            .to_string();

            // Extract text from OpenAI content (Value)
            // If string, simple. If array (multimodal), we only take text parts for now or flatten.
            let text = match &msg.content {
                Some(crate::api::models::ChatMessageContent::Text(s)) => s.clone(),
                Some(crate::api::models::ChatMessageContent::Parts(arr)) => {
                    let mut full_text = String::new();
                    for item in arr {
                        if let Some(obj) = item.as_object() {
                            if let Some(t) = obj.get("type").and_then(|v| v.as_str()) {
                                if t == "text" {
                                    if let Some(val) = obj.get("text").and_then(|v| v.as_str()) {
                                        full_text.push_str(val);
                                        full_text.push('\n');
                                    }
                                }
                            }
                        }
                    }
                    full_text
                },
                None => String::new(),
            };

            GeminiContent {
                role,
                parts: vec![GeminiPart { text }],
            }
        }).collect();

        let generation_config = if req.temperature.is_some() {
             Some(GeminiGenerationConfig {
                 temperature: req.temperature,
                 max_output_tokens: None, // could map max_tokens if present
             })
        } else {
            None
        };

        Ok(GeminiRequest {
            contents,
            generation_config,
        })
    }
}

// We need a way to convert GeminiResponse back to OpenAI Format (JSON Value mostly for the handler)
// But handlers.rs expects to return a Response object directly or modify body.
// We'll create a struct for OpenAIResponse to serialize it back.

#[derive(Debug, Serialize)]
pub struct OpenAIChatResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<OpenAIChatChoice>,
}

#[derive(Debug, Serialize)]
pub struct OpenAIChatChoice {
    pub index: u32,
    pub message: OpenAIChatMessage,
    pub finish_reason: String,
}

impl OpenAIChatResponse {
    pub fn from_gemini(gemini_resp: GeminiResponse, model: String) -> Result<Self> {
        if let Some(error) = gemini_resp.error {
            return Err(anyhow::anyhow!("Gemini Error: {} ({})", error.message, error.status));
        }

        let choices = gemini_resp.candidates.unwrap_or_default().into_iter().enumerate().map(|(i, c)| {
            // Map Gemini role "model" -> "assistant"
            let role = if c.content.role == "model" { "assistant" } else { "user" }.to_string();
            let content_text = c.content.parts.first().map(|p| p.text.clone()).unwrap_or_default();
            
            OpenAIChatChoice {
                index: i as u32,
                message: OpenAIChatMessage {
                    role,
                    content: Some(crate::api::models::ChatMessageContent::Text(content_text)),
                    name: None,
                    unknown_fields: Default::default(),
                },
                finish_reason: c.finish_reason.unwrap_or("stop".to_string()),
            }
        }).collect();

        Ok(OpenAIChatResponse {
            id: format!("chatcmpl-{}", uuid::Uuid::new_v4()),
            object: "chat.completion".to_string(),
            created: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
            model,
            choices,
        })
    }
}

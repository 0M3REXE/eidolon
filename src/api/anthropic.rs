use serde::{Deserialize, Serialize};
use crate::api::models::{OpenAIChatMessage};
use anyhow::Result;

// ── Anthropic Request ──────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AnthropicRequest {
    pub model: String,
    pub messages: Vec<AnthropicMessage>,
    pub max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnthropicMessage {
    pub role: String,
    pub content: AnthropicContent,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AnthropicContent {
    Text(String),
    Blocks(Vec<AnthropicBlock>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnthropicBlock {
    #[serde(rename = "type")]
    pub block_type: String,
    pub text: String,
}

// ── Anthropic Response ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AnthropicResponse {
    pub id: String,
    pub model: String,
    pub content: Vec<AnthropicBlock>,
    pub stop_reason: Option<String>,
    pub usage: Option<AnthropicUsage>,
}

#[derive(Debug, Deserialize)]
pub struct AnthropicUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

// ── OpenAI-compatible response (reused from gemini.rs pattern) ────────────

#[derive(Debug, Serialize)]
pub struct OpenAIChatResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<OpenAIChatChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<OpenAIUsage>,
}

#[derive(Debug, Serialize)]
pub struct OpenAIChatChoice {
    pub index: u32,
    pub message: OpenAIChatMessage,
    pub finish_reason: String,
}

#[derive(Debug, Serialize)]
pub struct OpenAIUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

// ── Conversion logic ──────────────────────────────────────────────────────

impl AnthropicRequest {
    /// Build an Anthropic request from OpenAI-compatible messages.
    pub fn from_openai(
        model: &str,
        messages: &[OpenAIChatMessage],
        temperature: Option<f32>,
        max_tokens: u32,
    ) -> Self {
        // Extract a leading system message if present.
        let system = messages.iter().find(|m| m.role == "system").map(|m| {
            match &m.content {
                serde_json::Value::String(s) => s.clone(),
                _ => String::new(),
            }
        });

        let chat_messages: Vec<AnthropicMessage> = messages
            .iter()
            .filter(|m| m.role != "system")
            .map(|m| {
                let content = match &m.content {
                    serde_json::Value::String(s) => AnthropicContent::Text(s.clone()),
                    serde_json::Value::Array(arr) => {
                        let blocks = arr.iter().filter_map(|v| {
                            if v.get("type")?.as_str()? == "text" {
                                Some(AnthropicBlock {
                                    block_type: "text".to_string(),
                                    text: v.get("text")?.as_str()?.to_string(),
                                })
                            } else {
                                None
                            }
                        }).collect();
                        AnthropicContent::Blocks(blocks)
                    }
                    _ => AnthropicContent::Text(String::new()),
                };
                AnthropicMessage {
                    role: m.role.clone(),
                    content,
                }
            })
            .collect();

        AnthropicRequest {
            model: model.to_string(),
            messages: chat_messages,
            max_tokens,
            temperature,
            system,
        }
    }
}

impl OpenAIChatResponse {
    /// Convert an Anthropic response back to the OpenAI format.
    pub fn from_anthropic(resp: AnthropicResponse) -> Result<Self> {
        let text = resp.content.into_iter()
            .filter(|b| b.block_type == "text")
            .map(|b| b.text)
            .collect::<Vec<_>>()
            .join("");

        let usage = resp.usage.map(|u| OpenAIUsage {
            prompt_tokens: u.input_tokens,
            completion_tokens: u.output_tokens,
            total_tokens: u.input_tokens + u.output_tokens,
        });

        Ok(OpenAIChatResponse {
            id: format!("chatcmpl-{}", resp.id),
            object: "chat.completion".to_string(),
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            model: resp.model,
            choices: vec![OpenAIChatChoice {
                index: 0,
                message: OpenAIChatMessage {
                    role: "assistant".to_string(),
                    content: serde_json::Value::String(text),
                    name: None,
                    unknown_fields: Default::default(),
                },
                finish_reason: resp.stop_reason.unwrap_or("stop".to_string()),
            }],
            usage,
        })
    }
}

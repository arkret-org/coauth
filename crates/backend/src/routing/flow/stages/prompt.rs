//! Prompt stage side effects.
//!
//! Validates that all required fields are present in the submitted data
//! and stores the collected values in the flow context under `prompt_data`.

use coauth_data::flow::{PromptField, StageOutcome, StageValidationError};
use serde_json::Value;

use super::StageExecutionError;

/// Execute the prompt stage.
///
/// Checks that every required field has a non-empty value in the submitted
/// `data` object.  On success the data is stored in the flow context as
/// `prompt_data`.
pub async fn execute(
    data: &Value,
    fields: &[PromptField],
    context: &mut Value,
) -> Result<StageOutcome, StageExecutionError> {
    let mut errors = Vec::new();

    for field in fields {
        if field.required {
            let value = data.get(&field.field_key);
            let is_missing = match value {
                None | Some(Value::Null) => true,
                Some(Value::String(s)) if s.is_empty() => true,
                _ => false,
            };

            if is_missing {
                errors.push(StageValidationError {
                    field: Some(field.field_key.clone()),
                    message: format!("{} is required", field.label),
                    code: "required".into(),
                });
            }
        }
    }

    if !errors.is_empty() {
        return Ok(StageOutcome::Retry { errors });
    }

    if let Some(ctx) = context.as_object_mut() {
        ctx.insert("prompt_data".into(), data.clone());
    }

    Ok(StageOutcome::Continue)
}

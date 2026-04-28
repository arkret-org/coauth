pub mod types;

use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;

use crate::config::api_base_url;

fn make_client() -> Client {
    Client::new()
}

/// Try to extract an error message from a non-2xx response body.
async fn extract_error(response: reqwest::Response) -> String {
    let status = response.status();
    match response.json::<Value>().await {
        Ok(body) => {
            if let Some(err) = body.get("error").and_then(|v| v.as_str()) {
                err.to_owned()
            } else {
                format!("Request failed ({status})")
            }
        }
        Err(_) => format!("Request failed ({status})"),
    }
}

/// Execute a GET request to the REST API.
pub async fn api_get<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T, String> {
    let url = format!("{}{}", api_base_url(), path);
    let client = make_client();

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("API request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(extract_error(response).await);
    }

    response
        .json()
        .await
        .map_err(|e| format!("Failed to parse API response: {e}"))
}

/// Execute a POST request to the REST API.
pub async fn api_post<T: for<'de> Deserialize<'de>>(path: &str, body: Value) -> Result<T, String> {
    let url = format!("{}{}", api_base_url(), path);
    let client = make_client();

    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("API request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(extract_error(response).await);
    }

    response
        .json()
        .await
        .map_err(|e| format!("Failed to parse API response: {e}"))
}

/// Execute a PUT request to the REST API.
pub async fn api_put<T: for<'de> Deserialize<'de>>(path: &str, body: Value) -> Result<T, String> {
    let url = format!("{}{}", api_base_url(), path);
    let client = make_client();

    let response = client
        .put(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("API request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(extract_error(response).await);
    }

    response
        .json()
        .await
        .map_err(|e| format!("Failed to parse API response: {e}"))
}

/// Execute a PATCH request to the REST API.
pub async fn api_patch<T: for<'de> Deserialize<'de>>(path: &str, body: Value) -> Result<T, String> {
    let url = format!("{}{}", api_base_url(), path);
    let client = make_client();

    let response = client
        .patch(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("API request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(extract_error(response).await);
    }

    response
        .json()
        .await
        .map_err(|e| format!("Failed to parse API response: {e}"))
}

/// Execute a DELETE request to the REST API.
pub async fn api_delete<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T, String> {
    let url = format!("{}{}", api_base_url(), path);
    let client = make_client();

    let response = client
        .delete(&url)
        .send()
        .await
        .map_err(|e| format!("API request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(extract_error(response).await);
    }

    response
        .json()
        .await
        .map_err(|e| format!("Failed to parse API response: {e}"))
}

/// Execute a DELETE request with a JSON body.
pub async fn api_delete_with_body<T: for<'de> Deserialize<'de>>(
    path: &str,
    body: Value,
) -> Result<T, String> {
    let url = format!("{}{}", api_base_url(), path);
    let client = make_client();

    let response = client
        .delete(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("API request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(extract_error(response).await);
    }

    response
        .json()
        .await
        .map_err(|e| format!("Failed to parse API response: {e}"))
}

use salvo::prelude::*;
use serde::Serialize;

use super::{
    DepotExt, RouteError, extract_bound_activity_tracker, extract_session_info, get_requester,
    make_clock,
};
use crate::storage;

// ── POST /api/v1/viewer/avatar ────────────────────────────────

const MAX_AVATAR_SIZE: usize = 5 * 1024 * 1024; // 5 MB

#[derive(Serialize, salvo::oapi::ToSchema)]
pub struct UploadAvatarResponse {
    pub avatar_url: String,
}

#[endpoint]
pub async fn upload_avatar(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<UploadAvatarResponse>, RouteError> {
    let repo_factory = depot.repo_factory()?;
    let principal_server = depot.principal_server()?;
    let url_builder = depot.url_builder()?;
    let clock = make_clock();

    let activity_tracker = extract_bound_activity_tracker(req, depot);
    let session_info = extract_session_info(req, depot);

    // Salvo's default secure body size limit is 64 KB, which silently
    // truncates any real avatar upload. Bump it to match the 5 MB cap we
    // enforce on the client.
    req.set_secure_max_size(5 * 1024 * 1024);

    // Parse multipart form first (before consuming the request body for session)
    let file = req
        .file("avatar")
        .await
        .ok_or_else(|| RouteError::BadRequest("missing 'avatar' file field".into()))?;

    let content_type = file
        .content_type()
        .map(|s| s.to_string())
        .unwrap_or_default();

    // Validate content type
    if !matches!(
        content_type.as_str(),
        "image/png" | "image/jpeg" | "image/gif" | "image/webp"
    ) {
        return Err(RouteError::BadRequest(
            "avatar must be an image (png, jpeg, gif, or webp)".into(),
        ));
    }

    let data = tokio::fs::read(file.path())
        .await
        .map_err(|e| RouteError::Internal(Box::new(e)))?;

    // Validate size
    if data.len() > MAX_AVATAR_SIZE {
        return Err(RouteError::BadRequest(format!(
            "avatar file too large (max {} MB)",
            MAX_AVATAR_SIZE / 1024 / 1024
        )));
    }

    let repo = repo_factory.create().await?;
    let (requester, mut repo) =
        get_requester(&clock, &activity_tracker, repo, &session_info).await?;

    let user = requester.user().ok_or(RouteError::Unauthorized)?;
    let user_id = user.id;

    // Determine extension from content type
    let ext = match content_type.as_str() {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        _ => "bin",
    };

    let key = format!("{}.{ext}", storage::avatar_key(&user_id.to_string()));

    // Delete old avatar if exists (different extension)
    for old_ext in &["png", "jpg", "gif", "webp"] {
        let old_key = format!("{}.{old_ext}", storage::avatar_key(&user_id.to_string()));
        if old_key != key {
            let _ = storage::delete(&old_key).await;
        }
    }

    // Write to storage
    storage::write(&key, &data)
        .await
        .map_err(|e| RouteError::Internal(e.into()))?;

    // Build the avatar URL
    let base = url_builder.http_base();
    let avatar_url = format!("{}api/v1/viewer/avatar/{}", base.as_str(), user_id);

    // Update user profile with the new avatar URL
    let patch = coauth_data::UserProfilePatch {
        avatar_url: Some(Some(avatar_url.clone())),
        display_name: None,
        preferred_locale: None,
    };

    crate::services::user_profile::patch_viewer_profile(
        &mut repo,
        &requester,
        &clock,
        principal_server.as_ref(),
        patch,
    )
    .await
    .map_err(|e| RouteError::Internal(Box::new(e)))?;

    repo.save().await?;

    Ok(Json(UploadAvatarResponse { avatar_url }))
}

// ── GET /api/v1/viewer/avatar/:user_id ────────────────────────

#[endpoint]
pub async fn get_avatar(req: &mut Request, res: &mut Response) {
    let user_id = req.param::<String>("user_id").unwrap_or_default();

    if user_id.is_empty() {
        res.status_code(StatusCode::BAD_REQUEST);
        return;
    }

    // Try each possible extension
    for ext in &["png", "jpg", "gif", "webp"] {
        let key = format!("{}.{ext}", storage::avatar_key(&user_id));

        // Try presigned redirect first
        if let Ok(Some(url)) = storage::presign_read(&key).await {
            res.render(Redirect::found(url));
            return;
        }

        // Try reading from storage
        if let Ok(data) = storage::read(&key).await {
            let content_type = match *ext {
                "png" => "image/png",
                "jpg" => "image/jpeg",
                "gif" => "image/gif",
                "webp" => "image/webp",
                _ => "application/octet-stream",
            };
            res.headers_mut()
                .insert("content-type", content_type.parse().unwrap());
            res.headers_mut()
                .insert("cache-control", "public, max-age=3600".parse().unwrap());
            res.write_body(data).ok();
            return;
        }
    }

    res.status_code(StatusCode::NOT_FOUND);
}

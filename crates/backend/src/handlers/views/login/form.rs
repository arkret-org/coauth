//! The HTML form payload posted to `POST /login`.

use coauth_templates::{LoginFormField, ToFormState};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct LoginForm {
    pub username: String,
    pub password: String,
}

impl ToFormState for LoginForm {
    type Field = LoginFormField;
}

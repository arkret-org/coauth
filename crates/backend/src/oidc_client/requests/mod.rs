// Copyright 2022-2024 Kevin Commaille.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Methods to interact with OpenID Connect and OAuth2.0 endpoints.

pub mod authorization_code;
pub mod client_credentials;
pub mod discovery;
pub mod jose;
pub mod refresh_token;
pub mod token;
pub mod userinfo;

// Pasion-specific request modules for social login providers.
pub mod dingtalk;
pub mod feishu;
pub mod qq_connect;
pub mod wechat;
pub mod wecom;

//! Analyzer configuration file (`telltale-systemone.config.v1`).

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::pack::{self, LoadedPack};
use crate::provider::{FixtureProvider, HttpProvider, Provider};

pub const CONFIG_SCHEMA: &str = "telltale-systemone.config.v1";
pub const DEFAULT_ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
pub const DEFAULT_DEADLINE_MS: u64 = 20_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: String,
    /// Exact model ID. Aliases such as `jev-latest` move between releases.
    pub model: String,
    #[serde(default)]
    pub allow_model_alias: bool,
    #[serde(default)]
    pub allow_unlisted_model: bool,
    /// Pack paths, relative to the config file.
    pub packs: Vec<PathBuf>,
    pub provider: ProviderConfig,
    #[serde(default)]
    pub default_deadline_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderConfig {
    /// TypeSafe System One or an endpoint with the same request/response shape.
    Typesafe {
        #[serde(default = "default_endpoint")]
        endpoint: String,
        #[serde(default = "default_key_env")]
        api_key_env: String,
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
        #[serde(default = "default_attempts")]
        max_attempts: u32,
    },
    /// Recorded or synthetic answers; never sends anything.
    Fixture { path: PathBuf },
}

fn default_endpoint() -> String {
    DEFAULT_ENDPOINT.into()
}
fn default_key_env() -> String {
    "TYPESAFE_API_KEY".into()
}
fn default_timeout_ms() -> u64 {
    10_000
}
fn default_attempts() -> u32 {
    3
}

pub struct Loaded {
    pub model: String,
    pub pinned_model: bool,
    pub packs: Vec<LoadedPack>,
    pub provider: Box<dyn Provider>,
    pub deadline: Duration,
}

pub fn is_model_alias(model: &str) -> bool {
    model.ends_with("-latest") || model.ends_with("-preview")
}

pub fn load(path: &Path) -> Result<Loaded, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read config: {e}"))?;
    let config: Config = serde_yaml::from_str(&text).map_err(|e| format!("invalid config: {e}"))?;
    if config.schema != CONFIG_SCHEMA {
        return Err(format!("config schema must be {CONFIG_SCHEMA}"));
    }
    let alias = is_model_alias(&config.model);
    if alias && !config.allow_model_alias {
        return Err(format!(
            "model `{}` is an alias; pin an exact ID or set allow_model_alias: true",
            config.model
        ));
    }
    let base = path.parent().unwrap_or(Path::new("."));
    if config.packs.is_empty() {
        return Err("config lists no packs".into());
    }
    let mut packs = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    for relative in &config.packs {
        let loaded = pack::load_file(&base.join(relative)).map_err(|errors| {
            errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        })?;
        if !loaded.pack.models.contains(&config.model) && !config.allow_unlisted_model {
            return Err(format!(
                "pack `{}` does not list model `{}`; set allow_unlisted_model: true to run it anyway",
                loaded.pack.id, config.model
            ));
        }
        for check in &loaded.pack.checks {
            if !ids.insert(check.id.clone()) {
                return Err(format!(
                    "check `{}` is declared by more than one pack",
                    check.id
                ));
            }
        }
        packs.push(loaded);
    }
    let provider: Box<dyn Provider> = match &config.provider {
        ProviderConfig::Typesafe {
            endpoint,
            api_key_env,
            timeout_ms,
            max_attempts,
        } => {
            let key = std::env::var(api_key_env).unwrap_or_default();
            Box::new(
                HttpProvider::new(
                    endpoint,
                    key,
                    Duration::from_millis(*timeout_ms),
                    *max_attempts,
                )
                .map_err(|code| format!("provider: {code}"))?,
            )
        }
        ProviderConfig::Fixture { path: fixture } => {
            Box::new(FixtureProvider::load(&base.join(fixture))?)
        }
    };
    Ok(Loaded {
        model: config.model,
        pinned_model: !alias,
        packs,
        provider,
        deadline: Duration::from_millis(config.default_deadline_ms.unwrap_or(DEFAULT_DEADLINE_MS)),
    })
}

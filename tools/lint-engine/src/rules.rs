//! The rule data (`rules.toml`): layers, exceptions, allowlists and banned names.

use std::collections::BTreeMap;

use serde::Deserialize;

/// The rules this build of the tool ships with.
pub const DEFAULT: &str = include_str!("../rules.toml");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    schema: u32,
    pub layer: Vec<Layer>,
    #[serde(default)]
    pub exception: Vec<Exception>,
    pub engine: Engine,
    pub source: Source,
    pub deadline_clock: DeadlineClock,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer {
    pub index: u32,
    pub crates: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    pub from: String,
    pub to: String,
    pub reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Engine {
    pub allow: BTreeMap<String, Vec<String>>,
    pub allow_dev: BTreeMap<String, Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub banned_crates: Vec<String>,
    pub banned_paths: Vec<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeadlineClock {
    pub allowed_in: Vec<String>,
}

impl Rules {
    pub fn parse(text: &str) -> Result<Rules, String> {
        let rules: Rules = toml::from_str(text).map_err(|e| e.to_string())?;
        if rules.schema != 1 {
            return Err(format!("unsupported schema {} (only 1)", rules.schema));
        }
        let mut seen = BTreeMap::new();
        for l in &rules.layer {
            for c in &l.crates {
                if let Some(prev) = seen.insert(c.as_str(), l.index) {
                    return Err(format!("`{c}` is in layer {prev} and layer {}", l.index));
                }
            }
        }
        Ok(rules)
    }

    pub fn layer_of(&self, krate: &str) -> Option<u32> {
        self.layer
            .iter()
            .find(|l| l.crates.iter().any(|c| c == krate))
            .map(|l| l.index)
    }
}

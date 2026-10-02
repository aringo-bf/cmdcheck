use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub ollama_url: String,
    pub model: String,
    pub timeout_ms: u64,
    pub keep_alive: String,
    pub on_error: String,
    pub on_pass: String,
    pub special_instructions_deny_threshold: f64,
    pub script_inspection: ScriptInspectionConfig,
    pub harm: HarmConfig,
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub exceptions: Vec<ExceptionConfig>,
    #[serde(default)]
    pub special_instructions: Vec<String>,
    #[serde(default)]
    pub custom_questions: Vec<CustomQuestion>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScriptInspectionConfig {
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
    pub max_depth: usize,
    pub max_scripts: usize,
    pub on_truncated: String,
    pub on_unreadable: String,
    pub on_dynamic_child: String,
    pub on_limit: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HarmConfig {
    pub enabled: bool,
    pub deny_threshold: f64,
    pub instructions: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub enabled: bool,
    pub required_proxy: String,
    pub network_threshold: f64,
    pub compliance_threshold: f64,
    pub instructions: String,
    #[serde(default)]
    pub trusted_prefixes: Vec<String>,
    pub preflight: PreflightConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreflightConfig {
    pub enabled: bool,
    pub proxy_url: String,
    pub check_url: String,
    pub timeout_ms: u64,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExceptionConfig {
    pub action: String,
    #[serde(rename = "match")]
    pub match_kind: String,
    pub pattern: String,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CustomQuestion {
    pub name: String,
    pub instructions: String,
    pub deny_threshold: f64,
    pub deny_reason: String,
}

pub fn embedded() -> Config {
    serde_json::from_str(include_str!(concat!(env!("OUT_DIR"), "/config.json")))
        .expect("build-generated configuration must be valid")
}

#[derive(Debug, Default)]
pub struct Overrides {
    pub harm: Option<bool>,
    pub proxy: Option<bool>,
    pub preflight: Option<bool>,
    pub explain: bool,
}

impl Config {
    pub fn apply(&mut self, overrides: &Overrides) {
        if let Some(value) = overrides.harm {
            self.harm.enabled = value;
        }
        if let Some(value) = overrides.proxy {
            self.proxy.enabled = value;
        }
        if let Some(value) = overrides.preflight {
            self.proxy.preflight.enabled = value;
        }
    }
}

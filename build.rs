use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, env, fs, path::PathBuf};

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    ollama_url: String,
    model: String,
    timeout_ms: u64,
    keep_alive: String,
    on_error: String,
    on_pass: String,
    special_instructions_deny_threshold: f64,
    script_inspection: ScriptInspectionConfig,
    harm: HarmConfig,
    proxy: ProxyConfig,
    #[serde(default)]
    exceptions: Vec<ExceptionConfig>,
    #[serde(default)]
    special_instructions: Vec<String>,
    #[serde(default)]
    custom_questions: Vec<CustomQuestion>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScriptInspectionConfig {
    max_file_bytes: usize,
    max_total_bytes: usize,
    max_depth: usize,
    max_scripts: usize,
    on_truncated: String,
    on_unreadable: String,
    on_dynamic_child: String,
    on_limit: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct HarmConfig {
    enabled: bool,
    deny_threshold: f64,
    instructions: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProxyConfig {
    enabled: bool,
    required_proxy: String,
    network_threshold: f64,
    compliance_threshold: f64,
    instructions: String,
    #[serde(default)]
    trusted_prefixes: Vec<String>,
    preflight: PreflightConfig,
}

#[derive(Debug, Serialize, Deserialize)]
struct PreflightConfig {
    enabled: bool,
    proxy_url: String,
    check_url: String,
    timeout_ms: u64,
    ttl_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExceptionConfig {
    action: String,
    #[serde(rename = "match")]
    match_kind: String,
    pattern: String,
    reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CustomQuestion {
    name: String,
    instructions: String,
    deny_threshold: f64,
    deny_reason: String,
}

fn probability(name: &str, value: f64) {
    assert!(
        (0.0..=1.0).contains(&value),
        "{name} must be between 0 and 1"
    );
}

fn main() {
    println!("cargo:rerun-if-changed=cmdcheck.toml");
    let raw = fs::read_to_string("cmdcheck.toml").expect("failed to read cmdcheck.toml");
    let config: Config = toml::from_str(&raw).expect("invalid cmdcheck.toml");

    assert!(
        !config.ollama_url.trim().is_empty(),
        "ollama_url cannot be empty"
    );
    assert!(!config.model.trim().is_empty(), "model cannot be empty");
    assert!(
        config.timeout_ms > 0,
        "timeout_ms must be greater than zero"
    );
    assert!(
        config.script_inspection.max_file_bytes > 0,
        "script_inspection.max_file_bytes must be greater than zero"
    );
    assert!(
        config.script_inspection.max_total_bytes > 0,
        "script_inspection.max_total_bytes must be greater than zero"
    );
    assert!(
        config.script_inspection.max_scripts > 0,
        "script_inspection.max_scripts must be greater than zero"
    );
    assert!(
        config.script_inspection.max_total_bytes >= config.script_inspection.max_file_bytes,
        "script_inspection.max_total_bytes must be at least max_file_bytes"
    );
    for (name, action) in [
        ("on_truncated", &config.script_inspection.on_truncated),
        ("on_unreadable", &config.script_inspection.on_unreadable),
        (
            "on_dynamic_child",
            &config.script_inspection.on_dynamic_child,
        ),
        ("on_limit", &config.script_inspection.on_limit),
    ] {
        assert!(
            ["allow", "ask", "deny"].contains(&action.as_str()),
            "script_inspection.{name} must be allow, ask, or deny"
        );
    }
    assert!(
        ["allow", "ask", "deny"].contains(&config.on_error.as_str()),
        "on_error must be allow, ask, or deny"
    );
    assert!(
        ["allow", "ask"].contains(&config.on_pass.as_str()),
        "on_pass must be allow or ask"
    );
    probability("harm.deny_threshold", config.harm.deny_threshold);
    probability(
        "special_instructions_deny_threshold",
        config.special_instructions_deny_threshold,
    );
    probability("proxy.network_threshold", config.proxy.network_threshold);
    probability(
        "proxy.compliance_threshold",
        config.proxy.compliance_threshold,
    );
    if config.proxy.enabled {
        assert!(
            !config.proxy.required_proxy.trim().is_empty(),
            "proxy.required_proxy cannot be empty when proxy enforcement is enabled"
        );
    }

    if config.proxy.preflight.enabled {
        assert!(
            !config.proxy.preflight.proxy_url.trim().is_empty(),
            "proxy.preflight.proxy_url is required"
        );
        assert!(
            !config.proxy.preflight.check_url.trim().is_empty(),
            "proxy.preflight.check_url is required"
        );
        assert!(
            config.proxy.preflight.timeout_ms > 0,
            "proxy.preflight.timeout_ms must be greater than zero"
        );
    }

    for rule in &config.exceptions {
        assert!(
            ["allow", "deny"].contains(&rule.action.as_str()),
            "exception action must be allow or deny"
        );
        assert!(
            ["prefix", "regex"].contains(&rule.match_kind.as_str()),
            "exception match must be prefix or regex"
        );
        assert!(
            !rule.pattern.is_empty(),
            "exception pattern cannot be empty"
        );
        if rule.match_kind == "regex" {
            Regex::new(&rule.pattern).unwrap_or_else(|error| {
                panic!("invalid exception regex {:?}: {error}", rule.pattern)
            });
        }
    }

    let reserved = [
        "harm",
        "network",
        "proxy_compliant",
        "special_policy_violation",
    ];
    let mut names = HashSet::new();
    let built_in_questions = usize::from(config.harm.enabled)
        + 2 * usize::from(config.proxy.enabled)
        + usize::from(!config.special_instructions.is_empty());
    assert!(
        built_in_questions + config.custom_questions.len() <= 64,
        "Nimble accepts at most 64 questions per request"
    );
    for question in &config.custom_questions {
        assert!(
            !reserved.contains(&question.name.as_str()),
            "custom question name {:?} is reserved",
            question.name
        );
        assert!(
            question
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "custom question names may contain only letters, digits, and underscores"
        );
        assert!(
            names.insert(&question.name),
            "duplicate custom question name {:?}",
            question.name
        );
        probability(
            &format!("custom question {} deny_threshold", question.name),
            question.deny_threshold,
        );
        assert!(
            !question.instructions.trim().is_empty(),
            "custom question instructions cannot be empty"
        );
    }

    let json = serde_json::to_string(&config).expect("could not serialize embedded config");
    let output =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is unset")).join("config.json");
    fs::write(output, json).expect("could not write embedded config");
}

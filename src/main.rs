mod config;
mod decide;
mod nimble;
mod preflight;
mod rules;
mod script;

use config::{Config, Overrides};
use decide::{Decision, Permission};
use rules::RuleAction;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    env,
    io::{self, Read},
    path::{Path, PathBuf},
    process,
};

#[derive(Debug, Deserialize)]
struct HookInput {
    #[serde(default)]
    tool_name: Option<String>,
    #[serde(default)]
    tool_input: Option<ToolInput>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    cwd: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct ToolInput {
    command: String,
}

struct Invocation {
    command: String,
    cwd: PathBuf,
    is_hook: bool,
}

fn usage() -> &'static str {
    "cmdcheck [OPTIONS] [-- COMMAND...]\n\n\
Reads a Claude Code PreToolUse event from stdin, or checks COMMAND directly.\n\n\
Options:\n  --harm / --no-harm\n  --proxy / --no-proxy\n  --preflight / --no-preflight\n  --explain       Print scores/details to stderr\n  -h, --help\n"
}

fn parse_args() -> Result<(Overrides, Vec<String>), String> {
    let mut overrides = Overrides::default();
    let mut command = Vec::new();
    let mut positional = false;
    for arg in env::args().skip(1) {
        if positional {
            command.push(arg);
            continue;
        }
        match arg.as_str() {
            "--" => positional = true,
            "--harm" => overrides.harm = Some(true),
            "--no-harm" => overrides.harm = Some(false),
            "--proxy" => overrides.proxy = Some(true),
            "--no-proxy" => overrides.proxy = Some(false),
            "--preflight" => overrides.preflight = Some(true),
            "--no-preflight" => overrides.preflight = Some(false),
            "--explain" => overrides.explain = true,
            "-h" | "--help" => {
                print!("{}", usage());
                process::exit(0);
            }
            _ if arg.starts_with('-') => return Err(format!("unknown option {arg:?}")),
            _ => {
                positional = true;
                command.push(arg);
            }
        }
    }
    Ok((overrides, command))
}

fn invocation(command_args: Vec<String>) -> Result<Invocation, String> {
    if !command_args.is_empty() {
        return Ok(Invocation {
            command: command_args.join(" "),
            cwd: env::current_dir().map_err(|e| e.to_string())?,
            is_hook: false,
        });
    }
    let mut stdin = String::new();
    io::stdin()
        .read_to_string(&mut stdin)
        .map_err(|error| format!("could not read stdin: {error}"))?;
    if stdin.trim().is_empty() {
        return Err("expected a PreToolUse JSON event on stdin or a command after --".into());
    }
    match serde_json::from_str::<HookInput>(&stdin) {
        Ok(input) => {
            if let Some(name) = &input.tool_name {
                if !name.eq_ignore_ascii_case("bash") {
                    return Ok(Invocation {
                        command: String::new(),
                        cwd: input
                            .cwd
                            .unwrap_or(env::current_dir().map_err(|e| e.to_string())?),
                        is_hook: true,
                    });
                }
            }
            let command = input
                .tool_input
                .map(|tool| tool.command)
                .or(input.command)
                .ok_or_else(|| {
                    "JSON input contains no tool_input.command or command".to_string()
                })?;
            Ok(Invocation {
                command,
                cwd: input
                    .cwd
                    .unwrap_or(env::current_dir().map_err(|e| e.to_string())?),
                is_hook: true,
            })
        }
        Err(_) => Ok(Invocation {
            command: stdin.trim_end().into(),
            cwd: env::current_dir().map_err(|e| e.to_string())?,
            is_hook: false,
        }),
    }
}

fn state(
    config: &Config,
    command: &str,
    cwd: &Path,
    sources: &[script::ScriptSource],
    trusted_proxy: bool,
) -> Value {
    let scripts: Vec<_> = sources
        .iter()
        .map(|source| {
            json!({
                "path": source.path,
                "contents": source.contents,
                "truncated": source.truncated,
            })
        })
        .collect();
    json!({
        "command": command,
        "working_directory": cwd,
        "scripts": scripts,
        "special_instructions": config.special_instructions,
        "proxy_policy": if config.proxy.enabled { Some(json!({
            "required_proxy": config.proxy.required_proxy,
            "instructions": config.proxy.instructions,
            "trusted_prefixes": config.proxy.trusted_prefixes,
        })) } else { None },
        "trusted_proxy_prefix_matched": trusted_proxy,
    })
}

fn check(config: &Config, invocation: &Invocation, explain: bool) -> Decision {
    if invocation.command.is_empty() {
        return Decision {
            permission: Permission::Allow,
            reason: "Hook does not target the Bash tool".into(),
            network: false,
        };
    }
    if let Some((action, reason)) =
        rules::matching_exception(&invocation.command, &config.exceptions)
    {
        return Decision {
            permission: if action == RuleAction::Allow {
                Permission::Allow
            } else {
                Permission::Deny
            },
            reason: format!("Exception rule: {reason}"),
            network: false,
        };
    }
    let inspection = script::inspect(
        &invocation.command,
        &invocation.cwd,
        &config.script_inspection,
    );
    if let Some(issue) = inspection.issue {
        let (rule, action) = match issue.kind {
            script::IssueKind::Truncated => (
                "on_truncated",
                config.script_inspection.on_truncated.as_str(),
            ),
            script::IssueKind::Unreadable => (
                "on_unreadable",
                config.script_inspection.on_unreadable.as_str(),
            ),
            script::IssueKind::DynamicChild => (
                "on_dynamic_child",
                config.script_inspection.on_dynamic_child.as_str(),
            ),
            script::IssueKind::Limit => ("on_limit", config.script_inspection.on_limit.as_str()),
        };
        return Decision {
            permission: Permission::from_config(action),
            reason: format!(
                "Rule matched: script_inspection.{rule} = {action:?}: {}",
                issue.detail
            ),
            network: false,
        };
    }
    let sources = inspection.sources;
    let trusted_proxy =
        rules::has_trusted_proxy_prefix(&invocation.command, &config.proxy.trusted_prefixes);
    let scores = match nimble::evaluate(
        config,
        state(
            config,
            &invocation.command,
            &invocation.cwd,
            &sources,
            trusted_proxy,
        ),
    ) {
        Ok(scores) => scores,
        Err(error) => {
            return Decision {
                permission: Permission::from_config(&config.on_error),
                reason: error,
                network: false,
            }
        }
    };
    let decision = match decide::from_scores(config, &scores) {
        Ok(decision) => decision,
        Err(error) => {
            return Decision {
                permission: Permission::from_config(&config.on_error),
                reason: error,
                network: false,
            }
        }
    };
    if explain {
        eprintln!("cmdcheck: {scores:?}");
    }
    if decision.network {
        if let Err(error) = preflight::ensure(&config.proxy.preflight) {
            return Decision {
                permission: Permission::from_config(&config.on_error),
                reason: error,
                network: true,
            };
        }
    }
    decision
}

fn emit(decision: Decision, is_hook: bool) {
    if is_hook {
        println!(
            "{}",
            json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": decision.permission.as_str(),
                    "permissionDecisionReason": decision.reason,
                }
            })
        );
    } else {
        println!(
            "{}: {}",
            decision.permission.as_str().to_uppercase(),
            decision.reason
        );
    }
}

fn main() {
    let (overrides, command_args) = match parse_args() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("cmdcheck: {error}\n\n{}", usage());
            process::exit(2);
        }
    };
    let invocation = match invocation(command_args) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("cmdcheck: {error}");
            process::exit(2);
        }
    };
    let mut config = config::embedded();
    config.apply(&overrides);
    emit(
        check(&config, &invocation, overrides.explain),
        invocation.is_hook,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_allow_exception_approves_before_script_inspection() {
        let mut config = config::embedded();
        config.exceptions.insert(
            0,
            config::ExceptionConfig {
                action: "allow".into(),
                match_kind: "prefix".into(),
                pattern: "trusted-run ".into(),
                reason: "Trusted wrapper".into(),
            },
        );
        let invocation = Invocation {
            command: "trusted-run bash \"$DYNAMIC_SCRIPT\"".into(),
            cwd: env::current_dir().unwrap(),
            is_hook: false,
        };

        let decision = check(&config, &invocation, false);

        assert_eq!(decision.permission, Permission::Allow);
        assert_eq!(decision.reason, "Exception rule: Trusted wrapper");
    }
}

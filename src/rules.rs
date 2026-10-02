use crate::config::ExceptionConfig;
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Deny,
}

pub fn matching_exception<'a>(
    command: &str,
    rules: &'a [ExceptionConfig],
) -> Option<(RuleAction, &'a str)> {
    let command = command.trim_start();
    rules.iter().find_map(|rule| {
        let matches = match rule.match_kind.as_str() {
            "prefix" => command.starts_with(&rule.pattern),
            "regex" => Regex::new(&rule.pattern)
                .expect("regex was checked at build time")
                .is_match(command),
            _ => false,
        };
        matches.then(|| {
            let action = if rule.action == "allow" {
                RuleAction::Allow
            } else {
                RuleAction::Deny
            };
            (action, rule.reason.as_str())
        })
    })
}

pub fn has_trusted_proxy_prefix(command: &str, prefixes: &[String]) -> bool {
    let command = command.trim_start();
    prefixes.iter().any(|prefix| command.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(action: &str, match_kind: &str, pattern: &str) -> ExceptionConfig {
        ExceptionConfig {
            action: action.into(),
            match_kind: match_kind.into(),
            pattern: pattern.into(),
            reason: "test".into(),
        }
    }

    #[test]
    fn first_matching_rule_wins() {
        let rules = [
            rule("deny", "regex", "curl"),
            rule("allow", "prefix", "curl"),
        ];
        assert_eq!(
            matching_exception("curl example.com", &rules).unwrap().0,
            RuleAction::Deny
        );
    }

    #[test]
    fn first_allow_rule_approves_before_later_deny() {
        let rules = [
            rule("allow", "prefix", "trusted-run "),
            rule("deny", "regex", ".*"),
        ];
        assert_eq!(
            matching_exception("trusted-run ./large.sh", &rules)
                .unwrap()
                .0,
            RuleAction::Allow
        );
    }

    #[test]
    fn prefix_is_anchored_after_whitespace() {
        let rules = [rule("allow", "prefix", "cargo test")];
        assert!(matching_exception("  cargo test --all", &rules).is_some());
        assert!(matching_exception("echo cargo test", &rules).is_none());
    }
}

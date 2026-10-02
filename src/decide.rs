use crate::{config::Config, nimble::Scores};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    Allow,
    Ask,
    Deny,
}

impl Permission {
    pub fn from_config(value: &str) -> Self {
        match value {
            "allow" => Self::Allow,
            "deny" => Self::Deny,
            _ => Self::Ask,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug)]
pub struct Decision {
    pub permission: Permission,
    pub reason: String,
    pub network: bool,
}

pub fn from_scores(config: &Config, scores: &Scores) -> Result<Decision, String> {
    if config.harm.enabled {
        let score = scores.get("harm")?;
        if score >= config.harm.deny_threshold {
            return Ok(Decision {
                permission: Permission::Deny,
                reason: format!(
                    "Harm check failed ({:.1}% >= {:.1}%)",
                    score * 100.0,
                    config.harm.deny_threshold * 100.0
                ),
                network: false,
            });
        }
    }

    let mut network = false;
    if config.proxy.enabled {
        let network_score = scores.get("network")?;
        network = network_score >= config.proxy.network_threshold;
        if network {
            let compliance = scores.get("proxy_compliant")?;
            if compliance < config.proxy.compliance_threshold {
                return Ok(Decision {
                    permission: Permission::Deny,
                    reason: format!(
                        "Rule matched: required_proxy = {:?}",
                        config.proxy.required_proxy
                    ),
                    network,
                });
            }
        }
    }

    if !config.special_instructions.is_empty() {
        let score = scores.get("special_policy_violation")?;
        if score >= config.special_instructions_deny_threshold {
            return Ok(Decision {
                permission: Permission::Deny,
                reason: format!(
                    "Special instructions check failed ({:.1}% >= {:.1}%)",
                    score * 100.0,
                    config.special_instructions_deny_threshold * 100.0
                ),
                network,
            });
        }
    }

    for question in &config.custom_questions {
        let score = scores.get(&question.name)?;
        if score >= question.deny_threshold {
            return Ok(Decision {
                permission: Permission::Deny,
                reason: format!(
                    "{} ({:.1}% probability)",
                    question.deny_reason,
                    score * 100.0
                ),
                network,
            });
        }
    }

    Ok(Decision {
        permission: Permission::from_config(&config.on_pass),
        reason: "Command passed configured checks".into(),
        network,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_harm_at_threshold() {
        let config = crate::config::embedded();
        let scores = Scores::from_values([("harm", config.harm.deny_threshold)]);
        assert_eq!(
            from_scores(&config, &scores).unwrap().permission,
            Permission::Deny
        );
    }

    #[test]
    fn proxy_requires_compliance_only_for_network_commands() {
        let mut config = crate::config::embedded();
        config.harm.enabled = false;
        config.proxy.enabled = true;
        let local = Scores::from_values([("network", 0.1), ("proxy_compliant", 0.0)]);
        let network = Scores::from_values([("network", 0.9), ("proxy_compliant", 0.1)]);
        assert_eq!(
            from_scores(&config, &local).unwrap().permission,
            Permission::Allow
        );
        assert_eq!(
            from_scores(&config, &network).unwrap().permission,
            Permission::Deny
        );
        assert_eq!(
            from_scores(&config, &network).unwrap().reason,
            format!(
                "Rule matched: required_proxy = {:?}",
                config.proxy.required_proxy
            )
        );
    }

    #[test]
    fn special_instructions_are_an_independent_gate() {
        let mut config = crate::config::embedded();
        config.harm.enabled = false;
        config.proxy.enabled = false;
        config.special_instructions = vec!["Commands must start with safe-run".into()];
        let scores = Scores::from_values([("special_policy_violation", 0.95)]);
        assert_eq!(
            from_scores(&config, &scores).unwrap().permission,
            Permission::Deny
        );
    }
}

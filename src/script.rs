use crate::config::ScriptInspectionConfig;
use std::{
    collections::{HashSet, VecDeque},
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub struct ScriptSource {
    pub path: PathBuf,
    pub contents: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueKind {
    Truncated,
    Unreadable,
    DynamicChild,
    Limit,
}

#[derive(Debug)]
pub struct InspectionIssue {
    pub kind: IssueKind,
    pub detail: String,
}

#[derive(Debug)]
pub struct Inspection {
    pub sources: Vec<ScriptSource>,
    pub issue: Option<InspectionIssue>,
}

#[derive(Debug, PartialEq, Eq)]
enum Candidate {
    Static(String),
    Dynamic(String),
}

/// A conservative shell tokenizer. It handles ordinary quotes and escapes
/// without evaluating expansions or executing any portion of the input.
fn words(command: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escape = false;
    for ch in command.chars() {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }
        if ch == '\\' && quote != Some('\'') {
            escape = true;
            continue;
        }
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            ' ' | '\t' | '\r' | '\n' => {
                if !current.is_empty() {
                    result.push(std::mem::take(&mut current));
                }
            }
            ';' | '|' | '&' => {
                if !current.is_empty() {
                    result.push(std::mem::take(&mut current));
                }
                result.push(ch.to_string());
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        result.push(current);
    }
    result
}

fn is_dynamic(value: &str) -> bool {
    value.contains('$') || value.contains('`')
}

fn candidate(value: &str) -> Candidate {
    if is_dynamic(value) {
        Candidate::Dynamic(value.to_string())
    } else {
        Candidate::Static(value.to_string())
    }
}

fn looks_like_script(value: &str) -> bool {
    [".sh", ".py", ".rb", ".pl", ".js"]
        .iter()
        .any(|extension| value.ends_with(extension))
        || value.starts_with("./")
        || value.starts_with("../")
}

fn script_candidates(command: &str) -> Vec<Candidate> {
    // A shebang or full-line comment is metadata, not an invocation.
    let executable_lines = command
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let words = words(&executable_lines);
    let interpreters = [
        "sh", "bash", "zsh", "dash", "python", "python3", "ruby", "perl", "node",
    ];
    let mut candidates = Vec::new();
    let mut i = 0;
    while i < words.len() {
        let word = &words[i];
        if [";", "|", "&"].contains(&word.as_str()) {
            i += 1;
            continue;
        }
        let program = Path::new(word)
            .file_name()
            .map(|name| name.to_string_lossy());
        if program
            .as_deref()
            .is_some_and(|name| interpreters.contains(&name))
        {
            i += 1;
            let mut inline = false;
            while i < words.len() && words[i].starts_with('-') {
                if words[i] == "-c" || words[i] == "-e" {
                    inline = true;
                    if let Some(body) = words.get(i + 1) {
                        if is_dynamic(body) {
                            candidates.push(Candidate::Dynamic(body.clone()));
                        }
                    }
                    i += 2;
                    break;
                }
                i += 1;
            }
            if !inline {
                if let Some(value) = words.get(i) {
                    if ![";", "|", "&"].contains(&value.as_str()) {
                        candidates.push(candidate(value));
                    }
                }
                i += 1;
            }
            continue;
        }
        if word == "source" || word == "." {
            if let Some(value) = words.get(i + 1) {
                candidates.push(candidate(value));
            }
            i += 2;
            continue;
        }
        if looks_like_script(word) {
            candidates.push(candidate(word));
        }
        i += 1;
    }
    candidates
}

fn issue(kind: IssueKind, detail: impl Into<String>, sources: Vec<ScriptSource>) -> Inspection {
    Inspection {
        sources,
        issue: Some(InspectionIssue {
            kind,
            detail: detail.into(),
        }),
    }
}

pub fn inspect(command: &str, cwd: &Path, config: &ScriptInspectionConfig) -> Inspection {
    let mut queue: VecDeque<_> = script_candidates(command)
        .into_iter()
        .map(|candidate| (candidate, cwd.to_path_buf(), 0_usize))
        .collect();
    let mut sources = Vec::new();
    let mut seen = HashSet::new();
    let mut total_bytes = 0_usize;

    while let Some((candidate, base, depth)) = queue.pop_front() {
        let value = match candidate {
            Candidate::Dynamic(value) => {
                return issue(
                    IssueKind::DynamicChild,
                    format!("dynamic script or command path cannot be inspected: {value}"),
                    sources,
                );
            }
            Candidate::Static(value) => value,
        };
        if depth > config.max_depth {
            return issue(
                IssueKind::Limit,
                format!("script recursion exceeds max_depth = {}", config.max_depth),
                sources,
            );
        }
        let candidate_path = PathBuf::from(&value);
        let path = if candidate_path.is_absolute() {
            candidate_path
        } else {
            base.join(candidate_path)
        };
        let canonical = match fs::canonicalize(&path) {
            Ok(path) => path,
            Err(error) => {
                return issue(
                    IssueKind::Unreadable,
                    format!("could not resolve script {}: {error}", path.display()),
                    sources,
                );
            }
        };
        if !seen.insert(canonical.clone()) {
            continue;
        }
        if sources.len() >= config.max_scripts {
            return issue(
                IssueKind::Limit,
                format!("script count exceeds max_scripts = {}", config.max_scripts),
                sources,
            );
        }
        let bytes = match fs::read(&canonical) {
            Ok(bytes) => bytes,
            Err(error) => {
                return issue(
                    IssueKind::Unreadable,
                    format!("could not read script {}: {error}", canonical.display()),
                    sources,
                );
            }
        };
        // Extensionless local executables are scripts only when they have a shebang.
        if !looks_like_script(&value) && !bytes.starts_with(b"#!") {
            continue;
        }
        let remaining = config.max_total_bytes.saturating_sub(total_bytes);
        let included = bytes.len().min(config.max_file_bytes).min(remaining);
        let truncated = included < bytes.len();
        let contents = String::from_utf8_lossy(&bytes[..included]).into_owned();
        total_bytes += included;
        let parent = canonical.parent().unwrap_or(&base).to_path_buf();
        sources.push(ScriptSource {
            path: canonical.clone(),
            contents: contents.clone(),
            truncated,
        });
        if bytes.len() > config.max_file_bytes {
            return issue(
                IssueKind::Truncated,
                format!(
                    "script {} exceeds max_file_bytes = {}",
                    canonical.display(),
                    config.max_file_bytes
                ),
                sources,
            );
        }
        if bytes.len() > remaining {
            return issue(
                IssueKind::Limit,
                format!(
                    "script content exceeds max_total_bytes = {}",
                    config.max_total_bytes
                ),
                sources,
            );
        }
        for child in script_candidates(&contents) {
            queue.push_back((child, parent.clone(), depth + 1));
        }
    }
    Inspection {
        sources,
        issue: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "cmdcheck-script-test-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn recognizes_static_and_dynamic_children() {
        assert_eq!(
            script_candidates("python3 -u 'some file.py'; source $NEXT"),
            vec![
                Candidate::Static("some file.py".into()),
                Candidate::Dynamic("$NEXT".into())
            ]
        );
    }

    #[test]
    fn ignores_literal_inline_program_but_finds_later_script() {
        assert_eq!(
            script_candidates("bash -c 'echo ok'; python later.py"),
            vec![Candidate::Static("later.py".into())]
        );
    }

    #[test]
    fn detects_dynamic_inline_program() {
        assert_eq!(
            script_candidates("bash -c \"$COMMAND\""),
            vec![Candidate::Dynamic("$COMMAND".into())]
        );
    }

    #[test]
    fn finds_multiple_scripts() {
        assert_eq!(
            script_candidates("./one.sh && node two.js"),
            vec![
                Candidate::Static("./one.sh".into()),
                Candidate::Static("two.js".into())
            ]
        );
    }

    #[test]
    fn ignores_shebang_before_child_invocation() {
        assert_eq!(
            script_candidates("#!/bin/sh\nsh child.sh\n"),
            vec![Candidate::Static("child.sh".into())]
        );
    }

    #[test]
    fn recursively_loads_relative_children_and_breaks_cycles() {
        let root = temp_dir("recursive");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(root.join("parent.sh"), "sh nested/child.sh\n").unwrap();
        fs::write(nested.join("child.sh"), "sh ../parent.sh\n").unwrap();
        let config = crate::config::embedded().script_inspection;

        let inspection = inspect("sh parent.sh", &root, &config);

        assert!(inspection.issue.is_none());
        assert_eq!(inspection.sources.len(), 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reports_truncation_instead_of_silently_scoring_partial_content() {
        let root = temp_dir("truncated");
        fs::write(
            root.join("large.sh"),
            "echo this is larger than four bytes\n",
        )
        .unwrap();
        let mut config = crate::config::embedded().script_inspection;
        config.max_file_bytes = 4;
        config.max_total_bytes = 8;

        let inspection = inspect("sh large.sh", &root, &config);

        assert_eq!(inspection.issue.unwrap().kind, IssueKind::Truncated);
        fs::remove_dir_all(root).unwrap();
    }
}

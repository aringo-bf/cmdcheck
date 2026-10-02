# cmdcheck

`cmdcheck` is a fast, standalone command-policy gate written in Rust. It sends proposed shell commands to the local [Nimble decision model for Ollama](https://ollama.com/library/nimble) and returns `ALLOW`, `ASK`, or `DENY`.

Use it from a terminal or integrate it with agents, shells, CI systems, and task runners. The policy engine is not tied to a particular hook system.

## Features

- Harm detection with configurable thresholds.
- Required proxy enforcement across ports and protocols.
- Semantic matching instead of exact command-string matching.
- Recursive inspection of shell, Python, Ruby, Perl, and Node scripts.
- Ordered allow/deny exceptions and custom policy questions.
- Build-time policy embedding—no configuration-file read at runtime.
- Optional live proxy preflight with a TTL cache.

## Quick start

Install [Nimble](https://ollama.com/library/nimble), make sure Ollama exposes `/v1/systemone`, and edit [`cmdcheck.toml`](cmdcheck.toml) for your environment. Then build:

```sh
./rebuild
```

Check a command:

```console
$ target/release/cmdcheck curl example.com
DENY: Rule matched: required_proxy = "http://127.0.0.1:8080"

$ target/release/cmdcheck curl example.com --proxy localhost:8080
ALLOW: Command passed configured checks
```

Nimble understands that `localhost:8080` and `127.0.0.1:8080` refer to the same local proxy, as well as variations in option order and command syntax. Use `--explain` to print the underlying model scores to stderr while keeping the decision on stdout clean.

> [!IMPORTANT]
> `cmdcheck` returns a policy decision; it does not execute the proposed command. A hook host normally executes an allowed command. Expand the standalone wrapper below to do the same from a shell.

<details>
<summary><strong>Execute approved commands from a shell</strong></summary>

This wrapper preserves argument boundaries and invokes the command only after `ALLOW`:

```sh
cmdcheck_run() {
  result="$(target/release/cmdcheck -- "$@")"
  printf '%s\n' "$result"

  case "$result" in
    ALLOW:*) command "$@" ;;
    ASK:*)  return 125 ;;
    DENY:*) return 126 ;;
    *)      return 127 ;;
  esac
}
```

```console
$ cmdcheck_run curl example.com --proxy localhost:8080
ALLOW: Command passed configured checks
<curl output follows>
```

`ASK` and `DENY` never invoke the command and return a nonzero status.

</details>

<details>
<summary><strong>CLI options and input modes</strong></summary>

CLI switches override the compiled enable/disable settings:

```text
--harm / --no-harm
--proxy / --no-proxy
--preflight / --no-preflight
--explain
```

Pass the command as arguments:

```sh
target/release/cmdcheck -- curl https://example.com
```

Or as plain text on stdin:

```sh
printf '%s' 'curl https://example.com' | target/release/cmdcheck
```

</details>

<details>
<summary><strong>Example integration: Claude Code</strong></summary>

Claude Code sends a structured `PreToolUse` event on stdin. `cmdcheck` recognizes the event and returns the corresponding hook JSON:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/cmdcheck/target/release/cmdcheck"
          }
        ]
      }
    ]
  }
}
```

Test the adapter directly:

```sh
printf '%s' '{"tool_name":"Bash","tool_input":{"command":"curl https://example.com"}}' \
  | target/release/cmdcheck
```

This is one optional adapter; the core policy engine remains integration-independent.

</details>

<details>
<summary><strong>Policy behavior and script inspection</strong></summary>

The build script validates the policy and embeds it in the binary. Re-run `./rebuild` after changing [`cmdcheck.toml`](cmdcheck.toml).

Evaluation order:

1. Ordered exception rules. The first match wins, so a first-match `allow` approves immediately.
2. Recursive script inspection.
3. Nimble harm, proxy, special-instruction, and custom-question checks in one request.
4. Optional proxy preflight for network commands.

Script inspection follows statically identifiable child scripts, resolves paths relative to the parent, avoids cycles, and applies bounded limits:

```toml
[script_inspection]
max_file_bytes = 262144
max_total_bytes = 524288
max_depth = 4
max_scripts = 16
on_truncated = "ask"
on_unreadable = "ask"
on_dynamic_child = "ask"
on_limit = "ask"
```

Each outcome accepts `allow`, `ask`, or `deny`. Dynamic constructs such as `bash "$SCRIPT_PATH"` cannot be resolved safely before execution and use `on_dynamic_child`.

`on_error` controls Ollama, response, and proxy-preflight failures. `on_pass` controls successful decisions. Denials identify the compiled rule that was enforced.

</details>

## License

[MIT](LICENSE)

# Portcullis Operator and Policy Authoring Guide

Portcullis is a deterministic local tool-call firewall that sits between an autonomous agent and the host machine. A harness passes a `portcullis-policy/1` document and one structured `portcullis-call/1` record, and Portcullis returns one canonical decision record (`allow`, `deny`, `rewrite`, or `escalate`) and appends that record to a line-validated JSON Lines audit log before the decision counts as delivered.

## 1. Fixed evaluation order

Unparseable JSON or JSON carrying duplicate keys at any depth is rejected immediately by `strict_parse` as a caller error (`exit 2` on the CLI, raising `CallerError` in the binding) without delivering or appending a decision. Every strictly parsed call document then runs in one fixed order defined by `CONTRACT.md` so a permissive rule can never shadow a safety block.

1. **Call schema validation** checks that the parsed document carries `portcullis-call/1` in `format` and matches the exact field schema of `shell`, `file`, or `network`. Any schema-invalid call is denied immediately with its decision `source` type set to `malformed`.
2. **Fail-closed policy check** denies every schema-valid call with `source` type `policy error` whenever the policy file could not be read, strictly parsed, or validated, before any rule or default runs.
3. **Deny rules** are evaluated in policy order across matching call kinds. The first matching `deny` rule wins immediately, regardless of any `allow`, `rewrite`, or `judge` rule earlier or later in the policy.
4. **Allow, rewrite, and judge rules** are evaluated in policy order once all `deny` rules pass without matching. The first matching rule decides the call.
5. **Policy default** (`allow` or `deny`) closes any call that matched no rule, with its decision `source` type set to `default`.

## 2. Authoring rules by call kind

Start from the ready-to-use template at `examples/policies/coding_agent_policy.json` and tailor matchers to your workspace. Every text matcher takes exactly one form (`exact`, `prefix`, or `glob`).

### Shell calls

Shell calls set `kind` to `shell` and carry `argv` as a non-empty array of strings plus an optional `cwd` string. Matchers can inspect `argv0` (compared verbatim against the raw `argv[0]` token as supplied, not its basename) and `args` at 1-based positions. Pair bare command `exact` rules (`rm`) with path-qualified `glob` rules (`*/rm`) so `/bin/rm` and `/usr/bin/sudo` are blocked alongside `rm` and `sudo`. Separately, Portcullis sets `interpreter` to `true` on the decision record whenever the basename of `argv[0]` names one of the nine Unix shells `sh`, `bash`, `dash`, `ash`, `zsh`, `ksh`, `csh`, `tcsh`, or `fish`.

```json
[
  {
    "id": "deny-rm",
    "kind": "shell",
    "action": "deny",
    "reason": "direct file deletion through rm is blocked",
    "match": {
      "argv0": {"exact": "rm"}
    }
  },
  {
    "id": "deny-rm-path",
    "kind": "shell",
    "action": "deny",
    "reason": "path-qualified rm deletion is blocked",
    "match": {
      "argv0": {"glob": "*/rm"}
    }
  }
]
```

### File calls, `path2`, and `normpath` traversal rules

File calls set `kind` to `file` and carry `operation` (`read`, `write`, `delete`, `move`, or `list`), `path`, and on `move` calls `path2` for the destination path. Under `PC-6`, both `path` and `path2` match a rule when **either** the raw string in the call **or** its lexically normalized path (`normpath`) satisfies the matcher. That OR-rule ensures `..` segments cannot evade a `deny` prefix such as `/etc/`, and also means any policy using `allow` or `rewrite` prefixes (such as `/work/`) must include `deny` rules rejecting `..` traversal segments (`..`, `../`, `*/../*`, and `*/..`) on both `path` and `path2` so raw `/work/../etc/passwd` is denied before reaching an `allow` rule.

```json
{
  "id": "deny-move-into-etc",
  "kind": "file",
  "action": "deny",
  "reason": "moving files into system configuration is blocked",
  "match": {
    "operation": {"exact": "move"},
    "path2": {"prefix": "/etc/"}
  }
}
```

### Staging writes with `rewrite`

A `rewrite` rule substitutes a safe replacement field in `rewritten_call` while exiting `0`, allowing a harness to redirect agent writes into a staging path for review before promotion.

```json
{
  "id": "stage-output-writes",
  "kind": "file",
  "action": "rewrite",
  "reason": "agent output writes land in staging first",
  "match": {
    "operation": {"exact": "write"},
    "path": {"prefix": "/work/out/"}
  },
  "substitute": {
    "path": "/work/staging/out.txt"
  }
}
```

### Network calls

Network calls set `kind` to `network` and carry `method` alongside either `url` (an HTTP or HTTPS URL without embedded userinfo) or explicit `host` and `port` fields. Matchers can restrict `method` (`exact`, `prefix`, or `glob`), lowercase-folded `host` (`exact`, `prefix`, or `glob`), and `port` (`exact` integer from `1` to `65535`).

## 3. Referring ambiguous calls to System One decision models

When static rules cannot tell whether an open-ended shell or network call aligns with the stated task, set `action` to `judge` on a rule and include a `judgment` block on the policy with `threshold` (`0.0` exclusive to `1.0` inclusive), `escalation` (`queue` to escalate uncertain calls or `none` to deny them), and optional `model` (defaulting to `jev-1.14.0` when omitted).

Portcullis ships pure deterministic provider wire codecs in its `providers` module and `examples/decision_judge.py` across five System One provider families.

| Provider family | Supported model identifiers | Environment variables read by `examples/decision_judge.py` |
| --- | --- | --- |
| TypeSafe | `jev-1.14.0` (default), `jev-1.13.0` | `TYPESAFE_API_KEY` or `DECISION_API_KEY` |
| Google | `gemini-decision-1` | `GEMINI_API_KEY`, `GOOGLE_API_KEY`, or `DECISION_API_KEY` |
| OpenAI | `gpt-6-luna`, `gpt-oss-safeguard-120b`, `gpt-oss-safeguard-20b` | `OPENAI_API_KEY` or `DECISION_API_KEY` |
| Perplexity | `pplx-decider-v1.3`, `pplx-decider-latest`, `pplx-decider-flash-v1.3`, `pplx-decider-flash-latest` | `PERPLEXITY_API_KEY` or `DECISION_API_KEY` |
| Cloudflare | `@cf/cloudflare/clef`, `@cf/cloudflare/clef-flash`, `clef`, `clef-flash` | `CLOUDFLARE_API_TOKEN` (with `CLOUDFLARE_ACCOUNT_ID`) or `DECISION_API_KEY` |

```sh
TYPESAFE_API_KEY='SYNTHETIC-TEST-VALUE-key' \
  portcullis check \
  --policy examples/policies/coding_agent_policy.json \
  --log audit.jsonl \
  --judge "python3 examples/decision_judge.py --provider typesafe" \
  call.json
```

When no `--judge` command (or Python `transport` callback) is supplied, or when a consultation fails or falls below `judgment.threshold`, Portcullis never silently allows the call and instead resolves to `escalate` (under `queue`) or `deny` (under `none`).

## 4. Audit log verification and risk-ranked sampling

Use `portcullis log --log audit.jsonl` to validate every JSON decision record in an audit log from start to finish (exiting `1` naming the exact line number on any torn or malformed record, and pairing the file with append-only permissions or external integrity controls when guarding against whole-line deletion), and `portcullis audit --log audit.jsonl --sample 10` to sample the highest-risk model-referred `allow` decisions for human spot-checking.

## 5. Running the bundled quickstarters

Build the `portcullis` binary and run both quickstarters (`examples/quickstart.rs` and `examples/agent_gate.py`) directly from a local checkout.

```sh
cargo build --bin portcullis
cargo run --example quickstart
python3 examples/agent_gate.py
```

## 6. Optional composition with sibling tools

Portcullis stands completely on its own with zero sibling dependencies. In hosts that combine all four Autocode tools, `arvin` governs run health and stage escalation, `portcullis` gates each proposed call, `deadbolt` injects short-lived scoped credentials only after an `allow` or `rewrite` verdict, and `mayfly` isolates execution inside a disposable namespace sandbox.

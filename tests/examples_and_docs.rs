//! Integration pins for obligations PC-38 and PC-39 covering docs/GUIDE.md,
//! SVG hero and architecture assets, CONTRIBUTING.md, GitHub issue forms,
//! bindings rustdoc collision prevention, examples/policies/coding_agent_policy.json,
//! verified README.md installation commands, examples/quickstart.rs, and examples/agent_gate.py.

#[path = "../examples/quickstart.rs"]
mod quickstart;

use std::path::Path;
use std::process::Command;

use portcullis::{evaluate, load_policy, strict_parse, Value};

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn find_python() -> &'static str {
    for candidate in ["python3", "python"] {
        if Command::new(candidate)
            .args(["-c", "import sys"])
            .status()
            .is_ok_and(|status| status.success())
        {
            return candidate;
        }
    }
    panic!("neither python3 nor python is runnable on PATH");
}

fn strip_markdown_link_targets(line: &str) -> String {
    let mut current = line.to_string();
    loop {
        let mut out = String::with_capacity(current.len());
        let bytes = current.as_bytes();
        let mut i = 0;
        let mut changed = false;
        while i < bytes.len() {
            let bang = bytes[i] == b'!' && i + 1 < bytes.len() && bytes[i + 1] == b'[';
            let open = if bang { i + 1 } else { i };
            if bytes[open] == b'[' {
                if let Some(rel_close) = current[open + 1..].find(']') {
                    let close = open + 1 + rel_close;
                    let label = &current[open + 1..close];
                    if !label.contains('[')
                        && !label.contains(']')
                        && close + 1 < bytes.len()
                        && bytes[close + 1] == b'('
                    {
                        if let Some(rel_end) = current[close + 2..].find(')') {
                            out.push_str(label);
                            i = close + 2 + rel_end + 1;
                            changed = true;
                            continue;
                        }
                    }
                }
            }
            let ch = current[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
        if !changed {
            return out;
        }
        current = out;
    }
}

fn strip_inline_code_spans(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_code = false;
    for ch in line.chars() {
        if ch == '`' {
            in_code = !in_code;
        } else if !in_code {
            out.push(ch);
        }
    }
    out
}

fn is_table_delimiter_row(trimmed: &str) -> bool {
    let inner = trimmed.trim_matches('|').trim();
    !inner.is_empty()
        && inner.split('|').all(|cell| {
            let c = cell.trim();
            c.contains('-') && c.chars().all(|ch| matches!(ch, '-' | ':' | ' ' | '\t'))
        })
}

fn check_prose_violations(text: &str) -> Vec<String> {
    let mut violations = Vec::new();
    if text.contains('\u{2014}') {
        violations.push("em dash U+2014".to_string());
    }
    if text.contains('\u{2013}') {
        violations.push("en dash U+2013".to_string());
    }
    let mut in_fence = false;
    let mut fence_marker = String::new();
    for (idx, raw) in text.lines().enumerate() {
        let trimmed = raw.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            let ch = trimmed.chars().next().unwrap();
            let count = trimmed.chars().take_while(|c| *c == ch).count();
            let marker: String = std::iter::repeat_n(ch, count).collect();
            if !in_fence {
                in_fence = true;
                fence_marker = marker;
            } else if trimmed.starts_with(&fence_marker) {
                in_fence = false;
            }
            continue;
        }
        if in_fence || trimmed.starts_with("<!--") {
            continue;
        }
        let cleaned = if trimmed.starts_with('|') {
            if is_table_delimiter_row(trimmed) {
                continue;
            }
            strip_markdown_link_targets(&strip_inline_code_spans(raw))
        } else {
            strip_markdown_link_targets(raw)
        };
        if cleaned.contains(':') {
            violations.push(format!("line {}: colon in prose: {raw}", idx + 1));
        }
        if cleaned.contains(';') {
            violations.push(format!("line {}: semicolon in prose: {raw}", idx + 1));
        }
    }
    violations
}

fn assert_clean_prose(path: &Path, text: &str) {
    let violations = check_prose_violations(text);
    assert!(
        violations.is_empty(),
        "{} failed prose check: {violations:?}",
        path.display()
    );
}

fn assert_sanitized(path: &Path, text: &str) {
    for forbidden in ["/Users/", "/home/david", "@gmail.com"] {
        assert!(
            !text.contains(forbidden),
            "{} contains unsanitized marker {forbidden:?}",
            path.display()
        );
    }
}

#[test]
fn prose_scanner_rejects_colons_semicolons_and_table_prose_punctuation() {
    assert!(!check_prose_violations("a\u{2014}b").is_empty());
    assert!(!check_prose_violations("a\u{2013}b").is_empty());
    assert!(!check_prose_violations("Plain sentence: bad.").is_empty());
    assert!(!check_prose_violations("Plain sentence; bad.").is_empty());
    assert!(!check_prose_violations("| col | cell: bad |\n").is_empty());
    assert!(!check_prose_violations("| col | cell; bad |\n").is_empty());
    assert!(
        check_prose_violations(
            "Clean [guide](https://example.test/a:b).\n| col | desc |\n| --- | :---: |\n| `a:b` | clean cell |\n"
        )
        .is_empty()
    );
}

#[test]
fn starter_coding_agent_policy_parses_strictly_and_enforces_boundaries() {
    let policy_path = repo_root().join("examples/policies/coding_agent_policy.json");
    let raw = std::fs::read_to_string(&policy_path).expect("starter policy exists");
    assert_sanitized(&policy_path, &raw);
    let doc = strict_parse(&raw).expect("starter policy strictly parses");
    let policy = load_policy(&doc).expect("starter policy loads cleanly");

    assert_eq!(policy.default, "deny");
    let judgment = policy.judgment.as_ref().expect("judgment block present");
    assert_eq!(judgment.model, "jev-1.14.0");
    assert_eq!(judgment.escalation, "queue");

    let at = "2031-05-04T12:00:00+00:00";

    for denied_json in [
        r#"{"format":"portcullis-call/1","kind":"shell","argv":["rm","-rf","/work/tmp"]}"#,
        r#"{"format":"portcullis-call/1","kind":"shell","argv":["/bin/rm","-rf","/work/tmp"]}"#,
        r#"{"format":"portcullis-call/1","kind":"shell","argv":["sudo","id"]}"#,
        r#"{"format":"portcullis-call/1","kind":"shell","argv":["/usr/bin/sudo","id"]}"#,
        r#"{"format":"portcullis-call/1","kind":"file","operation":"read","path":"/home/agent/.ssh/id_ed25519"}"#,
        r#"{"format":"portcullis-call/1","kind":"file","operation":"read","path":".ssh/id_ed25519"}"#,
        r#"{"format":"portcullis-call/1","kind":"file","operation":"list","path":"/work/.ssh"}"#,
        r#"{"format":"portcullis-call/1","kind":"file","operation":"list","path":".ssh"}"#,
        r#"{"format":"portcullis-call/1","kind":"file","operation":"read","path":"/work/.env.local"}"#,
        r#"{"format":"portcullis-call/1","kind":"file","operation":"read","path":".env"}"#,
        r#"{"format":"portcullis-call/1","kind":"file","operation":"read","path":"/work/../etc/shadow"}"#,
        r#"{"format":"portcullis-call/1","kind":"file","operation":"list","path":"/work/.."}"#,
        r#"{"format":"portcullis-call/1","kind":"file","operation":"write","path":"/work/out/../../etc/passwd"}"#,
        r#"{"format":"portcullis-call/1","kind":"file","operation":"move","path":"/work/a","path2":"/var/../etc/passwd"}"#,
        r#"{"format":"portcullis-call/1","kind":"file","operation":"move","path":"/work/a","path2":"/work/.env"}"#,
        r#"{"format":"portcullis-call/1","kind":"file","operation":"move","path":"/work/a","path2":"/home/agent/.ssh/authorized_keys"}"#,
        r#"{"format":"portcullis-call/1","kind":"file","operation":"move","path":"/work/a","path2":"/work/../tmp/escaped"}"#,
        r#"{"format":"portcullis-call/1","kind":"network","method":"GET","url":"https://api.example.test/v1"}"#,
    ] {
        let call = strict_parse(denied_json).unwrap();
        let decision = evaluate(Some(&policy), None, &call, at);
        assert_eq!(
            decision.get("decision").and_then(Value::as_str),
            Some("deny"),
            "expected deny for {denied_json}"
        );
    }

    for allowed_json in [
        r#"{"format":"portcullis-call/1","kind":"file","operation":"read","path":"/work/src/main.rs"}"#,
        r#"{"format":"portcullis-call/1","kind":"file","operation":"list","path":"/work/src"}"#,
    ] {
        let call = strict_parse(allowed_json).unwrap();
        let decision = evaluate(Some(&policy), None, &call, at);
        assert_eq!(
            decision.get("decision").and_then(Value::as_str),
            Some("allow"),
            "expected allow for {allowed_json}"
        );
    }

    let write_call = strict_parse(
        r#"{"format":"portcullis-call/1","kind":"file","operation":"write","path":"/work/out/artifact.json"}"#,
    )
    .unwrap();
    let rewrite = evaluate(Some(&policy), None, &write_call, at);
    assert_eq!(
        rewrite.get("decision").and_then(Value::as_str),
        Some("rewrite")
    );
    assert_eq!(
        rewrite
            .get("rewritten_call")
            .and_then(|v| v.get("path"))
            .and_then(Value::as_str),
        Some("/work/staging/out.txt")
    );

    let referred =
        strict_parse(r#"{"format":"portcullis-call/1","kind":"shell","argv":["pytest","-q"]}"#)
            .unwrap();
    let escalated = evaluate(Some(&policy), None, &referred, at);
    assert_eq!(
        escalated.get("decision").and_then(Value::as_str),
        Some("escalate")
    );
}

#[test]
fn operator_guide_and_contract_amendment_satisfy_pc38() {
    let contract_path = repo_root().join("CONTRACT.md");
    let contract = std::fs::read_to_string(&contract_path).expect("CONTRACT.md exists");
    let (_, pc38_section) = contract
        .split_once("## Operator guide, starter policy, runnable quickstarters, and verified install paths amendment")
        .expect("PC-38 amendment section present");
    assert_clean_prose(&contract_path, pc38_section);
    assert_sanitized(&contract_path, pc38_section);

    let guide_path = repo_root().join("docs/GUIDE.md");
    let guide = std::fs::read_to_string(&guide_path).expect("docs/GUIDE.md exists");
    assert_clean_prose(&guide_path, &guide);
    assert_sanitized(&guide_path, &guide);
    assert!(!guide.contains("cargo install portcullis"));
    assert!(!guide.contains("pip install portcullis"));
    assert!(!guide.contains("tamper-evident"));

    for needle in [
        "portcullis-policy/1",
        "portcullis-call/1",
        "strict_parse",
        "policy error",
        "interpreter",
        "path2",
        "normpath",
        "rewrite",
        "jev-1.14.0",
        "gemini-decision-1",
        "gpt-6-luna",
        "pplx-decider-v1.3",
        "@cf/cloudflare/clef",
        "examples/policies/coding_agent_policy.json",
        "examples/quickstart.rs",
        "examples/agent_gate.py",
        "arvin",
        "deadbolt",
        "mayfly",
    ] {
        assert!(guide.contains(needle), "docs/GUIDE.md missing {needle:?}");
    }
}

#[test]
fn readme_install_avoids_third_party_bare_names_and_links_guides() {
    let readme_path = repo_root().join("README.md");
    let readme = std::fs::read_to_string(&readme_path).expect("README.md exists");
    assert_clean_prose(&readme_path, &readme);
    assert_sanitized(&readme_path, &readme);

    for required in [
        "cargo install --git https://github.com/david-engelmann/portcullis.git --tag v0.2.0 --bin portcullis",
        "https://github.com/david-engelmann/portcullis/releases/tag/v0.2.0",
        "pip install \"git+https://github.com/david-engelmann/portcullis.git@v0.2.0\"",
        "cargo install --path . --bin portcullis",
        "[docs/GUIDE.md](docs/GUIDE.md)",
        "[examples/policies/coding_agent_policy.json](examples/policies/coding_agent_policy.json)",
        "[examples/quickstart.rs](examples/quickstart.rs)",
        "[examples/agent_gate.py](examples/agent_gate.py)",
    ] {
        assert!(readme.contains(required), "README.md missing {required:?}");
    }
    assert!(
        !readme.contains("cargo install portcullis"),
        "README.md must not instruct bare cargo install portcullis"
    );
    assert!(
        !readme.contains("pip install portcullis"),
        "README.md must not instruct bare pip install portcullis"
    );
}

#[test]
fn rust_quickstart_example_runs_end_to_end() {
    assert_sanitized(
        &repo_root().join("examples/quickstart.rs"),
        &std::fs::read_to_string(repo_root().join("examples/quickstart.rs")).unwrap(),
    );
    quickstart::run_quickstart().expect("examples/quickstart.rs runs end to end");
}

#[test]
fn python_agent_gate_walkthrough_runs_end_to_end() {
    let script = repo_root().join("examples/agent_gate.py");
    assert_sanitized(&script, &std::fs::read_to_string(&script).unwrap());

    let output = Command::new(find_python())
        .arg(&script)
        .arg("--portcullis-bin")
        .arg(env!("CARGO_BIN_EXE_portcullis"))
        .output()
        .expect("spawn examples/agent_gate.py");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "agent_gate.py failed ({:?}): stdout={stdout} stderr={stderr}",
        output.status.code()
    );
    for needle in [
        "1. read /work/README.md -> allow",
        "/work/staging/out.txt",
        "deny-move-into-etc",
        "(jev-1.14.0)",
        "5. audit sample returned 1 scored allow",
    ] {
        assert!(
            stdout.contains(needle),
            "agent_gate.py stdout missing {needle:?}: {stdout}"
        );
    }
}

#[test]
fn visual_assets_contributing_issue_forms_and_bindings_doc_satisfy_pc39() {
    let contract_path = repo_root().join("CONTRACT.md");
    let contract = std::fs::read_to_string(&contract_path).expect("CONTRACT.md exists");
    let (_, pc39_section) = contract
        .split_once(
            "## Visual architecture, contributor guide, issue forms, and workspace rustdoc amendment",
        )
        .expect("PC-39 amendment section present");
    assert_clean_prose(&contract_path, pc39_section);
    assert_sanitized(&contract_path, pc39_section);
    assert!(pc39_section.contains("Obligation PC-39"));

    for rel in ["docs/assets/hero.svg", "docs/assets/architecture.svg"] {
        let svg_path = repo_root().join(rel);
        let svg = std::fs::read_to_string(&svg_path).unwrap_or_else(|_| panic!("{rel} exists"));
        assert_sanitized(&svg_path, &svg);
        assert!(!svg.contains('\u{2014}') && !svg.contains('\u{2013}'));
        assert!(svg.contains("<svg ") && svg.contains("viewBox=") && svg.contains("</svg>"));
        let status = Command::new(find_python())
            .args([
                "-c",
                "import sys, xml.etree.ElementTree as ET; root = ET.parse(sys.argv[1]).getroot(); assert root.tag in ('{http://www.w3.org/2000/svg}svg', 'svg') and 'viewBox' in root.attrib",
            ])
            .arg(&svg_path)
            .status()
            .expect("parse SVG with ElementTree");
        assert!(status.success(), "{rel} failed strict XML SVG parse");
    }
    let reject_notsvg = Command::new(find_python())
        .args([
            "-c",
            "import xml.etree.ElementTree as ET; root = ET.fromstring('<notsvg viewBox=\"0 0 1 1\"><svg/></notsvg>'); assert root.tag in ('{http://www.w3.org/2000/svg}svg', 'svg')",
        ])
        .output()
        .expect("negative SVG root check");
    assert!(!reject_notsvg.status.success());

    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("README.md");
    for needle in [
        "![portcullis overview](docs/assets/hero.svg)",
        "![portcullis architecture](docs/assets/architecture.svg)",
        "## Architecture",
        "portcullis-decision/2",
        "judgment.threshold",
        "ci.yml/badge.svg",
        "portability.yml/badge.svg",
        "img.shields.io/github/v/release/david-engelmann/portcullis",
        "rust-1.91%2B-orange.svg",
        "license-MIT-blue.svg",
        "[Install](#install)",
        "[Quickstart](#quickstart)",
        "[Architecture](#architecture)",
        "[Usage](#usage)",
        "[Guides and examples](#guides-and-examples)",
        "[Operator Guide](docs/GUIDE.md)",
        "[Contributing](CONTRIBUTING.md)",
        "[Contract](CONTRACT.md)",
        "[CONTRIBUTING.md](CONTRIBUTING.md)",
        "[SECURITY.md](SECURITY.md)",
    ] {
        assert!(readme.contains(needle), "README.md missing {needle:?}");
    }
    let (_, after_arch) = readme
        .split_once("\n## Architecture\n")
        .expect("Architecture section present");
    let (arch_body, _) = after_arch
        .split_once("\n## Usage\n")
        .expect("Usage section follows Architecture");
    assert!(
        !arch_body.contains("```"),
        "## Architecture must not contain raw code fences that perturb README JSON pins"
    );
    for forbidden in [
        "crates.io/crates/portcullis",
        "shields.io/crates/",
        "docs.rs/portcullis",
    ] {
        assert!(
            !readme.contains(forbidden),
            "README.md must not badge unrelated third-party crate ({forbidden})"
        );
    }

    let guide = std::fs::read_to_string(repo_root().join("docs/GUIDE.md")).expect("docs/GUIDE.md");
    assert!(guide.contains("![portcullis architecture](assets/architecture.svg)"));

    let contrib_path = repo_root().join("CONTRIBUTING.md");
    let contrib = std::fs::read_to_string(&contrib_path).expect("CONTRIBUTING.md exists");
    assert_clean_prose(&contrib_path, &contrib);
    assert_sanitized(&contrib_path, &contrib);
    for needle in [
        "1.91",
        "CONTRACT.md",
        "Signed-off-by",
        "cargo test --locked",
        "codepoint_scan",
        "clippy",
        "cargo doc --locked --no-deps",
        "SYNTHETIC-TEST-VALUE-",
        "[SECURITY.md](SECURITY.md)",
    ] {
        assert!(
            contrib.contains(needle),
            "CONTRIBUTING.md missing {needle:?}"
        );
    }

    fn valid_issue_form_yaml(text: &str) -> bool {
        if text.trim().is_empty() || text.contains('\t') {
            return false;
        }
        let mut block_indent: Option<usize> = None;
        for raw in text.lines() {
            if raw.trim().is_empty() || raw.trim_start().starts_with('#') {
                continue;
            }
            let indent = raw.len() - raw.trim_start().len();
            if indent % 2 != 0 {
                return false;
            }
            if let Some(min_indent) = block_indent {
                if indent > min_indent {
                    continue;
                }
                block_indent = None;
            }
            let trimmed = raw.trim();
            let rest = trimmed.strip_prefix("- ").unwrap_or(trimmed);
            let Some((_, val)) = rest.split_once(':') else {
                return false;
            };
            let v = val.trim();
            if v == "|" || v == ">" {
                block_indent = Some(indent);
                continue;
            }
            if v.chars().filter(|c| *c == '"').count() % 2 != 0 {
                return false;
            }
            if v.chars().filter(|c| *c == '[').count() != v.chars().filter(|c| *c == ']').count() {
                return false;
            }
        }
        true
    }
    assert!(!valid_issue_form_yaml("name: Bug report\nbroken: [\n"));
    assert!(!valid_issue_form_yaml("name: Bug report\n\tbad: true\n"));

    for (rel, markers) in [
        (
            ".github/ISSUE_TEMPLATE/bug_report.yml",
            &["name: Bug report", "SECURITY.md", "portcullis --version"][..],
        ),
        (
            ".github/ISSUE_TEMPLATE/feature_request.yml",
            &[
                "name: Feature or contract proposal",
                "SECURITY.md",
                "CONTRACT.md",
            ][..],
        ),
        (
            ".github/ISSUE_TEMPLATE/config.yml",
            &[
                "contact_links:",
                "https://github.com/david-engelmann/portcullis/security/advisories/new",
            ][..],
        ),
    ] {
        let p = repo_root().join(rel);
        let yml = std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("{rel} exists"));
        assert_sanitized(&p, &yml);
        assert!(!yml.contains('\u{2014}') && !yml.contains('\u{2013}'));
        assert!(valid_issue_form_yaml(&yml), "{rel} failed YAML check");
        for m in markers {
            assert!(yml.contains(m), "{rel} missing {m:?}");
        }
    }

    let bindings_toml = std::fs::read_to_string(repo_root().join("bindings/Cargo.toml"))
        .expect("bindings/Cargo.toml");
    let (_, lib_section) = bindings_toml
        .split_once("[lib]")
        .expect("[lib] section in bindings/Cargo.toml");
    let lib_block = lib_section.split("\n[").next().unwrap_or(lib_section);
    assert!(
        lib_block.lines().any(|l| l.trim() == "doc = false"),
        "bindings/Cargo.toml [lib] must set doc = false"
    );
}

//! The setup pins, translated from the Python setup suite the
//! repo was seeded with, brought up to the current fleet
//! standard. Each test names the same fact its Python original
//! named, with the strengthenings the fleet folded in after
//! portcullis's Round 1 suite was written, three of them landing
//! with this port: the job level if false pin, the wrong arc
//! label pin, and the CI credential hygiene pin. Two facts
//! changed with the Rust conversion and the change is stated
//! where it lands. The CI gate commands are the Rust gate
//! commands of amended obligation S2, and the contract substance
//! pin asserts the amended S2 phrases.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

const MARKER: &str = "<!-- repo annex below this line -->";
const GATE_COMMAND: &str = "cargo test";
const SCAN_COMMAND: &str = "cargo run --bin codepoint_scan";
const FMT_COMMAND: &str = "cargo fmt --check";
const CLIPPY_COMMAND: &str = "cargo clippy --all-targets -- -D warnings";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(name: &str) -> String {
    std::fs::read_to_string(root().join(name)).unwrap()
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "portcullis-setup-test-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn seed_files_exist() {
    for name in ["README.md", "LICENSE", ".gitignore"] {
        assert!(root().join(name).is_file(), "{name}");
    }
}

#[test]
fn license_starts_with_mit_heading() {
    assert!(read("LICENSE").starts_with("MIT License\n"));
}

#[test]
fn agents_has_marker_and_portcullis_annex_below_it() {
    let text = read("AGENTS.md");
    assert!(text.contains(MARKER));
    let annex = text.split(MARKER).nth(1).unwrap();
    assert!(annex.contains("portcullis"));
    assert!(annex.contains("CONTRACT.md"));
    assert!(annex.contains("guards the calls"));
}

#[test]
fn agents_canonical_part_carries_program_headings() {
    let text = read("AGENTS.md");
    let canonical = text.split(MARKER).next().unwrap();
    assert!(canonical.starts_with("# AGENTS.md\n"));
    assert!(canonical.contains("## The round discipline"));
    assert!(canonical.contains("## Contract first"));
    assert!(canonical.contains("39 repo storefront perfection program"));
}

#[test]
fn contract_names_five_setup_obligations() {
    let text = read("CONTRACT.md");
    for name in ["S1", "S2", "S3", "S4", "S5"] {
        assert!(
            text.contains(&format!("Obligation {name} covers")),
            "{name}"
        );
    }
    assert!(!text.contains("Obligation S6"));
}

fn status_section(text: &str) -> &str {
    let start = text.find("\n## Status\n").unwrap() + "\n## Status\n".len();
    let rest = &text[start..];
    match rest.find("\n## ") {
        Some(end) => &rest[..end],
        None => rest,
    }
}

#[test]
fn readme_status_states_eleven_of_one_hundred() {
    let text = read("README.md");
    assert!(text.contains("## Status"));
    let status = status_section(&text);
    // The full sentence, never the bare count, because the
    // bare count is a substring of every two digit count that
    // ends in the same digit and a pin on it would pass over
    // a wrong statement of the closed rounds.
    assert!(status.contains("Closed perfection rounds are 11 of 100."));
    assert!(status.contains("46b1cafe58e78f9b0820b81800b6727cc2ffae60"));
}

/// Whether an `if:` value disables its step or job. The value
/// is read through its quote marks and through the expression
/// wrapper GitHub Actions accepts, because a step disabled as
/// ${{ false }} is skipped exactly as one disabled as false.
fn if_value_is_false(value: &str) -> bool {
    let value = value
        .trim()
        .trim_matches(|c| c == '\'' || c == '"')
        .trim_start_matches("${{")
        .trim_end_matches("}}")
        .trim()
        .trim_matches(|c| c == '\'' || c == '"')
        .to_lowercase();
    value == "false"
}

fn flush_step(step_lines: &mut Vec<String>, commands: &mut Vec<String>) {
    if step_lines.is_empty() {
        return;
    }
    let mut disabled = false;
    let mut runs = Vec::new();
    for stripped in step_lines.iter() {
        if let Some(value) = stripped.strip_prefix("if:") {
            if if_value_is_false(value) {
                disabled = true;
            }
        }
        if let Some(command) = stripped.strip_prefix("run:") {
            runs.push(command.trim().to_string());
        }
    }
    if !disabled {
        commands.extend(runs);
    }
    step_lines.clear();
}

fn run_commands(ci_text: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut step_lines: Vec<String> = Vec::new();
    let mut in_steps = false;
    let mut in_test_job = false;
    let mut job_disabled = false;
    for line in ci_text.lines() {
        let stripped = line.trim();
        if stripped.starts_with('#') {
            continue;
        }
        if stripped == "test:" {
            in_test_job = true;
            continue;
        }
        if in_test_job && !in_steps && stripped.starts_with("if:") {
            let value = stripped
                .split_once(':')
                .map(|(_, rest)| rest)
                .unwrap_or_default();
            if if_value_is_false(value) {
                job_disabled = true;
            }
            continue;
        }
        if stripped == "steps:" {
            in_steps = true;
            continue;
        }
        if in_steps && stripped.starts_with("- ") {
            flush_step(&mut step_lines, &mut commands);
            step_lines.push(stripped[2..].trim().to_string());
            continue;
        }
        if in_steps {
            step_lines.push(stripped.to_string());
        }
    }
    flush_step(&mut step_lines, &mut commands);
    if job_disabled {
        return Vec::new();
    }
    commands
}

#[test]
fn ci_runs_the_local_gate_commands() {
    let commands = run_commands(&read(".github/workflows/ci.yml"));
    assert!(commands.iter().any(|c| c == GATE_COMMAND));
    assert!(commands.iter().any(|c| c == SCAN_COMMAND));
    assert!(commands.iter().any(|c| c == FMT_COMMAND));
    assert!(commands.iter().any(|c| c == CLIPPY_COMMAND));
}

/// The part of the workflow that belongs to the test job,
/// running from its job key to the next job key at the same
/// indent, or to the end of the file when no job follows it.
fn test_job_section(ci_text: &str) -> &str {
    let start = ci_text
        .find("\n  test:\n")
        .map(|at| at + 1)
        .expect("the workflow carries no test job");
    let rest = &ci_text[start..];
    let mut end = rest.len();
    let mut offset = 0;
    for (index, line) in rest.lines().enumerate() {
        if index > 0 && line.starts_with("  ") && !line.starts_with("   ") && line.ends_with(':') {
            end = offset;
            break;
        }
        offset += line.len() + 1;
    }
    &rest[..end]
}

#[test]
fn ci_gate_steps_stand_inside_the_test_job() {
    let text = read(".github/workflows/ci.yml");
    let section = test_job_section(&text);
    // The pin on the gate commands finds all four commands
    // wherever they stand in the file. This pin is stricter.
    // The formatting step and the linter step must stand
    // inside the test job itself, under the toolchain that
    // job pins, and not drift into a later job that floats
    // on a toolchain of its own.
    assert!(section.contains(&format!("run: {FMT_COMMAND}")));
    assert!(section.contains(&format!("run: {CLIPPY_COMMAND}")));
}

#[test]
fn ci_carries_the_fleet_credential_hygiene() {
    let text = read(".github/workflows/ci.yml");
    // The workflow asks for no more than it uses. Its token
    // is limited to reading the repository, the checkout
    // leaves no credential behind for later steps, no step
    // widens the token, and the toolchain action is pinned
    // to a full commit SHA rather than a moving branch name.
    assert!(text.contains("permissions:"));
    assert!(text.contains("contents: read"));
    // The setting is read inside the checkout step alone, so
    // the same line standing under another step cannot stand
    // in for the checkout leaving no credential behind.
    let checkout_at = text
        .lines()
        .position(|line| line.contains("actions/checkout"))
        .expect("the workflow carries no checkout step");
    let checkout_block: Vec<&str> = text
        .lines()
        .skip(checkout_at + 1)
        .take_while(|line| line.trim().is_empty() || !line.trim_start().starts_with("- "))
        .collect();
    assert!(checkout_block
        .iter()
        .any(|line| line.trim() == "persist-credentials: false"));
    assert!(!text.contains("write-all"));
    assert!(!text.contains("contents: write"));
    assert!(!text.contains("rust-toolchain@master"));
    let toolchain_line = text
        .lines()
        .find(|line| line.contains("dtolnay/rust-toolchain@"))
        .expect("the workflow carries no toolchain step");
    let pin = toolchain_line
        .split("dtolnay/rust-toolchain@")
        .nth(1)
        .unwrap()
        .trim();
    assert_eq!(pin.len(), 40, "{}", toolchain_line);
    assert!(pin
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
}

#[test]
fn ci_gate_parser_skips_a_step_disabled_with_if_false() {
    let ci_text = read(".github/workflows/ci.yml");
    let gate_step = "      - name: Run the local gate\n        run: cargo test";
    assert!(ci_text.contains(gate_step));
    for flag in ["false", "\"false\"", "${{ false }}", "${{false}}"] {
        let disabled = ci_text.replace(
            gate_step,
            &format!(
                "      - name: Run the local gate\n        if: {flag}\n        run: cargo test"
            ),
        );
        let commands = run_commands(&disabled);
        assert!(!commands.iter().any(|c| c == GATE_COMMAND));
        assert!(commands.iter().any(|c| c == SCAN_COMMAND));
    }
}

#[test]
fn ci_gate_parser_rejects_a_job_disabled_with_if_false() {
    let ci_text = read(".github/workflows/ci.yml");
    let job_head = "  test:\n    runs-on: ubuntu-latest";
    assert!(ci_text.contains(job_head));
    for flag in ["false", "\"false\"", "${{ false }}", "${{false}}"] {
        let disabled = ci_text.replace(
            job_head,
            &format!("  test:\n    if: {flag}\n    runs-on: ubuntu-latest"),
        );
        let commands = run_commands(&disabled);
        assert!(!commands.iter().any(|c| c == GATE_COMMAND));
        assert!(!commands.iter().any(|c| c == SCAN_COMMAND));
        assert!(!commands.iter().any(|c| c == FMT_COMMAND));
        assert!(!commands.iter().any(|c| c == CLIPPY_COMMAND));
    }
    let commands = run_commands(&ci_text);
    assert!(commands.iter().any(|c| c == GATE_COMMAND));
    assert!(commands.iter().any(|c| c == SCAN_COMMAND));
    assert!(commands.iter().any(|c| c == FMT_COMMAND));
    assert!(commands.iter().any(|c| c == CLIPPY_COMMAND));
}

struct ScanOutput {
    status: i32,
    stdout: String,
    stderr: String,
}

fn scan_tree(root: &Path) -> ScanOutput {
    let output = Command::new(env!("CARGO_BIN_EXE_codepoint_scan"))
        .arg(root)
        .output()
        .unwrap();
    ScanOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[test]
fn codepoint_scan_reports_zero_for_the_repo() {
    let result = scan_tree(&root());
    assert_eq!(result.status, 0, "{}", result.stdout);
    assert!(result.stdout.contains("em dash U+2014 count 0"));
    assert!(result.stdout.contains("en dash U+2013 count 0"));
}

const CANONICAL_ABOVE_MARKER_SHA256: &str =
    "bb3e2fc1790b13729da3495c3f0902b968577f4e45ceb27e48e90b489f36e1a7";

#[test]
fn agents_canonical_part_matches_pinned_digest() {
    let agents = std::fs::read(root().join("AGENTS.md")).unwrap();
    let marker: &[u8] = b"<!-- repo annex below this line -->";
    let position = agents
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&agents[..position]);
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(digest, CANONICAL_ABOVE_MARKER_SHA256);
}

#[test]
fn readme_has_exactly_one_status_section() {
    let text = read("README.md");
    assert_eq!(text.matches("\n## Status\n").count(), 1);
}

#[test]
fn readme_carries_no_wrong_arc_label() {
    assert!(!read("README.md").contains("Fleet Operations"));
}

#[test]
fn codepoint_scan_counts_an_em_dash() {
    let dir = temp_dir("em-dash");
    std::fs::write(dir.join("note.md"), "a\u{2014}b").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 1);
    assert!(result.stdout.contains("em dash U+2014 count 1"));
    assert!(result.stdout.contains("note.md"));
}

#[test]
fn codepoint_scan_counts_an_en_dash() {
    let dir = temp_dir("en-dash");
    std::fs::write(dir.join("note.md"), "a\u{2013}b").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 1);
    assert!(result.stdout.contains("en dash U+2013 count 1"));
}

#[test]
fn codepoint_scan_scans_a_root_under_an_excluded_ancestor() {
    let dir = temp_dir("excluded-ancestor").join("venv").join("tree");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("note.md"), "a\u{2014}b").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 1);
    assert!(result.stdout.contains("em dash U+2014 count 1"));
}

#[test]
fn codepoint_scan_skips_excluded_dirs_below_the_root() {
    let dir = temp_dir("excluded-dirs");
    let cache = dir.join("build");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("note.md"), "a\u{2014}b").unwrap();
    std::fs::write(dir.join("clean.md"), "clean").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 0);
    assert!(result.stdout.contains("em dash U+2014 count 0"));
}

#[test]
fn contract_obligations_carry_their_substance() {
    let text = read("CONTRACT.md");
    for phrase in [
        "present from the first commit",
        "every later change lands through a pull request",
        "no paid service",
        "cargo test plus the codepoint scan run through cargo",
        "0 of 100 until a full cycle",
        "no file carries a real trace or a real transcript or a real name",
        "SHA-256 digest of the part above the marked line",
        "exactly the keys model and questions and state",
        "in the order the builder consumes them",
        "the probabilities entry of the chosen label",
        "the exhibit file EXHIBIT.md",
        "the first rule in policy order that matches the call",
        "a policy that stands loaded",
        "holds exactly the keys format and kind and method and host and port",
        "with keys sorted at every level",
    ] {
        assert!(text.contains(phrase), "{phrase}");
    }
}

#[test]
fn codepoint_scan_fails_loudly_on_undecodable_input() {
    let dir = temp_dir("undecodable");
    std::fs::write(dir.join("note.md"), b"\xff\xfe not utf-8").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 2);
    assert!(result.stderr.contains("note.md"));
}

#[test]
fn codepoint_scan_counts_a_dash_in_a_file_with_no_suffix() {
    let dir = temp_dir("no-suffix");
    std::fs::write(dir.join("LICENSE"), "a\u{2014}b").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 1);
    assert!(result.stdout.contains("em dash U+2014 count 1"));
}

#[test]
fn codepoint_scan_counts_a_dash_in_an_uppercase_suffix_file() {
    let dir = temp_dir("upper-suffix");
    std::fs::write(dir.join("UPPER.MD"), "a\u{2014}b").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 1);
    assert!(result.stdout.contains("em dash U+2014 count 1"));
}

#[test]
fn codepoint_scan_skips_a_file_with_an_uppercase_binary_suffix() {
    let dir = temp_dir("upper-binary");
    std::fs::write(dir.join("FAKE.PNG"), "a\u{2014}b").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 0);
    assert!(result.stdout.contains("em dash U+2014 count 0"));
    assert!(result.stdout.contains("en dash U+2013 count 0"));
}

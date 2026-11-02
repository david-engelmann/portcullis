import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARKER = "<!-- repo annex below this line -->"


def read(name):
    return (ROOT / name).read_text(encoding="utf-8")


def test_seed_files_exist():
    for name in ("README.md", "LICENSE", ".gitignore"):
        assert (ROOT / name).is_file(), name


def test_license_starts_with_mit_heading():
    assert read("LICENSE").startswith("MIT License\n")


def test_agents_has_marker_and_portcullis_annex_below_it():
    text = read("AGENTS.md")
    assert MARKER in text
    annex = text.split(MARKER, 1)[1]
    assert "portcullis" in annex
    assert "CONTRACT.md" in annex
    assert "guards the calls" in annex


def test_agents_canonical_part_carries_program_headings():
    canonical = read("AGENTS.md").split(MARKER, 1)[0]
    assert canonical.startswith("# AGENTS.md\n")
    assert "## The round discipline" in canonical
    assert "## Contract first" in canonical
    assert "39 repo storefront perfection program" in canonical


def test_contract_names_five_setup_obligations():
    text = read("CONTRACT.md")
    for name in ("S1", "S2", "S3", "S4", "S5"):
        assert f"Obligation {name} covers" in text, name
    assert "Obligation S6" not in text


def _status_section(text):
    start = text.index("\n## Status\n") + len("\n## Status\n")
    rest = text[start:]
    end = rest.find("\n## ")
    return rest if end == -1 else rest[:end]


def test_readme_status_states_zero_of_one_hundred():
    text = read("README.md")
    assert "## Status" in text
    status = _status_section(text)
    assert "0 of 100" in status
    assert "46b1cafe58e78f9b0820b81800b6727cc2ffae60" in status


def _run_commands(ci_text):
    commands = []
    step_lines = []

    def flush_step():
        if not step_lines:
            return
        disabled = False
        runs = []
        for stripped in step_lines:
            if stripped.startswith("if:"):
                value = stripped.split(":", 1)[1].strip().strip("'\"").lower()
                if value == "false":
                    disabled = True
            if "run:" in stripped:
                runs.append(stripped.split("run:", 1)[1].strip())
        if not disabled:
            commands.extend(runs)
        step_lines.clear()

    in_steps = False
    for line in ci_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped == "steps:":
            in_steps = True
            continue
        if in_steps and stripped.startswith("- "):
            flush_step()
            step_lines.append(stripped[2:].strip())
            continue
        if in_steps:
            step_lines.append(stripped)
    flush_step()
    return commands


def test_ci_runs_the_local_gate_commands():
    commands = _run_commands(read(".github/workflows/ci.yml"))
    assert "python -m pytest -q" in commands
    assert "python scripts/codepoint_scan.py" in commands


def test_ci_gate_parser_skips_a_step_disabled_with_if_false():
    ci_text = read(".github/workflows/ci.yml")
    gate_step = "      - name: Run the local gate\n        run: python -m pytest -q"
    assert gate_step in ci_text
    for flag in ("false", '"false"'):
        disabled = ci_text.replace(
            gate_step,
            "      - name: Run the local gate\n"
            f"        if: {flag}\n"
            "        run: python -m pytest -q",
        )
        commands = _run_commands(disabled)
        assert "python -m pytest -q" not in commands
        assert "python scripts/codepoint_scan.py" in commands


def test_codepoint_scan_reports_zero_for_the_repo():
    result = _scan_tree(ROOT)
    assert result.returncode == 0, result.stdout
    assert "em dash U+2014 count 0" in result.stdout
    assert "en dash U+2013 count 0" in result.stdout


CANONICAL_ABOVE_MARKER_SHA256 = "bb3e2fc1790b13729da3495c3f0902b968577f4e45ceb27e48e90b489f36e1a7"


def test_agents_canonical_part_matches_pinned_digest():
    agents = (ROOT / "AGENTS.md").read_bytes()
    marker = b"<!-- repo annex below this line -->"
    above = agents[: agents.find(marker)]
    assert hashlib.sha256(above).hexdigest() == CANONICAL_ABOVE_MARKER_SHA256


def test_readme_has_exactly_one_status_section():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert readme.count("\n## Status\n") == 1


def _scan_tree(root):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "codepoint_scan.py"), str(root)],
        capture_output=True,
        text=True,
    )


def test_codepoint_scan_counts_an_em_dash(tmp_path):
    (tmp_path / "note.md").write_text("a\u2014b", encoding="utf-8")
    result = _scan_tree(tmp_path)
    assert result.returncode == 1
    assert "em dash U+2014 count 1" in result.stdout
    assert "note.md" in result.stdout


def test_codepoint_scan_counts_an_en_dash(tmp_path):
    (tmp_path / "note.md").write_text("a\u2013b", encoding="utf-8")
    result = _scan_tree(tmp_path)
    assert result.returncode == 1
    assert "en dash U+2013 count 1" in result.stdout


def test_codepoint_scan_scans_a_root_under_an_excluded_ancestor(tmp_path):
    root = tmp_path / "venv" / "tree"
    root.mkdir(parents=True)
    (root / "note.md").write_text("a\u2014b", encoding="utf-8")
    result = _scan_tree(root)
    assert result.returncode == 1
    assert "em dash U+2014 count 1" in result.stdout


def test_codepoint_scan_skips_excluded_dirs_below_the_root(tmp_path):
    cache = tmp_path / "build"
    cache.mkdir()
    (cache / "note.md").write_text("a\u2014b", encoding="utf-8")
    (tmp_path / "clean.md").write_text("clean", encoding="utf-8")
    result = _scan_tree(tmp_path)
    assert result.returncode == 0
    assert "em dash U+2014 count 0" in result.stdout


def test_contract_obligations_carry_their_substance():
    text = read("CONTRACT.md")
    for phrase in (
        "present from the first commit",
        "every later change lands through a pull request",
        "no network access and no paid service",
        "0 of 100 until a full cycle",
        "no file carries a real trace or a real transcript or a real name",
        "SHA-256 digest of the part above the marked line",
    ):
        assert phrase in text, phrase


def test_codepoint_scan_fails_loudly_on_undecodable_input(tmp_path):
    (tmp_path / "note.md").write_bytes(b"\xff\xfe not utf-8")
    result = _scan_tree(tmp_path)
    assert result.returncode == 2
    assert "note.md" in result.stderr


def test_codepoint_scan_counts_a_dash_in_a_file_with_no_suffix(tmp_path):
    (tmp_path / "LICENSE").write_text("a\u2014b", encoding="utf-8")
    result = _scan_tree(tmp_path)
    assert result.returncode == 1
    assert "em dash U+2014 count 1" in result.stdout


def test_codepoint_scan_counts_a_dash_in_an_uppercase_suffix_file(tmp_path):
    (tmp_path / "UPPER.MD").write_text("a\u2014b", encoding="utf-8")
    result = _scan_tree(tmp_path)
    assert result.returncode == 1
    assert "em dash U+2014 count 1" in result.stdout


def test_codepoint_scan_skips_a_file_with_an_uppercase_binary_suffix(tmp_path):
    (tmp_path / "FAKE.PNG").write_text("a\u2014b", encoding="utf-8")
    result = _scan_tree(tmp_path)
    assert result.returncode == 0
    assert "em dash U+2014 count 0" in result.stdout
    assert "en dash U+2013 count 0" in result.stdout

//! Matching, whether a rule reaches a call and what a rewrite makes of it.

use crate::policy::{Matcher, Rule, Substitute};
use crate::value::Value;
use crate::DECISION_FORMAT;

/// Lexical path normalization with no filesystem access, the
/// posixpath.normpath behaviour, resolving dot segments exactly
/// as that function resolves them.
pub fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let mut initial_slashes = usize::from(path.starts_with('/'));
    if initial_slashes == 1 && path.starts_with("//") && !path.starts_with("///") {
        initial_slashes = 2;
    }
    let mut new_comps: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp != ".."
            || (initial_slashes == 0 && new_comps.is_empty())
            || new_comps.last() == Some(&"..")
        {
            new_comps.push(comp);
        } else if !new_comps.is_empty() {
            new_comps.pop();
        }
    }
    let joined = new_comps.join("/");
    let result = if initial_slashes > 0 {
        format!("{}{}", "/".repeat(initial_slashes), joined)
    } else {
        joined
    };
    if result.is_empty() {
        ".".to_string()
    } else {
        result
    }
}

/// Case sensitive glob matching in which the star crosses path
/// separators, the fnmatch.fnmatchcase behaviour. The pattern
/// language is a star for any run of characters, a question mark
/// for exactly one character, and a bracket class holding single
/// characters and ranges, negated by a leading exclamation mark.
/// A backslash is an ordinary character.
///
/// The match is a single scan over the pattern atoms and the
/// text, with backtracking through the last star alone. When
/// the scan stalls, the last star takes one more character and
/// the scan resumes just past it, and the position that star
/// has consumed up to only ever advances, so no split of the
/// text at a star is ever retried from an earlier split. A
/// bracket class test costs a binary search over the ranges of
/// that class. The work the match can do is bounded by the
/// pattern length times the text length in the worst
/// arrangement, and the scan is one forward pass, with no
/// backtracking at all, when the pattern holds no star, so
/// neither a long literal pattern nor a many starred pattern
/// against a long text grows the stack or stalls the scan.
fn glob_match(pattern: &[char], text: &[char]) -> bool {
    let atoms = glob_atoms(pattern);
    let (mut atom_at, mut text_at) = (0, 0);
    // The last star atom the scan passed, and the text position
    // that star has consumed up to. A stall hands that star one
    // more character and resumes the scan just past it.
    let mut last_star: Option<(usize, usize)> = None;
    while text_at < text.len() {
        if atom_at < atoms.len() {
            match &atoms[atom_at] {
                GlobAtom::Star => {
                    last_star = Some((atom_at, text_at));
                    atom_at += 1;
                    continue;
                }
                atom => {
                    if glob_atom_matches(atom, text[text_at]) {
                        atom_at += 1;
                        text_at += 1;
                        continue;
                    }
                }
            }
        }
        match last_star {
            Some((star_at, consumed)) => {
                let consumed = consumed + 1;
                last_star = Some((star_at, consumed));
                atom_at = star_at + 1;
                text_at = consumed;
            }
            None => return false,
        }
    }
    atoms[atom_at..]
        .iter()
        .all(|atom| matches!(atom, GlobAtom::Star))
}

/// Whether one single character atom of a glob pattern admits
/// a character. A star is not a single character atom and never
/// reaches this test, the scan handles it on its own.
fn glob_atom_matches(atom: &GlobAtom, member: char) -> bool {
    match atom {
        GlobAtom::Star => false,
        GlobAtom::Any => true,
        GlobAtom::Literal(expected) => member == *expected,
        GlobAtom::Class { negated, ranges } => glob_class_admits(ranges, member) != *negated,
    }
}

/// One atom of a glob pattern, a star, a question mark, a
/// literal character, or a bracket class held as the sorted and
/// merged ranges it admits, so a membership test is a binary
/// search and the union the class admits is the union its
/// members and ranges name.
enum GlobAtom {
    Star,
    Any,
    Literal(char),
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
}

/// Read a glob pattern into its atoms. A run of stars collapses
/// into one star atom, because a star already stands for any run
/// of characters, so the collapse changes no outcome and
/// shortens the table. A bracket that never closes stands as a
/// literal character, as the glob translator reads it, and a
/// bracket standing past the last closing bracket in the
/// pattern can never close, so it is read as a literal without
/// a scan of the tail.
fn glob_atoms(pattern: &[char]) -> Vec<GlobAtom> {
    let last_close = pattern.iter().rposition(|member| *member == ']');
    let mut atoms = Vec::new();
    let mut at = 0;
    while at < pattern.len() {
        match pattern[at] {
            '*' => {
                if !matches!(atoms.last(), Some(GlobAtom::Star)) {
                    atoms.push(GlobAtom::Star);
                }
                at += 1;
            }
            '?' => {
                atoms.push(GlobAtom::Any);
                at += 1;
            }
            '[' if last_close.is_some_and(|close| at < close) => {
                match parse_class(&pattern[at..]) {
                    Some((negated, items, rest)) => {
                        let consumed = pattern[at..].len() - rest.len();
                        atoms.push(GlobAtom::Class {
                            negated,
                            ranges: glob_class_ranges(&items),
                        });
                        at += consumed;
                    }
                    None => {
                        atoms.push(GlobAtom::Literal('['));
                        at += 1;
                    }
                }
            }
            first => {
                atoms.push(GlobAtom::Literal(first));
                at += 1;
            }
        }
    }
    atoms
}

/// Hold the members of a bracket class as sorted and merged
/// ranges. A range whose ends stand reversed admits no
/// character and drops out, as the recursive reader before this
/// evaluation judged it, and merging ranges that overlap or
/// touch leaves the admitted union exactly as named.
fn glob_class_ranges(items: &[ClassItem]) -> Vec<(char, char)> {
    let mut ranges: Vec<(char, char)> = items
        .iter()
        .filter_map(|item| match item {
            ClassItem::Single(member) => Some((*member, *member)),
            ClassItem::Range(lo, hi) if lo <= hi => Some((*lo, *hi)),
            ClassItem::Range(..) => None,
        })
        .collect();
    ranges.sort_unstable();
    let mut merged: Vec<(char, char)> = Vec::with_capacity(ranges.len());
    for (lo, hi) in ranges {
        match merged.last_mut() {
            Some((_, open_hi)) if (lo as u32) <= (*open_hi as u32) + 1 => {
                if hi > *open_hi {
                    *open_hi = hi;
                }
            }
            _ => merged.push((lo, hi)),
        }
    }
    merged
}

/// Whether a sorted and merged range set admits a character,
/// found by binary search for the last range opening at or
/// before the character and a check that the character falls
/// inside it.
fn glob_class_admits(ranges: &[(char, char)], member: char) -> bool {
    let opening = ranges.partition_point(|(lo, _)| *lo <= member);
    opening > 0 && member <= ranges[opening - 1].1
}

enum ClassItem {
    Single(char),
    Range(char, char),
}

/// Parse a bracket class at the head of a pattern, returning its
/// negation, its members, and the pattern past the closing
/// bracket, or None when the bracket never closes and stands as
/// a literal character, as the glob translator reads it.
fn parse_class(pattern: &[char]) -> Option<(bool, Vec<ClassItem>, &[char])> {
    let mut index = 1;
    let mut negated = false;
    if index < pattern.len() && pattern[index] == '!' {
        negated = true;
        index += 1;
    }
    let mut members: Vec<char> = Vec::new();
    if index < pattern.len() && pattern[index] == ']' {
        members.push(']');
        index += 1;
    }
    while index < pattern.len() && pattern[index] != ']' {
        members.push(pattern[index]);
        index += 1;
    }
    if index >= pattern.len() {
        return None;
    }
    let mut items = Vec::new();
    let mut position = 0;
    while position < members.len() {
        if position + 2 < members.len() && members[position + 1] == '-' {
            items.push(ClassItem::Range(members[position], members[position + 2]));
            position += 3;
        } else {
            items.push(ClassItem::Single(members[position]));
            position += 1;
        }
    }
    Some((negated, items, &pattern[index + 1..]))
}

fn match_text(matcher: &Matcher, value: &str) -> bool {
    match matcher {
        Matcher::Exact(pattern) => value == pattern,
        Matcher::Prefix(pattern) => value.starts_with(pattern.as_str()),
        Matcher::Glob(pattern) => {
            let pattern_chars: Vec<char> = pattern.chars().collect();
            let value_chars: Vec<char> = value.chars().collect();
            glob_match(&pattern_chars, &value_chars)
        }
    }
}

fn text_field<'a>(call: &'a Value, key: &str) -> &'a str {
    call.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

pub(crate) fn rule_matches(rule: &Rule, call: &Value) -> bool {
    let match_ = &rule.match_;
    match call.get("kind").and_then(|v| v.as_str()).unwrap_or("") {
        "shell" => {
            if let Some(argv0) = &match_.argv0 {
                let argv = call.get("argv").and_then(|v| v.as_array()).unwrap();
                let first = argv.first().and_then(|v| v.as_str()).unwrap_or("");
                if !match_text(argv0, first) {
                    return false;
                }
            }
            let argv = call.get("argv").and_then(|v| v.as_array()).unwrap();
            for condition in &match_.args {
                if condition.index >= argv.len() {
                    return false;
                }
                let token = argv[condition.index].as_str().unwrap_or("");
                if !match_text(&condition.matcher, token) {
                    return false;
                }
            }
            true
        }
        "file" => {
            if let Some(operation) = &match_.operation {
                if !match_text(operation, text_field(call, "operation")) {
                    return false;
                }
            }
            if let Some(path) = &match_.path {
                let given = text_field(call, "path");
                if !match_text(path, given) {
                    let normalized = normpath(given);
                    if !match_text(path, &normalized) {
                        return false;
                    }
                }
            }
            if let Some(path2) = &match_.path2 {
                let Some(given) = call.get("path2").and_then(|v| v.as_str()) else {
                    return false;
                };
                if !match_text(path2, given) {
                    let normalized = normpath(given);
                    if !match_text(path2, &normalized) {
                        return false;
                    }
                }
            }
            true
        }
        _ => {
            if let Some(method) = &match_.method {
                if !match_text(method, text_field(call, "method")) {
                    return false;
                }
            }
            if let Some(host) = &match_.host {
                if !match_text(host, text_field(call, "host")) {
                    return false;
                }
            }
            if let Some(port) = &match_.port {
                if call.get("port").and_then(|v| v.int_i64()) != Some(*port) {
                    return false;
                }
            }
            true
        }
    }
}

pub(crate) fn apply_substitute(call: &Value, substitute: &Substitute, kind: &str) -> Value {
    let mut pairs: Vec<(String, Value)> = call.as_object().unwrap().clone();
    let replacements: Vec<(&str, &Option<Value>)> = match kind {
        "shell" => vec![("argv", &substitute.argv), ("cwd", &substitute.cwd)],
        "file" => vec![
            ("operation", &substitute.operation),
            ("path", &substitute.path),
            ("path2", &substitute.path2),
        ],
        _ => vec![
            ("method", &substitute.method),
            ("host", &substitute.host),
            ("port", &substitute.port),
        ],
    };
    for (key, replacement) in replacements {
        if let Some(value) = replacement {
            match pairs.iter_mut().find(|(k, _)| k == key) {
                Some(slot) => slot.1 = value.clone(),
                None => pairs.push((key.to_string(), value.clone())),
            }
        }
    }
    Value::Object(pairs)
}

pub(crate) fn decision(
    at: &str,
    digest: &str,
    outcome: &str,
    source: Value,
    reason: Option<&str>,
    interpreter: bool,
    rewritten_call: Option<Value>,
) -> Value {
    Value::obj(vec![
        ("format", Value::text(DECISION_FORMAT)),
        ("at", Value::text(at)),
        ("call_digest", Value::text(digest)),
        ("decision", Value::text(outcome)),
        ("source", source),
        (
            "reason",
            match reason {
                Some(reason) => Value::text(reason),
                None => Value::Null,
            },
        ),
        ("interpreter", Value::Bool(interpreter)),
        (
            "rewritten_call",
            match rewritten_call {
                Some(call) => call,
                None => Value::Null,
            },
        ),
    ])
}

pub(crate) fn source_rule(rule_id: &str) -> Value {
    Value::obj(vec![
        ("type", Value::text("rule")),
        ("rule", Value::text(rule_id)),
    ])
}

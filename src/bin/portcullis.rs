//! The command line for portcullis, a thin shell over the core.
//!
//! The three commands are check and log and audit. The check command reads
//! one policy and one call, prints the decision record as one
//! canonical JSON line, and appends that record to the audit log
//! before the decision counts as delivered. The audit command
//! reads one audit log whole and prints the sampling report as
//! one canonical JSON line, and it decides nothing. Exit codes carry the
//! outcome. Zero for an allow or a rewrite and for an audit
//! report printed, one for a deny from any source and for an escalate and for corruption found by
//! the log command or the audit command, and
//! two for a caller error. The argument surface mirrors the
//! Python argparse surface, its subcommands and required options
//! and its acceptance of unambiguous option prefixes and of the
//! equals form for an option value.

use std::ffi::OsString;
use std::io::Read;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use portcullis::{
    append_decision, audit_log, canonical, evaluate, evaluate_with_transport, load_policy,
    read_log, strict_parse, CallerError, LogReadError, Policy, SubprocessTransport, Value,
};

const MAIN_USAGE: &str = "usage: portcullis [-h] {check,log,audit} ...";
const CHECK_USAGE: &str =
    "usage: portcullis check [-h] --policy POLICY --log LOG [--judge COMMAND] [call]";
const LOG_USAGE: &str = "usage: portcullis log [-h] --log LOG";
const AUDIT_USAGE: &str = "usage: portcullis audit [-h] --log LOG --sample SAMPLE";
const CHECK_HELP: &str = "The judge command is an external program the check command consults for a call the policy refers. It receives the request document on its standard input as one canonical line and answers with the reply body on its standard output, under a timeout of thirty seconds the library fixes. With no judge command configured, every referred call is decided on the no transport fallback.";
const AUDIT_HELP: &str = "The audit ranks recorded calls by their recorded scores and decides nothing. It reads the audit log whole and prints one report naming the count of each class of record and the sample of the highest ranked allows the named size asks for.";

fn fail(message: &str) {
    eprintln!("error: {message}");
}

/// Print one line on stdout and report a failed write to the
/// caller, which turns it into a caller error exit, because a
/// decision that could not be printed was not delivered even
/// when it was appended.
fn print_line(text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{text}")?;
    stdout.flush()
}

fn arg_error(usage: &str, detail: &str) -> i32 {
    eprintln!("{usage}");
    eprintln!("portcullis: error: {detail}");
    2
}

/// Print the help text of one subcommand, its usage line
/// and, for the check command, the statement of the judge
/// protocol that stands beside the usage.
fn print_help(command: &str, usage: &str) {
    let _ = print_line(&format!("{usage}\n"));
    if command == "check" {
        let _ = print_line(CHECK_HELP);
    }
    if command == "audit" {
        let _ = print_line(AUDIT_HELP);
    }
}

fn now_iso() -> String {
    // A clock reading before the epoch formats as the negative
    // offset it is, as the datetime original does, rather than
    // collapsing onto the epoch.
    let (secs, micros) = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => (now.as_secs() as i64, now.subsec_micros()),
        Err(error) => {
            let total_micros = (error.duration().as_micros() as i128).saturating_neg();
            (
                total_micros.div_euclid(1_000_000) as i64,
                total_micros.rem_euclid(1_000_000) as u32,
            )
        }
    };
    let days = secs.div_euclid(86_400);
    let day_secs = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let mut text = format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        day_secs / 3600,
        (day_secs % 3600) / 60,
        day_secs % 60
    );
    if micros > 0 {
        text.push_str(&format!(".{micros:06}"));
    }
    text.push_str("+00:00");
    text
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    (year, month as u32, day as u32)
}

fn read_call_text(path: &Option<PathBuf>) -> Result<String, CallerError> {
    match path {
        None => {
            let mut bytes = Vec::new();
            match std::io::stdin().lock().read_to_end(&mut bytes) {
                Ok(_) => {}
                Err(exc) => {
                    return Err(CallerError(format!(
                        "the call document cannot be read, {exc}"
                    )));
                }
            }
            match String::from_utf8(bytes) {
                Ok(text) => Ok(text),
                Err(exc) => Err(CallerError(format!(
                    "the call document cannot be read, {exc}"
                ))),
            }
        }
        Some(path) => {
            let bytes = match std::fs::read(path) {
                Ok(bytes) => bytes,
                Err(exc) => {
                    return Err(CallerError(format!(
                        "the call document at {} cannot be read, {exc}",
                        path.display()
                    )));
                }
            };
            match String::from_utf8(bytes) {
                Ok(text) => Ok(text),
                Err(exc) => Err(CallerError(format!(
                    "the call document at {} cannot be read, {exc}",
                    path.display()
                ))),
            }
        }
    }
}

/// The loaded policy and a load failure detail, one of them None.
fn load_policy_file(path: &PathBuf) -> (Option<Policy>, Option<String>) {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(exc) => {
            return (
                None,
                Some(format!(
                    "the policy at {} cannot be read, {exc}",
                    path.display()
                )),
            );
        }
    };
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(exc) => {
            return (
                None,
                Some(format!(
                    "the policy at {} cannot be read, {exc}",
                    path.display()
                )),
            );
        }
    };
    let document = match strict_parse(&text) {
        Ok(document) => document,
        Err(_) => {
            return (
                None,
                Some(format!(
                    "the policy at {} does not parse as strict JSON",
                    path.display()
                )),
            );
        }
    };
    match load_policy(&document) {
        Ok(policy) => (Some(policy), None),
        Err(exc) => (None, Some(exc.0)),
    }
}

fn check(
    policy_path: PathBuf,
    log_path: PathBuf,
    judge_command: Option<String>,
    call_path: Option<PathBuf>,
) -> i32 {
    let call_text = match read_call_text(&call_path) {
        Ok(text) => text,
        Err(exc) => {
            fail(&exc.0);
            return 2;
        }
    };
    let document: Value = match strict_parse(&call_text) {
        Ok(document) => document,
        Err(_) => {
            fail("the call document does not parse as strict JSON");
            return 2;
        }
    };
    let (policy, policy_error) = load_policy_file(&policy_path);
    let at = now_iso();
    let decision = match &judge_command {
        Some(command) => {
            let transport = SubprocessTransport::new(command);
            evaluate_with_transport(
                policy.as_ref(),
                policy_error.as_deref(),
                &document,
                &at,
                Some(&transport),
            )
        }
        None => evaluate(policy.as_ref(), policy_error.as_deref(), &document, &at),
    };
    if let Err(exc) = append_decision(&log_path, &decision) {
        fail(&format!(
            "the decision could not be appended to the audit log at {}, {}",
            log_path.display(),
            exc.0
        ));
        return 2;
    }
    let line = String::from_utf8(canonical(&decision)).unwrap();
    if print_line(&line).is_err() {
        fail("the decision could not be printed");
        return 2;
    }
    match decision.get("decision").and_then(|v| v.as_str()) {
        Some("allow") | Some("rewrite") => 0,
        _ => 1,
    }
}

fn log(log_path: PathBuf) -> i32 {
    match read_log(&log_path) {
        Ok(records) => {
            for record in &records {
                let line = String::from_utf8(canonical(record)).unwrap();
                if print_line(&line).is_err() {
                    fail("the audit log could not be printed");
                    return 2;
                }
            }
            0
        }
        Err(LogReadError::Corruption(exc)) => {
            fail(&format!("the audit log is corrupt at {exc}"));
            1
        }
        Err(LogReadError::Caller(exc)) => {
            fail(&exc.0);
            2
        }
    }
}

fn audit(log_path: PathBuf, sample_size: usize) -> i32 {
    match audit_log(&log_path, sample_size) {
        Ok(report) => {
            let line = String::from_utf8(canonical(&report)).unwrap();
            if print_line(&line).is_err() {
                fail("the audit report could not be printed");
                return 2;
            }
            0
        }
        Err(LogReadError::Corruption(exc)) => {
            fail(&format!("the audit log is corrupt at {exc}"));
            1
        }
        Err(LogReadError::Caller(exc)) => {
            fail(&exc.0);
            2
        }
    }
}

struct ParsedArgs {
    policy: Option<PathBuf>,
    log: Option<PathBuf>,
    judge: Option<String>,
    sample: Option<usize>,
    call: Option<PathBuf>,
}

/// Split one argument token at its first equals sign, keeping
/// the inline value as the operating system string it arrived
/// as, so a value holding bytes that are not text survives as a
/// path exactly as a value in its own argument does.
#[cfg(unix)]
fn split_inline(token: &OsString) -> (String, Option<OsString>) {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let bytes = token.as_bytes();
    match bytes.iter().position(|byte| *byte == b'=') {
        Some(at) => (
            String::from_utf8_lossy(&bytes[..at]).into_owned(),
            Some(OsString::from_vec(bytes[at + 1..].to_vec())),
        ),
        None => (token.to_string_lossy().into_owned(), None),
    }
}

#[cfg(not(unix))]
fn split_inline(token: &OsString) -> (String, Option<OsString>) {
    let text = token.to_string_lossy().into_owned();
    match text.split_once('=') {
        Some((name, value)) => (name.to_string(), Some(OsString::from(value))),
        None => (text, None),
    }
}

/// Match one long option name against the known options of a
/// subcommand, accepting an unambiguous prefix as the Python
/// parser accepts it.
fn match_long_option<'a>(
    name_token: &str,
    error_token: &str,
    known: &[&'a str],
) -> Result<&'a str, String> {
    let full = name_token;
    let matches: Vec<&str> = known
        .iter()
        .filter(|option| option.starts_with(full))
        .copied()
        .collect();
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(format!("unrecognized arguments: {error_token}")),
        _ => Err(format!("ambiguous option: {error_token}")),
    }
}

fn parse_subcommand(command: &str, args: &[OsString]) -> Result<ParsedArgs, (String, i32)> {
    let usage = match command {
        "check" => CHECK_USAGE,
        "audit" => AUDIT_USAGE,
        _ => LOG_USAGE,
    };
    let known: &[&str] = match command {
        "check" => &["--policy", "--log", "--judge", "--help"],
        "audit" => &["--log", "--sample", "--help"],
        _ => &["--log", "--help"],
    };
    let mut parsed = ParsedArgs {
        policy: None,
        log: None,
        judge: None,
        sample: None,
        call: None,
    };
    let mut positional_only = false;
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        let token_text = token.to_string_lossy().into_owned();
        if !positional_only && token_text == "--" {
            positional_only = true;
            index += 1;
            continue;
        }
        if !positional_only && (token_text == "-h" || token_text == "--help") {
            print_help(command, usage);
            return Err((String::new(), 0));
        }
        if !positional_only && token_text.starts_with("--") {
            let (name_token, inline) = split_inline(token);
            let option = match match_long_option(&name_token, &token_text, known) {
                Ok(option) => option,
                Err(detail) => return Err((detail, 2)),
            };
            if option == "--help" {
                print_help(command, usage);
                return Err((String::new(), 0));
            }
            let value = match inline {
                Some(value) => PathBuf::from(value),
                None => {
                    index += 1;
                    match args.get(index) {
                        Some(value) => PathBuf::from(value),
                        None => {
                            return Err((format!("argument {option}: expected one argument"), 2));
                        }
                    }
                }
            };
            match option {
                "--policy" => parsed.policy = Some(value),
                "--judge" => parsed.judge = Some(value.to_string_lossy().into_owned()),
                "--sample" => {
                    let text = value.to_string_lossy().into_owned();
                    match text.parse::<usize>() {
                        Ok(0) => {
                            return Err((
                                "argument --sample: the sample size must stand at one or above"
                                    .to_string(),
                                2,
                            ));
                        }
                        Ok(size) => parsed.sample = Some(size),
                        Err(_) => {
                            return Err((
                                format!("argument --sample: invalid positive count value: {text}"),
                                2,
                            ));
                        }
                    }
                }
                _ => parsed.log = Some(value),
            }
            index += 1;
            continue;
        }
        if !positional_only && token_text.starts_with('-') && token_text != "-" {
            return Err((format!("unrecognized arguments: {token_text}"), 2));
        }
        if command == "check" && parsed.call.is_none() {
            parsed.call = Some(PathBuf::from(token));
        } else {
            return Err((format!("unrecognized arguments: {token_text}"), 2));
        }
        index += 1;
    }
    let mut missing: Vec<&str> = Vec::new();
    if command == "check" && parsed.policy.is_none() {
        missing.push("--policy");
    }
    if parsed.log.is_none() {
        missing.push("--log");
    }
    if command == "audit" && parsed.sample.is_none() {
        missing.push("--sample");
    }
    if !missing.is_empty() {
        return Err((
            format!(
                "the following arguments are required: {}",
                missing.join(", ")
            ),
            2,
        ));
    }
    Ok(parsed)
}

fn run() -> i32 {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let first = match args.first() {
        Some(first) => first.to_string_lossy().into_owned(),
        None => return arg_error(MAIN_USAGE, "the following arguments are required: command"),
    };
    if first == "-h" || first == "--help" {
        let _ = print_line(MAIN_USAGE);
        return 0;
    }
    match first.as_str() {
        "check" | "log" | "audit" => match parse_subcommand(&first, &args[1..]) {
            Ok(parsed) => {
                if first == "check" {
                    check(
                        parsed.policy.unwrap(),
                        parsed.log.unwrap(),
                        parsed.judge,
                        parsed.call,
                    )
                } else if first == "audit" {
                    audit(parsed.log.unwrap(), parsed.sample.unwrap())
                } else {
                    log(parsed.log.unwrap())
                }
            }
            Err((detail, code)) => {
                if detail.is_empty() {
                    code
                } else {
                    let usage = match first.as_str() {
                        "check" => CHECK_USAGE,
                        "audit" => AUDIT_USAGE,
                        _ => LOG_USAGE,
                    };
                    arg_error(usage, &detail)
                }
            }
        },
        _ => arg_error(MAIN_USAGE, &format!("invalid choice: {first}")),
    }
}

fn main() {
    std::process::exit(run());
}

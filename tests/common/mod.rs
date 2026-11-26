//! Helpers the integration suites share.
//!
//! Each suite includes this module once and takes the helpers
//! it uses from here, so one helper stands in one copy and a
//! repair to it lands once. Suite-specific builders stay in
//! their suites.

use std::cell::RefCell;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use portcullis::{canonical, JudgeTransport, TransportError, Value};

pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn temp_dir_with(prefix: &str, tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn s(text: &str) -> Value {
    Value::text(text)
}

pub fn field<'a>(doc: &'a Value, key: &str) -> &'a Value {
    doc.get(key).unwrap()
}

pub fn write_log_lines(log_path: &Path, records: &[Value]) {
    let mut text = String::new();
    for record in records {
        text.push_str(&String::from_utf8(canonical(record)).unwrap());
        text.push('\n');
    }
    std::fs::write(log_path, text).unwrap();
}

pub struct CliOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_cli(arguments: &[&str], stdin_text: Option<&str>) -> CliOutput {
    run_cli_bytes(arguments, stdin_text.map(|text| text.as_bytes().to_vec()))
}

pub fn run_cli_bytes(arguments: &[&str], stdin_bytes: Option<Vec<u8>>) -> CliOutput {
    let mut command = Command::new(env!("CARGO_BIN_EXE_portcullis"));
    command
        .args(arguments)
        .current_dir(root())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin_bytes.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().unwrap();
    if let Some(bytes) = stdin_bytes {
        child.stdin.take().unwrap().write_all(&bytes).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    CliOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// A transport that records every request it is handed and
/// answers with one canned outcome.
pub struct StubTransport {
    pub outcome: Result<String, String>,
    pub requests: RefCell<Vec<Value>>,
}

impl StubTransport {
    pub fn replying(body: &str) -> StubTransport {
        StubTransport {
            outcome: Ok(body.to_string()),
            requests: RefCell::new(Vec::new()),
        }
    }

    pub fn failing() -> StubTransport {
        StubTransport {
            outcome: Err("the stub transport failed".to_string()),
            requests: RefCell::new(Vec::new()),
        }
    }

    pub fn consulted(&self) -> usize {
        self.requests.borrow().len()
    }
}

impl JudgeTransport for StubTransport {
    fn consult(&self, request: &Value) -> Result<String, TransportError> {
        self.requests.borrow_mut().push(request.clone());
        match &self.outcome {
            Ok(body) => Ok(body.clone()),
            Err(detail) => Err(TransportError(detail.clone())),
        }
    }
}

/// Open a writable stream whose writes deterministically fail across
/// platforms. Prefers /dev/full where present on Linux and falls back
/// to the write end of an anonymous pipe whose read end is already
/// closed on macOS and Windows, proving a probe write fails first.
#[allow(dead_code)]
pub fn dead_stream() -> Stdio {
    if let Ok(mut full) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/full")
    {
        if full.write_all(b"probe").is_err() {
            return Stdio::from(full);
        }
    }
    // Portability adaptation retries pipe creation when a concurrent child
    // spawn on macOS inherits reader before FIOCLEX closes the race window.
    for _ in 0..64 {
        let (reader, mut writer) = std::io::pipe().expect("pipe creation failed");
        drop(reader);
        if writer.write_all(b"probe").is_err() {
            return Stdio::from(writer);
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("probe write to closed pipe must fail")
}

#[cfg(unix)]
#[allow(dead_code)]
pub fn mkfifo(path: &Path) {
    let status = Command::new("mkfifo").arg(path).status().unwrap();
    assert!(status.success(), "mkfifo failed for {}", path.display());
}

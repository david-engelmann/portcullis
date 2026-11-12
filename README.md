# portcullis

A local tool-call firewall that sits between an agent and your machine, allowing, denying, or rewriting shell, file, and network calls by rule, and referring the calls its rules leave open to a decision model.

Portcullis is one local binary backed by a Rust library, with a thin Python binding over the same library. A harness or a person hands it a policy and one structured call record. It answers with one decision record, appends that record to an audit log, and executes nothing itself.

[![CI](https://github.com/david-engelmann/portcullis/actions/workflows/ci.yml/badge.svg)](https://github.com/david-engelmann/portcullis/actions/workflows/ci.yml)

```
{"at":"2026-11-07T08:12:42.201571+00:00","call_digest":"sha256:85b02c27042e96633fb1bf6f809b37fcfa3a1cc8afdcb51dacd2e601752bb23c","decision":"deny","format":"portcullis-decision/1","interpreter":false,"reason":"removal is not run directly","rewritten_call":null,"source":{"rule":"deny-rm","type":"rule"}}
exit 1
```

## Install

Portcullis builds from source with Cargo. Clone the repo and install the binary onto your path.

```
git clone https://github.com/david-engelmann/portcullis.git
cd portcullis
cargo install --path . --bin portcullis
```

The install puts the portcullis binary in the Cargo bin directory. On a default install that directory is ~/.cargo/bin, and it must stand on your PATH for the portcullis command to resolve.

## Quickstart

The repo ships a sample policy and sample calls under tests/fixtures. The quickstart runs two calls against the sample policy. Every check prints its decision record as one JSON line and appends the same record to the audit log named by the --log option.

The first call runs the shell command rm x, and the policy holds a deny rule for rm.

```
portcullis check --policy tests/fixtures/policy-full.json --log audit.jsonl tests/fixtures/call-shell-deny.json
```

```
{"at":"2026-11-07T08:12:42.201571+00:00","call_digest":"sha256:85b02c27042e96633fb1bf6f809b37fcfa3a1cc8afdcb51dacd2e601752bb23c","decision":"deny","format":"portcullis-decision/1","interpreter":false,"reason":"removal is not run directly","rewritten_call":null,"source":{"rule":"deny-rm","type":"rule"}}
exit 1
```

A deny from any source exits 1. An allow or a rewrite exits 0, and a caller error exits 2.

The second call lists a directory, and an allow rule matches it.

```
portcullis check --policy tests/fixtures/policy-full.json --log audit.jsonl tests/fixtures/call-shell-allow.json
```

```
{"at":"2026-11-07T08:12:42.244792+00:00","call_digest":"sha256:22423464240d7a30193a40d5d6f065bc72d05cdab2ab0e7e53927c922eb14a63","decision":"allow","format":"portcullis-decision/1","interpreter":false,"reason":"listing is fine","rewritten_call":null,"source":{"rule":"allow-ls","type":"rule"}}
exit 0
```

## Usage

### The evaluation order, rewrites, and the default

The order is fixed and is part of the contract. A malformed call is denied before any rule is consulted. Deny rules are then read in policy order, the first matching allow or rewrite or judge rule decides what survives, and the declared default closes what nothing matched.

A rewrite rule answers with a substitute call in place of the one proposed, and the decision record carries the rewritten call. The sample policy stages file writes, so a write under /work/out lands in staging instead.

```
portcullis check --policy tests/fixtures/policy-full.json --log audit.jsonl tests/fixtures/call-file-rewrite.json
```

```
{"at":"2026-11-07T08:12:42.264336+00:00","call_digest":"sha256:b862a8cfad0c1eebea3fd8904c455c2dee7d89011f37f61ce0398c22b678e283","decision":"rewrite","format":"portcullis-decision/1","interpreter":false,"reason":"writes land in staging","rewritten_call":{"format":"portcullis-call/1","kind":"file","operation":"write","path":"/work/staging/out.txt"},"source":{"rule":"stage-writes","type":"rule"}}
exit 0
```

A call no rule matches falls to the policy default, and the record names the default as its source. The sample policy defaults to deny, so this network call is denied even though no rule names its host.

```
portcullis check --policy tests/fixtures/policy-full.json --log audit.jsonl tests/fixtures/call-network-explicit.json
```

```
{"at":"2026-11-07T08:12:42.292542+00:00","call_digest":"sha256:dcd9c04ec7a46422c3f40e649910b868bd8fc4d00d4bd46fd46b72edfc7f55ec","decision":"deny","format":"portcullis-decision/1","interpreter":false,"reason":null,"rewritten_call":null,"source":{"type":"default"}}
exit 1
```

### Referring a call to a decision model

A rule with the judge action refers the calls it matches to the model the policy judgment block names. The check command consults an external judge program through its --judge option. The program receives the request document on its standard input and answers with the reply body on its standard output. The example answers with a recorded reply held in a file, so the run needs no model access and no network.

Save the three documents below as judge-policy.json, call-judge.json, and reply.json in one directory, and run the commands of this section from that directory.

The policy holds one judge rule for shell calls and a judgment block naming the model, its threshold, and its escalation.

```
{
  "format": "portcullis-policy/1",
  "default": "deny",
  "judgment": {"model": "jev-1.13.0", "threshold": 0.75, "escalation": "queue"},
  "rules": [
    {
      "id": "judge-shell",
      "kind": "shell",
      "action": "judge",
      "reason": "shell calls whose safety turns on the stated task",
      "match": {"argv0": {"glob": "*"}}
    }
  ]
}
```

The call is a plain directory listing.

```
{
  "format": "portcullis-call/1",
  "kind": "shell",
  "argv": ["ls"]
}
```

The recorded reply answers allow with a probability of 0.93 against deny at 0.03 and escalate at 0.03.

```
{"model": "jev-1.13.0", "answers": {"verdict": {"type": "choice", "choice": "allow", "confidence": 0.5, "probabilities": {"allow": 0.93, "deny": 0.03, "escalate": 0.03, "other": 0.01}}, "risk": {"type": "score", "score": 3.2, "probabilities": {}}}, "usage": {"input_tokens": 10, "output_tokens": 5}}
```

```
portcullis check --policy judge-policy.json --log audit.jsonl --judge "cat reply.json" call-judge.json
```

```
{"at":"2026-11-07T08:12:42.338978+00:00","call_digest":"sha256:250a209806ea501e643c1d7ccb3f6a0dde645b81fa3dfbb6e0f75416440b9f92","decision":"allow","format":"portcullis-decision/2","interpreter":false,"model":{"confidence":0.93,"failure":null,"fallback":"none","model":"jev-1.13.0","probabilities":{"allow":0.93,"deny":0.03,"escalate":0.03,"other":0.01},"request_digest":"sha256:e2ac680d4f062f471ef518e2842718004cde79ea8de63a84908da31737baa69c","risk_score":4.2,"verdict":"allow"},"reason":"shell calls whose safety turns on the stated task","rewritten_call":null,"source":{"rule":"judge-shell","type":"model"}}
exit 0
```

The decision record is a portcullis-decision/2 record. Its model block carries the verdict, the confidence read from the probabilities map of the reply, and the recorded risk score, and its source names the referring rule.

Since Round 5 the instructions the model reads carry two further sentences of denial doctrine. A call that is itself the harm, one that destroys data or overwrites it past recovery, reads a credential or key file, sends project material to a destination outside the project, or runs code fetched from an address the state does not name as approved, is stated to be a denial and not an escalation, whatever boundary question it also raises. On a call of one of those shapes the model is told to state the deny probability the shape earns rather than dividing it with escalate, because a deny verdict divided with escalate lands below the threshold the policy sets and the call is escalated to a human instead of refused.

With no judge program configured, a referred call lands on the no transport fallback and escalates, and the command exits 1. The run below logs to its own file, apart from the log the audit example reads.

```
portcullis check --policy judge-policy.json --log nojudge.jsonl call-judge.json
```

```
{"at":"2026-11-07T06:28:18.347178+00:00","call_digest":"sha256:250a209806ea501e643c1d7ccb3f6a0dde645b81fa3dfbb6e0f75416440b9f92","decision":"escalate","format":"portcullis-decision/2","interpreter":false,"model":{"confidence":null,"failure":"no transport","fallback":"no transport","model":"jev-1.13.0","probabilities":null,"request_digest":"sha256:e2ac680d4f062f471ef518e2842718004cde79ea8de63a84908da31737baa69c","risk_score":null,"verdict":null},"reason":"shell calls whose safety turns on the stated task","rewritten_call":null,"source":{"rule":"judge-shell","type":"model"}}
exit 1
```

### The audit log and the sampling audit

Every decision the check command delivers stands in the audit log it was named, one JSON record per line, and the log command prints the records back. The audit command reads a log whole and prints a sampling report. The report counts the classes of records the log holds and returns the allows that carry a recorded risk score, highest score first, up to the sample size asked for.

The log behind this report holds the five decisions from the runs above, four plain decision records and one model referred allow.

```
portcullis audit --log audit.jsonl --sample 2
```

```
{"counts":{"first_format":4,"lines":5,"ranked":1,"scored_not_allowed":0,"unscored":0},"format":"portcullis-audit/1","requested":2,"returned":1,"sample":[{"line":5,"rank":1,"record":{"at":"2026-11-07T08:12:42.338978+00:00","call_digest":"sha256:250a209806ea501e643c1d7ccb3f6a0dde645b81fa3dfbb6e0f75416440b9f92","decision":"allow","format":"portcullis-decision/2","interpreter":false,"model":{"confidence":0.93,"failure":null,"fallback":"none","model":"jev-1.13.0","probabilities":{"allow":0.93,"deny":0.03,"escalate":0.03,"other":0.01},"request_digest":"sha256:e2ac680d4f062f471ef518e2842718004cde79ea8de63a84908da31737baa69c","risk_score":4.2,"verdict":"allow"},"reason":"shell calls whose safety turns on the stated task","rewritten_call":null,"source":{"rule":"judge-shell","type":"model"}},"risk_score":4.2}]}
exit 0
```

A sample of two returns the one ranked record that stands in the log.

### The Python binding

The binding wraps the same library for Python callers. It exposes check and read_log and audit_log, and a refusal raises a subclass of PortcullisError carrying the same words the command line prints. Build it with maturin from a virtual environment at the repo root.

```
python3 -m venv .venv
.venv/bin/pip install maturin
.venv/bin/maturin develop --manifest-path bindings/Cargo.toml
```

The script below decides the same rm call the quickstart denies, through the library rather than the binary, and reads the log back. The count it prints is one, because the log starts empty and the script appends its decision before it reads.

```
import json
from pathlib import Path

import portcullis

fixtures = Path("tests/fixtures")
policy = json.loads((fixtures / "policy-full.json").read_text())
call = json.loads((fixtures / "call-shell-deny.json").read_text())

decision = portcullis.check(policy, call, "binding-audit.jsonl", "2026-11-07T00:00:00+00:00")
print(decision["decision"], decision["source"])
print(len(portcullis.read_log("binding-audit.jsonl")))
```

```
deny {'type': 'rule', 'rule': 'deny-rm'}
1
```

## Status

The gate, the referral, and the sampling audit all work today. Portcullis checks shell and file and network calls against a policy, refers the calls its rules leave open when a judge is configured, appends every decision it delivers to an audit log, and samples that log on request. The Python binding carries the same operations.

Portcullis executes nothing and wires into no harness. A harness or a person presents each call and acts on each decision, and no model access is bundled, so a referring policy needs a judge program from the operator or a transport handed to the binding.

The contract lives in CONTRACT.md. Obligations S1 to S5 stand as the setup record. Obligations PC-1 to PC-12 state the behaviour of the gate, PC-13 to PC-20 state the behaviour of the referral and the judgment, PC-21 to PC-25 state the behaviour of the sampling audit, and PC-26 states the interior of the referral, and PC-27 to PC-29 state the doctrine the gathered population supports, and PC-30 to PC-32 state the successor doctrine the two gatherings support, and PC-33 states the bar the recorded population supports, and PC-34 states the seam under a failed consultation.

The continuous integration workflow runs the full suite and the Python binding smoke on every push and pull request, and both checks are required on main.

Closed perfection rounds are 39 of 100. A round counts only when a full cycle of work and audit and review and red team and approval has closed, and seeding and setup are not rounds.

The remote seed was verified on 2026-11-02 against the staged seed, and its commit is 46b1cafe58e78f9b0820b81800b6727cc2ffae60, a parentless commit holding exactly README.md and LICENSE and .gitignore.

## License

MIT. See [LICENSE](LICENSE).

# portcullis

A local tool-call firewall that sits between an agent and your machine, approving, denying, or rewriting shell, file, and network calls by rule.

## What this is

Nothing enforces a policy across harnesses at the call itself. Hooks log that they fired, and the gateway tools that do enforce policy live at the traffic layer for fleets, not on one developer's machine. Portcullis shrinks the gateway to a single local binary at the tool-call layer. An agent attempting a destructive command gets the blocked call, the rule that caught it, and the safe substitute, on screen. The boundary with its siblings is one sentence. Portcullis guards the calls, deadbolt guards the credentials the calls ask for, hookdoctor grades the guards.

## Status

The remote seed was verified on 2026-11-02 against the staged seed and its commit is 46b1cafe58e78f9b0820b81800b6727cc2ffae60, a parentless commit holding exactly README.md and LICENSE and .gitignore. Setup arrives through a pull request and no work lands on main directly.

The contract lives in CONTRACT.md. The full contract landed as the first build act of this repo in Round 1 slice 1, and obligations S1 to S5 stand as its setup record with obligations PC-1 to PC-12 stating the behaviour of the gate. Round 1 slice 1 builds the decision engine. A structured call record and a policy go in, a decision record comes out, and the decision is appended to an audit log. The gate judges shell and file and network calls by rule in the evaluation order the contract fixes, and it fails closed when its policy cannot be loaded. It wires into no harness and executes nothing, and ROADMAP.md stands as it landed ahead of setup and this slice does not change it.

Closed perfection rounds are 1 of 100. A round counts only when a full cycle of work and audit and review and red team and approval has closed, and seeding and setup are not rounds.

The local gate is python -m pytest -q plus python scripts/codepoint_scan.py, run on the exact final head before any push, with the continuous integration workflow running the same commands as a backstop.

## Licence

MIT. See LICENSE.

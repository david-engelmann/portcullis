# portcullis

A local tool-call firewall that sits between an agent and your machine, approving, denying, or rewriting shell, file, and network calls by rule.

## What this is

Nothing enforces a policy across harnesses at the call itself. Hooks log that they fired, and the gateway tools that do enforce policy live at the traffic layer for fleets, not on one developer's machine. Portcullis shrinks the gateway to a single local binary at the tool-call layer. An agent attempting a destructive command gets the blocked call, the rule that caught it, and the safe substitute, on screen. The boundary with its siblings is one sentence. Portcullis guards the calls, deadbolt guards the credentials the calls ask for, hookdoctor grades the guards.

## Status

Seeded in October 2026. The build has not started. Part of the impatient programming portfolio, in the Fleet Operations arc.

## Licence

MIT. See LICENSE.

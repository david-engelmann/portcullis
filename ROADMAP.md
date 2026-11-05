# Portcullis roadmap

Portcullis guards tool calls. It is the admission gate an agent's proposed tool call passes through before the call runs, and it has closed its first three rounds. Its setup slice and its first deterministic slices come before anything in the decision model section below. That section is recorded now, before the gate is built, so the admission design grows around a stated place for judgment instead of acquiring one later by accident.

## Decision models

Judgment enters portcullis at the admission gate, in the grey zone the hard rules cannot settle.

The deterministic rules speak first and they speak in absolutes. Schema validation, the allowlist, the deny list, and rate limits are evaluated by ordinary code, and a hard deny ends the matter. What remains is the class of call whose risk is contextual, a well formed call to an allowed tool whose arguments, target, or history make its safety a judgment rather than a lookup. Those calls go to a decision model, which returns a choice among allow and deny and escalate, with a calibrated confidence and per label probabilities.

A deterministic policy layer combines the two voices, and the combination rule is the security property of the design. A hard deny can never be overridden by the model. A model allow applies only when no hard rule has fired. A model verdict under the confidence threshold the policy declares, and any abstention or failed call, lands on escalate, or on deny where the policy declares no escalation path exists. The model can therefore widen nothing. It can only resolve calls the rules left open, in the direction the policy already chose for uncertainty.

The model also returns a risk score for a second, quieter job. High volume allowed traffic is audited by sampling, and the score sets the sampling priority, so human and agent review time lands on the calls judgment finds strangest. The score never admits or refuses anything by itself.

The model is Typesafe Jev, reached only through the program's Typesafe connector route, a System One decision model whose choice and score shapes fit the two jobs above directly. The OpenAI decision model is the named comparison point. The same recorded tool call vignettes are scored by both models in evaluation, and wiring the comparison model waits on a route and a budget set at program level. Every admission the model influenced is logged with the tool call's synthetic or redacted shape as policy allows, the model name, the verdict, the confidence, and the fallback taken, because a guard whose reasoning cannot be audited is a guard that will eventually be bypassed by its own operators.

What stays deterministic is the enforcement itself. The gate runs or refuses the call by ordinary code, the hard rules are ordinary code, the combination rule is ordinary code, and the audit log is written by ordinary code. The model advises a verdict inside that envelope and performs no action in the world.

Tests stay offline. A bounded recording window captures synthetic tool call contexts and the model's responses and stores them in the repo as JSON fixtures, each fixture carrying the model name and the exact call shape. Every fixture context is synthetic, invented for this repo, because nothing real ever enters this repo. The suite replays the fixtures through a fixture transport and no test performs a network call. The combination rule is tested purely deterministically, including the shapes that matter most, a confident allow against a hard deny, an abstention, and a verdict under threshold, so the security property is pinned by tests that owe nothing to any model's mood.

The live call budget for this repo is a call count budget, set by the repo owner under the program standing delegation of 2026-11-02, because a decision call is small. The budget is at most 10 verification calls while the client shim is built, at most 200 calls in the single fixture recording window, and at most 100 live evaluation calls in the round that lands the admission feature, with the recorded usage printed in that round's gate report. At the vendor's claimed price the expected spend across all three allowances is under a cent, and the binding cap is the count, with a hard stop of 5 dollars per repo per month if real pricing or call sizes differ from the claim. Any surprise is reported before any further call is made.

## Round 3

Round 3 opens with the admission slice. The contract amendment PC-13 to PC-20 lands first in the slice pull request and states the referral, the judgment block, the combination rule, the failure classes, the second decision record format, the risk score, the transport seam, and the limits of the slice. The library and command line and binding build follows the amendment in the same pull request, and the recorded fixtures and the deterministic pins follow the build. The admission slice landed in PR 8 and Round 3 closed with it.

## Round 4

Round 4 opens with the sampling audit slice. The contract amendment PC-21 to PC-25 lands first in the slice pull request and states the audit population, the ranking rule, the audit report, the audit surface, and the limits of the sampling slice. The library and command line and binding build follows the amendment in the same pull request, and the pins follow the build, and no live call stands anywhere in the slice.
